"""The automations engine.

An automation is a standing instruction: *"remind me before subscriptions
renew"*, *"file documents into folders"*, *"draft a reply when someone has been
waiting three days"*.

The important property is what an automation **is not** allowed to become. It
is not a second path to action. Every automation runs its action through the
same Action Firewall as everything else, with ``ActorType.AUTOMATION``, which
means:

* the policy engine evaluates it exactly as it would a human's request;
* anything above LOW risk produces a proposal that waits for approval;
* lockdown disables the lot, because ``automations_enabled`` is checked before
  a single trigger is evaluated;
* the standing permission still has to exist.

So the worst case for a misconfigured automation is a queue of proposals the
owner declines, not an action they did not sanction. That is the entire reason
this module is thin: the interesting decisions already happened elsewhere.

Triggers are deterministic conditions over stored data, matching the proactive
engine's philosophy. An automation cannot be "whenever it seems important".
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    EntityType,
    InboxItemState,
    ObligationStatus,
    Urgency,
)
from mybot_schemas.models import AutomationRule, EmailMessage, Entity, InboxItem, Obligation
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

from ..action_firewall.service import ActionFirewall, ActionRejected, ProposalRequest
from ..audit.service import AuditService
from ..notifications.service import NotificationService
from ..policy.service import PolicyService

log = get_logger(__name__)

#: Trigger types an automation may use. Adding one is a code change, reviewed
#: like any other -- an owner cannot invent a trigger from the UI, because a
#: trigger is a query and arbitrary user-supplied queries are a bad idea.
TRIGGER_TYPES = (
    "obligation.due_within",
    "subscription.renewing",
    "email.unanswered_for",
    "inbox.urgency_at_least",
    "document.expiring_within",
)


@dataclass
class AutomationOutcome:
    rule_id: str
    rule_name: str
    matched: int = 0
    proposals_created: list[str] = field(default_factory=list)
    notifications_created: int = 0
    skipped_reason: str | None = None
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "matched": self.matched,
            "proposals": self.proposals_created,
            "notifications": self.notifications_created,
            "skipped_reason": self.skipped_reason,
            "errors": self.errors,
        }


@dataclass
class AutomationRunReport:
    ran: list[AutomationOutcome] = field(default_factory=list)
    disabled_by_lockdown: bool = False

    @property
    def proposals_created(self) -> int:
        return sum(len(o.proposals_created) for o in self.ran)

    def as_dict(self) -> dict:
        return {
            "automations": [o.as_dict() for o in self.ran],
            "proposals_created": self.proposals_created,
            "notifications_created": sum(o.notifications_created for o in self.ran),
            "disabled_by_lockdown": self.disabled_by_lockdown,
        }


class AutomationEngine:
    def __init__(
        self,
        session: Session,
        firewall: ActionFirewall,
        *,
        policy: PolicyService | None = None,
        audit: AuditService | None = None,
        notifications: NotificationService | None = None,
    ):
        self.session = session
        self.firewall = firewall
        self.audit = audit or AuditService(session)
        self.policy = policy or PolicyService(session, self.audit)
        self.notifications = notifications or NotificationService(session, self.audit)

    def run(self, owner_id: str, *, now: dt.datetime | None = None) -> AutomationRunReport:
        """Evaluate every enabled automation for one owner."""
        now = now or utcnow()
        report = AutomationRunReport()

        state = self.policy.get_security_state(owner_id)
        if state.locked or not state.automations_enabled:
            # Checked once, before anything is evaluated. Lockdown means
            # nothing runs, not "runs but gets refused later".
            report.disabled_by_lockdown = True
            return report

        rules = list(
            self.session.execute(
                sa.select(AutomationRule).where(
                    AutomationRule.owner_id == owner_id,
                    AutomationRule.enabled.is_(True),
                )
            ).scalars()
        )

        for rule in rules:
            outcome = self._run_one(owner_id, rule, now)
            report.ran.append(outcome)
            rule.last_run_at = now
            rule.run_count = int(rule.run_count or 0) + 1

        self.session.flush()
        return report

    # ------------------------------------------------------------------

    def _run_one(
        self, owner_id: str, rule: AutomationRule, now: dt.datetime
    ) -> AutomationOutcome:
        outcome = AutomationOutcome(rule_id=rule.id, rule_name=rule.name)

        if rule.trigger_type not in TRIGGER_TYPES:
            outcome.skipped_reason = f"unknown trigger type: {rule.trigger_type}"
            log.warning("automation.unknown_trigger", trigger=rule.trigger_type)
            return outcome

        try:
            matches = self._evaluate_trigger(owner_id, rule, now)
        except Exception as exc:  # noqa: BLE001
            log.exception("automation.trigger_failed", rule=rule.id)
            outcome.errors.append(f"trigger evaluation failed: {type(exc).__name__}")
            return outcome

        outcome.matched = len(matches)
        if not matches:
            return outcome

        for match in matches:
            # An automation with no action is a notifier. That is a legitimate
            # and often preferable configuration: "tell me, do not act".
            if not rule.action_type:
                notification = self.notifications.notify(
                    owner_id,
                    title=rule.name,
                    body=match["summary"],
                    urgency=match.get("urgency", Urgency.LOW),
                    inbox_item_id=match.get("inbox_item_id"),
                    # Keyed on the thing itself, not on the rule, so an
                    # automation and a proactive card about the same renewal
                    # collide instead of both firing.
                    source=_dedupe_key(match),
                )
                if notification is not None:
                    outcome.notifications_created += 1
                continue

            try:
                proposal = self.firewall.propose(
                    ProposalRequest(
                        owner_id=owner_id,
                        action_type=rule.action_type,
                        params={**(rule.action_params or {}), **match.get("params", {})},
                        actor_type=ActorType.AUTOMATION,
                        actor_id=rule.id,
                        actor_label=f"Automation: {rule.name}",
                        reason=match["summary"],
                        confidence=match.get("confidence", 0.9),
                        source_ids=match.get("source_ids", []),
                    )
                )
                outcome.proposals_created.append(proposal.id)
            except ActionRejected as exc:
                # A refusal is a normal outcome, not an error. It is recorded so
                # the owner can see their automation is asking for something
                # they have not permitted.
                outcome.errors.append(str(exc))
                log.info("automation.action_refused", rule=rule.id, reason=str(exc)[:120])

        self.audit.record(
            owner_id,
            AuditEventType.SECURITY,
            actor_type=ActorType.AUTOMATION,
            actor_id=rule.id,
            resource_type="automation_rule",
            resource_id=rule.id,
            reason=f"automation ran: {rule.name}",
            result="ran",
            details={
                "trigger": rule.trigger_type,
                "matched": outcome.matched,
                "proposals": len(outcome.proposals_created),
                "notifications": outcome.notifications_created,
                "refusals": len(outcome.errors),
            },
        )
        return outcome

    # ------------------------------------------------------------------
    # Triggers
    # ------------------------------------------------------------------

    def _evaluate_trigger(
        self, owner_id: str, rule: AutomationRule, now: dt.datetime
    ) -> list[dict]:
        config = rule.trigger_config or {}
        handler = {
            "obligation.due_within": self._trigger_obligation_due,
            "subscription.renewing": self._trigger_subscription_renewing,
            "email.unanswered_for": self._trigger_email_unanswered,
            "inbox.urgency_at_least": self._trigger_inbox_urgency,
            "document.expiring_within": self._trigger_document_expiring,
        }[rule.trigger_type]
        return handler(owner_id, config, now)

    def _trigger_obligation_due(self, owner_id: str, config: dict, now: dt.datetime) -> list[dict]:
        days = int(config.get("days_before", 7))
        horizon = now + dt.timedelta(days=days)
        rows = self.session.execute(
            sa.select(Obligation).where(
                Obligation.owner_id == owner_id,
                Obligation.archived.is_(False),
                Obligation.status.in_(
                    [ObligationStatus.OPEN.value, ObligationStatus.OVERDUE.value]
                ),
                Obligation.due_at.is_not(None),
                Obligation.due_at <= horizon,
                Obligation.due_at >= now - dt.timedelta(days=30),
            )
        ).scalars()

        out = []
        for obligation in rows:
            remaining = (obligation.due_at - now).days
            out.append(
                {
                    "summary": (
                        f"{obligation.title} is due "
                        + (f"in {remaining} days." if remaining >= 0 else "and is overdue.")
                    ),
                    "urgency": Urgency.HIGH if remaining <= 2 else Urgency.MEDIUM,
                    "source_ids": [f"obligation:{obligation.id}"],
                    "confidence": obligation.confidence,
                }
            )
        return out

    def _trigger_subscription_renewing(
        self, owner_id: str, config: dict, now: dt.datetime
    ) -> list[dict]:
        days = int(config.get("days_before", 3))
        rows = self.session.execute(
            sa.select(Entity).where(
                Entity.owner_id == owner_id,
                Entity.entity_type == EntityType.SUBSCRIPTION.value,
                Entity.archived.is_(False),
            )
        ).scalars()

        out = []
        for sub in rows:
            renews_on = _parse(sub.attributes.get("renews_on") if sub.attributes else None)
            if renews_on is None:
                continue
            remaining = (renews_on - now).days
            if not (0 <= remaining <= days):
                continue
            amount = (sub.attributes or {}).get("amount")
            out.append(
                {
                    "summary": (
                        f"{sub.name} renews in {remaining} day"
                        f"{'' if remaining == 1 else 's'}"
                        + (f" for ${amount:,.2f}." if amount else ".")
                    ),
                    "urgency": Urgency.MEDIUM,
                    "source_ids": [f"entity:{sub.id}"],
                    "confidence": sub.confidence,
                }
            )
        return out

    def _trigger_email_unanswered(
        self, owner_id: str, config: dict, now: dt.datetime
    ) -> list[dict]:
        hours = int(config.get("hours", 72))
        cutoff = now - dt.timedelta(hours=hours)
        rows = self.session.execute(
            sa.select(EmailMessage).where(
                EmailMessage.owner_id == owner_id,
                EmailMessage.requires_reply.is_(True),
                EmailMessage.replied_at.is_(None),
                EmailMessage.received_at <= cutoff,
                EmailMessage.received_at >= now - dt.timedelta(days=30),
            )
        ).scalars()

        out = []
        for message in rows:
            # Anything derived from an email body carries its taint. The
            # firewall will force approval; this just makes the provenance
            # explicit rather than implicit.
            out.append(
                {
                    "summary": (
                        f"{message.from_name or message.from_address} has been waiting "
                        f"{int((now - message.received_at).total_seconds() // 3600)} hours "
                        f"for a reply about “{message.subject or '(no subject)'}”."
                    ),
                    "urgency": Urgency.MEDIUM,
                    "source_ids": [f"email:{message.id}"],
                    "confidence": message.classification_confidence or 0.6,
                    "params": {
                        "to": [message.from_address],
                        "subject": message.subject or "Re:",
                        "in_reply_to": message.external_id,
                    },
                }
            )
        return out

    def _trigger_inbox_urgency(self, owner_id: str, config: dict, now: dt.datetime) -> list[dict]:
        threshold = float(config.get("min_score", 70))
        rows = self.session.execute(
            sa.select(InboxItem).where(
                InboxItem.owner_id == owner_id,
                InboxItem.state == InboxItemState.OPEN.value,
                InboxItem.priority_score >= threshold,
            )
        ).scalars()
        return [
            {
                "summary": item.explanation,
                "urgency": Urgency(item.urgency),
                "source_ids": item.source_ids or [],
                "confidence": item.confidence,
                "inbox_item_id": item.id,
            }
            for item in rows
        ]

    def _trigger_document_expiring(
        self, owner_id: str, config: dict, now: dt.datetime
    ) -> list[dict]:
        from mybot_schemas.models import Document

        days = int(config.get("days_before", 30))
        horizon = now + dt.timedelta(days=days)
        rows = self.session.execute(
            sa.select(Document).where(
                Document.owner_id == owner_id, Document.archived.is_(False)
            )
        ).scalars()

        out = []
        for document in rows:
            for extracted in document.extracted_fields or []:
                if extracted.get("field") != "expiration_date":
                    continue
                expires = _parse(extracted.get("value"))
                if expires is None or not (now <= expires <= horizon):
                    continue
                out.append(
                    {
                        "summary": (
                            f"{(document.document_type or document.filename).replace('_', ' ')} "
                            f"expires on {expires.strftime('%B %-d, %Y')}."
                        ),
                        "urgency": Urgency.MEDIUM,
                        "source_ids": [f"document:{document.id}"],
                        "confidence": float(extracted.get("confidence", 0.8)),
                    }
                )
        return out


def _dedupe_key(match: dict) -> str | None:
    """A stable key for the underlying record a trigger matched."""
    if match.get("inbox_item_id"):
        return f"inbox:{match['inbox_item_id']}"
    sources = match.get("source_ids") or []
    return f"source:{sources[0]}" if sources else None


def _parse(value) -> dt.datetime | None:
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except ValueError:
        try:
            parsed = dt.datetime.strptime(str(value), "%Y-%m-%d")
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


__all__ = ["AutomationEngine", "AutomationOutcome", "AutomationRunReport", "TRIGGER_TYPES"]
