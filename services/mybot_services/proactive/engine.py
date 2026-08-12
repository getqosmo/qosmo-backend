"""The proactive engine.

Runs on a schedule, looks at the Life Graph and synced connector data, and
produces Life Inbox cards. Every rule is a plain function over structured data
with an explicit ``rule_id``, a stable ``dedupe_key`` and cited sources.

The instruction this implements most directly: *do not have an LLM
continuously re-read the entire database*. That would be expensive, slow,
non-deterministic, and would ship the user's whole life to a third party every
five minutes. Deterministic triggers fire first; a model may enrich the
resulting card afterwards, and only that card.

Rules currently implemented:

===========================  ==============================================
``obligation.due_soon``      deadline inside the horizon
``obligation.overdue``       past due and still open
``subscription.renewing``    renewal inside 3 days
``subscription.unused``      renewed recently, no recent use
``calendar.conflict``        two events overlap
``calendar.no_location``     in-person event with nowhere to be
``email.unanswered``         important message older than 72h
``email.injection``          message tried to give MyBot instructions
``document.expiring``        document expiry inside the horizon
``bill.due_soon``            bill with an amount inside the horizon
===========================  ==============================================
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    EntityType,
    InboxCategory,
    ObligationStatus,
    SecurityEventType,
)
from mybot_schemas.models import (
    CalendarEvent,
    Document,
    EmailMessage,
    Entity,
    Obligation,
    SecurityEvent,
)
from sqlalchemy.orm import Session

from ..inbox.service import CardDraft, InboxService
from ..memory.service import MemoryService
from ..obligations.service import ObligationService
from .intel import CLASS_ACTIONABLE, CLASS_IMPORTANT, find_conflicts, missing_location

#: How far ahead deadlines are surfaced.
DEADLINE_HORIZON_DAYS = 14
RENEWAL_HORIZON_DAYS = 3
UNANSWERED_HOURS = 72
DOCUMENT_HORIZON_DAYS = 60
#: A subscription is "unused" if it renewed and has not been touched in this long.
UNUSED_SUBSCRIPTION_DAYS = 60


@dataclass
class ScanReport:
    """What a scan did, and -- importantly -- what it could not check.

    ``unavailable`` is what stops MyBot from saying "nothing else requires
    your attention" when it simply could not reach the calendar.
    """

    cards_created: int = 0
    cards_updated: int = 0
    rules_run: list[str] = None
    unavailable: list[str] = None

    def __post_init__(self):
        self.rules_run = self.rules_run or []
        self.unavailable = self.unavailable or []

    @property
    def fully_covered(self) -> bool:
        return not self.unavailable

    def as_dict(self) -> dict:
        return {
            "cards": self.cards_created + self.cards_updated,
            "created": self.cards_created,
            "updated": self.cards_updated,
            "rules_run": self.rules_run,
            "unavailable": self.unavailable,
            "fully_covered": self.fully_covered,
        }


class ProactiveEngine:
    def __init__(
        self,
        session: Session,
        *,
        inbox: InboxService | None = None,
        obligations: ObligationService | None = None,
        memory: MemoryService | None = None,
    ):
        self.session = session
        self.inbox = inbox or InboxService(session)
        self.obligations = obligations or ObligationService(session)
        self.memory = memory or MemoryService(session)

    def scan(self, owner_id: str, *, now: dt.datetime | None = None) -> ScanReport:
        now = now or utcnow()
        report = ScanReport()
        prefs = self.memory.preferences(owner_id)
        self.obligations.mark_overdue(owner_id, now=now)

        for rule in (
            self._rule_obligations,
            self._rule_subscriptions,
            self._rule_calendar,
            self._rule_email,
            self._rule_documents,
        ):
            rule(owner_id, now, report, prefs)

        return report

    # -- rules -----------------------------------------------------------

    def _rule_obligations(self, owner_id: str, now: dt.datetime, report: ScanReport, prefs: dict) -> None:
        report.rules_run.append("obligation.due_soon")
        report.rules_run.append("obligation.overdue")
        horizon = now + dt.timedelta(days=DEADLINE_HORIZON_DAYS)

        rows = list(
            self.session.execute(
                sa.select(Obligation).where(
                    Obligation.owner_id == owner_id,
                    Obligation.archived.is_(False),
                    Obligation.status.in_(
                        [
                            ObligationStatus.OPEN.value,
                            ObligationStatus.IN_PROGRESS.value,
                            ObligationStatus.OVERDUE.value,
                        ]
                    ),
                    Obligation.due_at.is_not(None),
                    Obligation.due_at <= horizon,
                )
            ).scalars()
        )

        for obligation in rows:
            overdue = obligation.due_at < now
            days = (obligation.due_at - now).days
            rule_id = "obligation.overdue" if overdue else "obligation.due_soon"

            if overdue:
                when = f"was due {abs(days)} day{'s' if abs(days) != 1 else ''} ago"
                category = InboxCategory.URGENT
            elif days <= 0:
                when = "is due today"
                category = InboxCategory.URGENT
            else:
                when = f"is due in {days} day{'s' if days != 1 else ''}"
                category = InboxCategory.MONEY if obligation.amount else InboxCategory.URGENT
                if days > 7:
                    category = InboxCategory.FYI if not obligation.amount else InboxCategory.MONEY

            explanation = f"{obligation.title} {when}."
            if obligation.amount:
                explanation += f" Amount: ${obligation.amount:,.2f}."
            if obligation.consequence:
                explanation += f" {obligation.consequence}"

            actions: list[dict] = []
            if obligation.recommended_action_type:
                actions.append(
                    {
                        "label": _action_label(obligation.recommended_action_type),
                        "action_type": obligation.recommended_action_type,
                        "requires_approval": True,
                    }
                )
            actions.append({"label": "Mark as done", "action_type": "obligation.complete"})

            self._emit(
                owner_id,
                CardDraft(
                    dedupe_key=f"obligation:{obligation.id}",
                    rule_id=rule_id,
                    category=category,
                    title=obligation.title,
                    explanation=explanation,
                    reason=_obligation_reason(obligation),
                    confidence=obligation.confidence,
                    due_at=obligation.due_at,
                    financial_impact=obligation.amount,
                    importance=0.8 if overdue else 0.6,
                    irreversible=obligation.kind in ("registration_renewal", "tax", "legal"),
                    source_ids=list(obligation.source_ids or []),
                    evidence=[
                        {
                            "kind": "obligation",
                            "id": obligation.id,
                            "due_at": obligation.due_at.isoformat(),
                            "source_kind": obligation.source_kind,
                            "source_detail": obligation.source_detail,
                        }
                    ],
                    obligation_id=obligation.id,
                    entity_id=obligation.entity_id,
                    possible_actions=actions,
                    recommended_action=(
                        _action_label(obligation.recommended_action_type)
                        if obligation.recommended_action_type
                        else "Review"
                    ),
                ),
                report,
                now,
            )

    def _rule_subscriptions(self, owner_id: str, now: dt.datetime, report: ScanReport, prefs: dict) -> None:
        report.rules_run.append("subscription.renewing")
        report.rules_run.append("subscription.unused")

        subs = list(
            self.session.execute(
                sa.select(Entity).where(
                    Entity.owner_id == owner_id,
                    Entity.entity_type == EntityType.SUBSCRIPTION.value,
                    Entity.archived.is_(False),
                )
            ).scalars()
        )
        wants_renewal_reminders = bool(prefs.get("remind_before_renewal"))

        for sub in subs:
            attrs = sub.attributes or {}
            amount = attrs.get("amount")
            renews_on = _parse_iso(attrs.get("renews_on"))
            last_used = _parse_iso(attrs.get("last_used_at"))

            if renews_on is not None:
                days = (renews_on - now).days
                if 0 <= days <= RENEWAL_HORIZON_DAYS:
                    self._emit(
                        owner_id,
                        CardDraft(
                            dedupe_key=f"subscription-renewal:{sub.id}:{renews_on.date()}",
                            rule_id="subscription.renewing",
                            category=InboxCategory.MONEY,
                            title=f"{sub.name} renews in {days} day{'s' if days != 1 else ''}",
                            explanation=(
                                f"{sub.name} renews on {renews_on.strftime('%B %-d')}"
                                + (f" for ${amount:,.2f}." if amount else ".")
                            ),
                            reason=(
                                f"The renewal date on record for {sub.name} is "
                                f"{renews_on.date().isoformat()}."
                            ),
                            confidence=sub.confidence,
                            due_at=renews_on,
                            financial_impact=amount,
                            importance=0.5,
                            matches_user_rule=wants_renewal_reminders,
                            source_ids=[f"entity:{sub.id}"],
                            evidence=[{"kind": "entity", "id": sub.id, "renews_on": renews_on.isoformat()}],
                            entity_id=sub.id,
                            possible_actions=[
                                {
                                    "label": "Cancel subscription",
                                    "action_type": "subscription.cancel",
                                    "requires_approval": True,
                                },
                                {"label": "Keep it", "action_type": "inbox.dismiss"},
                            ],
                            recommended_action="Review before it renews",
                        ),
                        report,
                        now,
                    )

            if last_used is not None and amount:
                idle_days = (now - last_used).days
                if idle_days >= UNUSED_SUBSCRIPTION_DAYS:
                    self._emit(
                        owner_id,
                        CardDraft(
                            dedupe_key=f"subscription-unused:{sub.id}",
                            rule_id="subscription.unused",
                            category=InboxCategory.MONEY,
                            title=f"{sub.name} renewed for ${amount:,.2f}",
                            explanation=(
                                f"{sub.name} renewed for ${amount:,.2f}. "
                                f"MyBot has no record of you using it in {idle_days} days."
                            ),
                            reason=(
                                f"Last recorded use of {sub.name} was "
                                f"{last_used.date().isoformat()}, {idle_days} days ago."
                            ),
                            # Absence of evidence is not evidence of absence:
                            # MyBot may simply not see the usage signal.
                            confidence=0.7,
                            financial_impact=amount,
                            importance=0.45,
                            source_ids=[f"entity:{sub.id}"],
                            evidence=[
                                {"kind": "entity", "id": sub.id, "last_used_at": last_used.isoformat()},
                                {"kind": "caveat", "note": "usage is inferred from limited signals"},
                            ],
                            entity_id=sub.id,
                            possible_actions=[
                                {
                                    "label": "Cancel subscription",
                                    "action_type": "subscription.cancel",
                                    "requires_approval": True,
                                },
                                {"label": "I still use it", "action_type": "inbox.dismiss"},
                            ],
                            recommended_action="Decide whether to keep it",
                        ),
                        report,
                        now,
                    )

    def _rule_calendar(self, owner_id: str, now: dt.datetime, report: ScanReport, prefs: dict) -> None:
        report.rules_run.append("calendar.conflict")
        report.rules_run.append("calendar.no_location")

        window_end = now + dt.timedelta(days=14)
        events = list(
            self.session.execute(
                sa.select(CalendarEvent).where(
                    CalendarEvent.owner_id == owner_id,
                    CalendarEvent.cancelled.is_(False),
                    CalendarEvent.end_at >= now,
                    CalendarEvent.start_at <= window_end,
                )
            ).scalars()
        )
        if not events:
            # Distinguish "no events" from "could not check": the caller only
            # records unavailability when a connector actually failed.
            return

        for conflict in find_conflicts(events):
            first = next(e for e in events if e.id == conflict.first_id)
            second = next(e for e in events if e.id == conflict.second_id)
            self._emit(
                owner_id,
                CardDraft(
                    dedupe_key=f"conflict:{min(conflict.first_id, conflict.second_id)}:"
                    f"{max(conflict.first_id, conflict.second_id)}",
                    rule_id="calendar.conflict",
                    category=InboxCategory.DECISION,
                    title="Two things are booked at the same time",
                    explanation=(
                        f"“{first.title}” and “{second.title}” overlap by "
                        f"{conflict.overlap_minutes} minutes on "
                        f"{conflict.starts_at.strftime('%A %B %-d')}."
                    ),
                    reason=(
                        f"“{first.title}” runs {first.start_at.strftime('%-I:%M %p')}–"
                        f"{first.end_at.strftime('%-I:%M %p')} and “{second.title}” runs "
                        f"{second.start_at.strftime('%-I:%M %p')}–{second.end_at.strftime('%-I:%M %p')}."
                    ),
                    confidence=1.0,
                    due_at=conflict.starts_at,
                    importance=0.75,
                    source_ids=[f"calendar_event:{first.id}", f"calendar_event:{second.id}"],
                    evidence=[
                        {
                            "kind": "calendar_event",
                            "id": first.id,
                            "title": first.title,
                            "start": first.start_at.isoformat(),
                            "end": first.end_at.isoformat(),
                        },
                        {
                            "kind": "calendar_event",
                            "id": second.id,
                            "title": second.title,
                            "start": second.start_at.isoformat(),
                            "end": second.end_at.isoformat(),
                        },
                    ],
                    possible_actions=[
                        {
                            "label": f"Move “{_movable(first, second, conflict).title}”",
                            "action_type": "calendar.reschedule",
                            "requires_approval": True,
                            "event_id": _movable(first, second, conflict).external_id,
                        },
                        {"label": "Leave both", "action_type": "inbox.dismiss"},
                    ],
                    recommended_action=f"Move “{_movable(first, second, conflict).title}”",
                ),
                report,
                now,
            )

        for event in missing_location(events):
            if (event.start_at - now).days > 3:
                continue
            self._emit(
                owner_id,
                CardDraft(
                    dedupe_key=f"no-location:{event.id}",
                    rule_id="calendar.no_location",
                    category=InboxCategory.FYI,
                    title=f"“{event.title}” has no location",
                    explanation=(
                        f"“{event.title}” on {event.start_at.strftime('%A at %-I:%M %p')} "
                        "has no address and does not look like a video call."
                    ),
                    reason="The calendar entry has an empty location field.",
                    confidence=0.85,
                    due_at=event.start_at,
                    importance=0.3,
                    source_ids=[f"calendar_event:{event.id}"],
                    evidence=[{"kind": "calendar_event", "id": event.id, "title": event.title}],
                    possible_actions=[{"label": "Dismiss", "action_type": "inbox.dismiss"}],
                    recommended_action="Add a location",
                ),
                report,
                now,
            )

    def _rule_email(self, owner_id: str, now: dt.datetime, report: ScanReport, prefs: dict) -> None:
        report.rules_run.append("email.unanswered")
        report.rules_run.append("email.injection")

        cutoff = now - dt.timedelta(hours=UNANSWERED_HOURS)
        messages = list(
            self.session.execute(
                sa.select(EmailMessage).where(
                    EmailMessage.owner_id == owner_id,
                    EmailMessage.received_at >= now - dt.timedelta(days=30),
                )
            ).scalars()
        )

        for message in messages:
            if (
                message.classification_label in (CLASS_ACTIONABLE, CLASS_IMPORTANT)
                and message.requires_reply
                and message.replied_at is None
                and message.received_at <= cutoff
            ):
                age_hours = int((now - message.received_at).total_seconds() / 3600)
                days = age_hours // 24
                sender = message.from_name or message.from_address
                self._emit(
                    owner_id,
                    CardDraft(
                        dedupe_key=f"unanswered:{message.id}",
                        rule_id="email.unanswered",
                        category=InboxCategory.WORK,
                        title=f"Unanswered: {message.subject or '(no subject)'}",
                        explanation=(
                            f"{sender} wrote {days} day{'s' if days != 1 else ''} ago and "
                            "appears to be waiting for a reply."
                        ),
                        reason=(
                            "Classified as "
                            f"{message.classification_label} because: "
                            + "; ".join((message.extracted or {}).get("signals", [])[:2])
                            + f". Received {message.received_at.strftime('%B %-d')}, no reply recorded."
                        ),
                        confidence=message.classification_confidence or 0.6,
                        importance=0.7,
                        source_ids=[f"email:{message.id}"],
                        evidence=[
                            {
                                "kind": "email",
                                "id": message.id,
                                "from": message.from_address,
                                "subject": message.subject,
                                "received_at": message.received_at.isoformat(),
                                "untrusted": True,
                            }
                        ],
                        possible_actions=[
                            {
                                "label": "Draft a reply",
                                "action_type": "email.draft",
                                "requires_approval": True,
                                "message_id": message.external_id,
                            },
                            {"label": "Not important", "action_type": "inbox.dismiss"},
                        ],
                        recommended_action="Draft a reply",
                    ),
                    report,
                    now,
                )

            if message.injection_suspected:
                self._emit(
                    owner_id,
                    CardDraft(
                        dedupe_key=f"injection:{message.id}",
                        rule_id="email.injection",
                        category=InboxCategory.FYI,
                        title="An email tried to give MyBot instructions",
                        explanation=(
                            f"A message from {message.from_address} contains text written to look "
                            "like a command to MyBot. It was treated as data only and no action "
                            "was taken."
                        ),
                        reason=(
                            "Matched patterns: "
                            + ", ".join((message.extracted or {}).get("injection_patterns", []))
                            + ". Untrusted content can never trigger a privileged action."
                        ),
                        confidence=0.95,
                        importance=0.4,
                        source_ids=[f"email:{message.id}"],
                        evidence=[
                            {
                                "kind": "security",
                                "id": message.id,
                                "from": message.from_address,
                                "subject": message.subject,
                                "patterns": (message.extracted or {}).get("injection_patterns", []),
                            }
                        ],
                        possible_actions=[{"label": "Acknowledge", "action_type": "inbox.dismiss"}],
                        recommended_action="No action needed",
                    ),
                    report,
                    now,
                )
                self._ensure_security_event(owner_id, message)

    def _rule_documents(self, owner_id: str, now: dt.datetime, report: ScanReport, prefs: dict) -> None:
        report.rules_run.append("document.expiring")
        horizon = now + dt.timedelta(days=DOCUMENT_HORIZON_DAYS)

        documents = list(
            self.session.execute(
                sa.select(Document).where(
                    Document.owner_id == owner_id, Document.archived.is_(False)
                )
            ).scalars()
        )

        # A document whose expiry already produced an obligation is covered by
        # the obligation rule. Emitting both would show the same deadline
        # twice, worded differently -- which reads as two problems and erodes
        # trust in the count on the home screen.
        tracked_sources = {
            source
            for obligation in self.session.execute(
                sa.select(Obligation).where(
                    Obligation.owner_id == owner_id,
                    Obligation.archived.is_(False),
                    Obligation.status != ObligationStatus.DONE.value,
                )
            ).scalars()
            for source in (obligation.source_ids or [])
        }

        for document in documents:
            if f"document:{document.id}" in tracked_sources:
                continue
            for field_data in document.extracted_fields or []:
                if field_data.get("field") not in ("expiration_date", "renewal_date"):
                    continue
                expires = _parse_iso(field_data.get("value"))
                if expires is None or expires > horizon or expires < now - dt.timedelta(days=1):
                    continue
                days = (expires - now).days
                confidence = float(field_data.get("confidence", 0.7))
                self._emit(
                    owner_id,
                    CardDraft(
                        dedupe_key=f"document-expiry:{document.id}:{field_data.get('field')}",
                        rule_id="document.expiring",
                        category=InboxCategory.URGENT if days <= 14 else InboxCategory.FYI,
                        title=f"{document.document_type or document.filename} expires in {days} days",
                        explanation=(
                            f"{(document.document_type or document.filename).replace('_', ' ').title()} "
                            f"expires on {expires.strftime('%B %-d, %Y')}."
                        ),
                        reason=(
                            f"Extracted from {document.filename}"
                            + (f" ({field_data['evidence']})" if field_data.get("evidence") else "")
                            + f", confidence {confidence:.0%}."
                        ),
                        confidence=confidence,
                        due_at=expires,
                        importance=0.7,
                        irreversible=True,
                        source_ids=[f"document:{document.id}"],
                        evidence=[
                            {
                                "kind": "document",
                                "id": document.id,
                                "filename": document.filename,
                                "field": field_data.get("field"),
                                "value": field_data.get("value"),
                                "confidence": confidence,
                                "excerpt": field_data.get("evidence"),
                            }
                        ],
                        possible_actions=[
                            {"label": "Add a reminder", "action_type": "obligation.create"},
                            {"label": "Dismiss", "action_type": "inbox.dismiss"},
                        ],
                        recommended_action="Renew before it expires",
                    ),
                    report,
                    now,
                )

    # -- helpers ---------------------------------------------------------

    def _emit(self, owner_id: str, draft: CardDraft, report: ScanReport, now: dt.datetime) -> None:
        from mybot_schemas.models import InboxItem

        existed = self.session.execute(
            sa.select(sa.func.count())
            .select_from(InboxItem)
            .where(InboxItem.owner_id == owner_id, InboxItem.dedupe_key == draft.dedupe_key)
        ).scalar_one()
        self.inbox.upsert(owner_id, draft, now=now)
        if existed:
            report.cards_updated += 1
        else:
            report.cards_created += 1

    def _ensure_security_event(self, owner_id: str, message: EmailMessage) -> None:
        # Dedupe on the summary rather than a JSON path: JSON containment
        # queries differ between SQLite and Postgres, and this record only
        # needs to exist once per message.
        summary = f"Injection-shaped content in message {message.external_id}"
        duplicate = self.session.execute(
            sa.select(sa.func.count())
            .select_from(SecurityEvent)
            .where(
                SecurityEvent.owner_id == owner_id,
                SecurityEvent.event_type == SecurityEventType.PROMPT_INJECTION_SUSPECTED.value,
                SecurityEvent.summary == summary,
            )
        ).scalar_one()
        if duplicate:
            return
        self.session.add(
            SecurityEvent(
                owner_id=owner_id,
                event_type=SecurityEventType.PROMPT_INJECTION_SUSPECTED.value,
                severity="warning",
                summary=summary,
                details={
                    "email_id": message.id,
                    "from": message.from_address,
                    "patterns": (message.extracted or {}).get("injection_patterns", []),
                    "outcome": "content treated as data; no action taken",
                },
            )
        )
        self.session.flush()


def _movable(first, second, conflict):
    return first if conflict.suggested_move_id == first.id else second


def _obligation_reason(obligation: Obligation) -> str:
    parts = [f"Due {obligation.due_at.strftime('%B %-d, %Y')}."]
    if obligation.source_detail:
        parts.append(f"Source: {obligation.source_detail}.")
    if obligation.confidence < 1.0:
        parts.append(f"Confidence {obligation.confidence:.0%}.")
    return " ".join(parts)


def _action_label(action_type: str | None) -> str:
    from mybot_schemas.actions import ACTION_REGISTRY

    if not action_type:
        return "Review"
    spec = ACTION_REGISTRY.get(action_type)
    return spec.display if spec else "Review"


def _parse_iso(value) -> dt.datetime | None:
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


__all__ = [
    "DEADLINE_HORIZON_DAYS",
    "ProactiveEngine",
    "RENEWAL_HORIZON_DAYS",
    "ScanReport",
    "UNANSWERED_HOURS",
]
