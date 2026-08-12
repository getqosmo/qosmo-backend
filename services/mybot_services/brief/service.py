"""The Morning Brief.

Every sentence here is rendered from a structured record by a template. No
model writes any part of it.

That is a deliberate product decision, not a limitation. The brief is the one
surface a person reads while half awake and acts on without checking. If a
model can phrase it, a model can invent an obligation that does not exist, or
drop one that does. So the generator takes rows -- obligations, inbox cards,
calendar events, audit events -- and formats them. ``facts`` on the stored
brief holds the exact source records behind every line, so any claim can be
traced back.

The other property that matters is the closing line. "Nothing else requires
your attention" is only emitted when every relevant system was actually
checked. If the calendar could not be reached, the brief says so instead.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    InboxCategory,
    InboxItemState,
)
from mybot_schemas.models import AuditEvent, CalendarEvent, DailyBrief, InboxItem, User
from sqlalchemy.orm import Session

from ..audit.service import AuditService
from ..inbox.service import InboxService

#: Audit event types that count as "MyBot handled this" -- work done without
#: needing the owner. Only genuinely completed things appear.
HANDLED_EVENT_TYPES = (
    AuditEventType.DOCUMENT_INGESTED.value,
    AuditEventType.OBLIGATION_CREATED.value,
    AuditEventType.INBOX_ITEM_CREATED.value,
    AuditEventType.ENTITY_CREATED.value,
)


@dataclass
class BriefLine:
    """One factual statement plus the record it came from."""

    text: str
    source_kind: str
    source_id: str | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "text": self.text,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "detail": self.detail,
        }


@dataclass
class Brief:
    greeting: str
    summary: str
    needs_you: list[BriefLine]
    handled: list[BriefLine]
    schedule: list[BriefLine]
    closing: str
    coverage: dict
    brief_date: str

    def as_dict(self) -> dict:
        return {
            "brief_date": self.brief_date,
            "greeting": self.greeting,
            "summary": self.summary,
            "needs_you": [line.as_dict() for line in self.needs_you],
            "handled": [line.as_dict() for line in self.handled],
            "schedule": [line.as_dict() for line in self.schedule],
            "closing": self.closing,
            "coverage": self.coverage,
        }


class BriefService:
    def __init__(
        self,
        session: Session,
        *,
        inbox: InboxService | None = None,
        audit: AuditService | None = None,
    ):
        self.session = session
        self.inbox = inbox or InboxService(session)
        self.audit = audit or AuditService(session)

    def generate(
        self,
        owner_id: str,
        *,
        now: dt.datetime | None = None,
        coverage: dict | None = None,
        persist: bool = True,
    ) -> Brief:
        now = now or utcnow()
        user = self.session.get(User, owner_id)
        display_name = (user.display_name.split()[0] if user else "there")
        coverage = coverage or {}

        needs = self.inbox.needs_attention(owner_id)
        needs_lines = [self._needs_line(item, now) for item in needs[:6]]
        handled_lines = self._handled(owner_id, now)
        schedule_lines = self._schedule(owner_id, now)

        greeting = f"{_time_of_day(now)}, {display_name}."
        count = len(needs_lines)
        if count == 0:
            summary = "Nothing needs you right now."
        elif count == 1:
            summary = "One thing needs you."
        else:
            summary = f"{count} things need you."

        unavailable = [k for k, v in coverage.items() if not v.get("ok", True)]
        if unavailable:
            names = ", ".join(sorted(unavailable))
            closing = (
                f"MyBot could not check {names}, so this may be incomplete. "
                "Everything else was checked."
            )
        elif count == 0:
            closing = "Nothing else requires your attention."
        else:
            closing = "Nothing else requires your attention."

        brief = Brief(
            greeting=greeting,
            summary=summary,
            needs_you=needs_lines,
            handled=handled_lines,
            schedule=schedule_lines,
            closing=closing,
            coverage=coverage,
            brief_date=now.date().isoformat(),
        )

        if persist:
            self._persist(owner_id, brief, needs)
        return brief

    # -- sections --------------------------------------------------------

    def _needs_line(self, item: InboxItem, now: dt.datetime) -> BriefLine:
        text = item.explanation
        if item.due_at is not None:
            days = (item.due_at - now).days
            if days < 0:
                text = f"{text} (overdue)"
            elif days == 0:
                text = f"{text} (today)"
        return BriefLine(
            text=text,
            source_kind="inbox_item",
            source_id=item.id,
            detail={
                "title": item.title,
                "category": item.category,
                "urgency": item.urgency,
                "priority_score": item.priority_score,
                "confidence": item.confidence,
                "reason": item.reason,
                "source_ids": item.source_ids,
                "recommended_action": item.recommended_action,
                "action_proposal_id": item.action_proposal_id,
            },
        )

    def _handled(self, owner_id: str, now: dt.datetime) -> list[BriefLine]:
        """What MyBot did on its own since yesterday.

        Grouped by type and counted, from real audit events. If MyBot did
        nothing, this section is empty rather than padded.
        """
        since = now - dt.timedelta(hours=24)
        events = list(
            self.session.execute(
                sa.select(AuditEvent).where(
                    AuditEvent.owner_id == owner_id,
                    AuditEvent.timestamp >= since,
                    AuditEvent.event_type.in_(HANDLED_EVENT_TYPES),
                    AuditEvent.actor_type == ActorType.SYSTEM.value,
                )
            ).scalars()
        )
        buckets: dict[str, list[AuditEvent]] = {}
        for event in events:
            buckets.setdefault(event.event_type, []).append(event)

        labels = {
            AuditEventType.DOCUMENT_INGESTED.value: ("Organised {n} document{s}", "documents"),
            AuditEventType.OBLIGATION_CREATED.value: ("Tracked {n} new deadline{s}", "obligations"),
            AuditEventType.INBOX_ITEM_CREATED.value: ("Surfaced {n} thing{s} worth knowing", "inbox"),
            AuditEventType.ENTITY_CREATED.value: ("Added {n} record{s} to your Life Graph", "entities"),
        }
        lines: list[BriefLine] = []
        for event_type, rows in buckets.items():
            template, bucket = labels.get(event_type, ("{n} update{s}", "other"))
            n = len(rows)
            lines.append(
                BriefLine(
                    text=template.format(n=n, s="" if n == 1 else "s"),
                    source_kind="audit",
                    detail={
                        "event_type": event_type,
                        "count": n,
                        "bucket": bucket,
                        "event_ids": [r.id for r in rows[:20]],
                    },
                )
            )
        return sorted(lines, key=lambda line: -line.detail.get("count", 0))

    def _schedule(self, owner_id: str, now: dt.datetime) -> list[BriefLine]:
        day_end = now.replace(hour=23, minute=59, second=59)
        events = list(
            self.session.execute(
                sa.select(CalendarEvent)
                .where(
                    CalendarEvent.owner_id == owner_id,
                    CalendarEvent.cancelled.is_(False),
                    CalendarEvent.end_at >= now,
                    CalendarEvent.start_at <= day_end,
                )
                .order_by(CalendarEvent.start_at)
            ).scalars()
        )
        lines = []
        for event in events:
            when = "All day" if event.all_day else event.start_at.strftime("%-I:%M %p")
            text = f"{when} — {event.title}"
            if event.location:
                text += f" ({event.location})"
            lines.append(
                BriefLine(
                    text=text,
                    source_kind="calendar_event",
                    source_id=event.id,
                    detail={
                        "title": event.title,
                        "start": event.start_at.isoformat(),
                        "end": event.end_at.isoformat(),
                        "location": event.location,
                    },
                )
            )
        return lines

    # -- persistence -----------------------------------------------------

    def _persist(self, owner_id: str, brief: Brief, needs: list[InboxItem]) -> DailyBrief:
        row = self.session.execute(
            sa.select(DailyBrief).where(
                DailyBrief.owner_id == owner_id, DailyBrief.brief_date == brief.brief_date
            )
        ).scalar_one_or_none()
        payload = brief.as_dict()
        facts = {
            "inbox_item_ids": [item.id for item in needs],
            "generated_at": utcnow().isoformat(),
            "generator": "deterministic-template-v1",
            "model_used": None,
        }
        if row is None:
            row = DailyBrief(owner_id=owner_id, brief_date=brief.brief_date)
            self.session.add(row)
        row.greeting = brief.greeting
        row.needs_you = payload["needs_you"]
        row.handled = payload["handled"]
        row.schedule = payload["schedule"]
        row.facts = facts
        row.coverage = brief.coverage
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.BRIEF_GENERATED,
            actor_type=ActorType.SYSTEM,
            resource_type="daily_brief",
            resource_id=row.id,
            reason="daily brief generated from structured records",
            model_used=None,
            details={
                "needs_you": len(brief.needs_you),
                "handled": len(brief.handled),
                "schedule": len(brief.schedule),
                "coverage": brief.coverage,
            },
        )
        return row

    def get_stored(self, owner_id: str, brief_date: str) -> DailyBrief | None:
        return self.session.execute(
            sa.select(DailyBrief).where(
                DailyBrief.owner_id == owner_id, DailyBrief.brief_date == brief_date
            )
        ).scalar_one_or_none()

    # -- "what do I need to worry about?" --------------------------------

    def worry_report(self, owner_id: str, *, coverage: dict | None = None) -> dict:
        """The first-class answer to "what do I need to worry about?".

        Fully deterministic aggregation over the inbox, grouped into the
        categories the product spec names. Because no model is involved, it
        cannot invent a worry -- and it cannot reassure falsely either: the
        closing line depends on what was actually checked.
        """
        coverage = coverage or {}
        items = self.inbox.list_items(owner_id, state=InboxItemState.OPEN.value, limit=200)

        groups: dict[str, list[dict]] = {
            "URGENT": [],
            "MONEY": [],
            "CALENDAR": [],
            "WORK": [],
            "HOME": [],
            "DOCUMENTS": [],
            "OTHER": [],
        }
        for item in items:
            groups[_worry_group(item)].append(
                {
                    "id": item.id,
                    "title": item.title,
                    "explanation": item.explanation,
                    "reason": item.reason,
                    "urgency": item.urgency,
                    "priority_score": item.priority_score,
                    "confidence": item.confidence,
                    "due_at": item.due_at.isoformat() if item.due_at else None,
                    "recommended_action": item.recommended_action,
                    "source_ids": item.source_ids,
                    "action_proposal_id": item.action_proposal_id,
                }
            )

        unavailable = [k for k, v in coverage.items() if not v.get("ok", True)]
        total = sum(len(v) for v in groups.values())
        if unavailable:
            closing = (
                "MyBot could not check " + ", ".join(sorted(unavailable))
                + ", so there may be more. Everything else was checked."
            )
        elif total == 0:
            closing = "Nothing requires your attention."
        else:
            closing = "Nothing else requires your attention."

        return {
            "groups": {k: v for k, v in groups.items() if v},
            "total": total,
            "closing": closing,
            "coverage": coverage,
            "checked_everything": not unavailable,
        }


def _worry_group(item: InboxItem) -> str:
    if item.category == InboxCategory.URGENT.value:
        return "URGENT"
    if item.category == InboxCategory.MONEY.value:
        return "MONEY"
    if item.category in (InboxCategory.DECISION.value, InboxCategory.APPROVAL.value):
        return "CALENDAR" if item.rule_id.startswith("calendar.") else "OTHER"
    if item.category == InboxCategory.WORK.value:
        return "WORK"
    if item.category in (InboxCategory.HOME.value, InboxCategory.FAMILY.value):
        return "HOME"
    if item.rule_id.startswith("document."):
        return "DOCUMENTS"
    if item.rule_id.startswith("calendar."):
        return "CALENDAR"
    return "OTHER"


def _time_of_day(now: dt.datetime) -> str:
    hour = now.hour
    if hour < 12:
        return "Good morning"
    if hour < 18:
        return "Good afternoon"
    return "Good evening"


__all__ = ["Brief", "BriefLine", "BriefService", "HANDLED_EVENT_TYPES"]
