"""Agent tools.

Every tool here is narrow, typed and owner-scoped. There is no
``execute_anything(command)``, no shell, no SQL passthrough and no generic
HTTP fetch. The reasoning layer's entire reachable surface is this file.

The read/mutate split is absolute:

* **Read tools** return structured data plus the ids that can cite it.
* **Mutation tools** return an :class:`ActionProposal`. They call the Action
  Firewall, which applies policy. They do not execute, and they cannot be made
  to -- the firewall decides, not the caller.

Note also what is *not* here: no tool reads the Vault, lists credentials,
creates permission rules, writes audit events, or touches another owner's
data. A tool that does not exist cannot be talked into running.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import ActorType, MemoryKind, SourceKind
from mybot_schemas.models import CalendarEvent, Document, EmailMessage
from sqlalchemy.orm import Session

from ..action_firewall.service import ActionFirewall, ProposalRequest
from ..inbox.service import InboxService
from ..life_graph.service import LifeGraphService
from ..memory.service import MemoryService
from ..obligations.service import ObligationService


@dataclass
class ToolResult:
    """A tool's answer plus everything needed to cite it."""

    name: str
    items: list[dict]
    #: Record ids backing the items, used for provenance in the reply.
    citations: list[str]
    #: Set when the underlying system could not be consulted at all.
    unavailable: str | None = None

    def as_dict(self) -> dict:
        return {
            "tool": self.name,
            "items": self.items,
            "citations": self.citations,
            "unavailable": self.unavailable,
        }


class AgentTools:
    """The complete tool surface available to the reasoning layer."""

    def __init__(self, session: Session, owner_id: str, firewall: ActionFirewall):
        self.session = session
        self.owner_id = owner_id
        self.firewall = firewall
        self.graph = LifeGraphService(session)
        self.memory = MemoryService(session)
        self.obligations = ObligationService(session)
        self.inbox = InboxService(session)

    # ==================================================================
    # Read tools
    # ==================================================================

    def lifegraph_find_entity(
        self, query: str, entity_type: str | None = None, limit: int = 10
    ) -> ToolResult:
        entities = self.graph.list_entities(
            self.owner_id, entity_type=entity_type, query=query, limit=limit
        )
        items = [
            {
                "id": e.id,
                "type": e.entity_type,
                "name": e.name,
                "summary": e.summary,
                "attributes": _safe_attributes(e.attributes),
                "confidence": e.confidence,
                "source": e.source_kind,
            }
            for e in entities
        ]
        return ToolResult("lifegraph_find_entity", items, [f"entity:{e.id}" for e in entities])

    def lifegraph_get_facts(self, entity_id: str) -> ToolResult:
        entity = self.graph.get_entity(self.owner_id, entity_id)
        if entity is None:
            return ToolResult("lifegraph_get_facts", [], [])
        facts = self.graph.current_facts(self.owner_id, entity_id)
        items = [
            {
                "key": f.key,
                "value": (f.value or {}).get("value"),
                "confidence": f.confidence,
                "source": f.source_kind,
                "evidence": f.evidence,
                "observed_at": f.observed_at.isoformat(),
            }
            for f in facts
        ]
        return ToolResult("lifegraph_get_facts", items, [f"fact:{f.id}" for f in facts])

    def memory_search(self, query: str | None = None, kind: str | None = None) -> ToolResult:
        memories = self.memory.search(self.owner_id, query, kind=kind, limit=25)
        items = [
            {
                "id": m.id,
                "kind": m.kind,
                "subject": m.subject,
                "content": m.content,
                "structured": m.structured,
                "created_at": m.created_at.isoformat(),
                "source": m.source_kind,
            }
            for m in memories
        ]
        return ToolResult("memory_search", items, [f"memory:{m.id}" for m in memories])

    def obligations_list(self, within_days: int | None = None, kind: str | None = None) -> ToolResult:
        rows = self.obligations.open_obligations(self.owner_id)
        if within_days is not None:
            horizon = utcnow() + dt.timedelta(days=within_days)
            rows = [o for o in rows if o.due_at is not None and o.due_at <= horizon]
        if kind:
            rows = [o for o in rows if o.kind == kind]
        rows.sort(key=lambda o: (o.due_at is None, o.due_at or utcnow()))
        items = [
            {
                "id": o.id,
                "title": o.title,
                "kind": o.kind,
                "status": o.status,
                "due_at": o.due_at.isoformat() if o.due_at else None,
                "amount": o.amount,
                "currency": o.currency,
                "consequence": o.consequence,
                "confidence": o.confidence,
                "source": o.source_detail or o.source_kind,
            }
            for o in rows
        ]
        return ToolResult("obligations_list", items, [f"obligation:{o.id}" for o in rows])

    def inbox_list(self, limit: int = 20) -> ToolResult:
        items_rows = self.inbox.list_items(self.owner_id, limit=limit)
        items = [
            {
                "id": i.id,
                "title": i.title,
                "explanation": i.explanation,
                "reason": i.reason,
                "category": i.category,
                "urgency": i.urgency,
                "priority_score": i.priority_score,
                "confidence": i.confidence,
                "due_at": i.due_at.isoformat() if i.due_at else None,
                "recommended_action": i.recommended_action,
            }
            for i in items_rows
        ]
        return ToolResult("inbox_list", items, [f"inbox_item:{i.id}" for i in items_rows])

    def calendar_list_events(self, days_ahead: int = 7, days_back: int = 0) -> ToolResult:
        now = utcnow()
        rows = list(
            self.session.execute(
                sa.select(CalendarEvent)
                .where(
                    CalendarEvent.owner_id == self.owner_id,
                    CalendarEvent.cancelled.is_(False),
                    CalendarEvent.end_at >= now - dt.timedelta(days=days_back),
                    CalendarEvent.start_at <= now + dt.timedelta(days=days_ahead),
                )
                .order_by(CalendarEvent.start_at)
            ).scalars()
        )
        items = [
            {
                "id": e.id,
                "external_id": e.external_id,
                "title": e.title,
                "start": e.start_at.isoformat(),
                "end": e.end_at.isoformat(),
                "location": e.location,
                "attendees": e.attendees,
                "all_day": e.all_day,
            }
            for e in rows
        ]
        return ToolResult("calendar_list_events", items, [f"calendar_event:{e.id}" for e in rows])

    def email_search(
        self, query: str | None = None, label: str | None = None, limit: int = 15
    ) -> ToolResult:
        """Search email metadata.

        Returns subjects, senders and classifications -- never bodies. A body
        is untrusted content and is only ever loaded through
        :meth:`email_get_body`, which wraps it explicitly.
        """
        stmt = sa.select(EmailMessage).where(EmailMessage.owner_id == self.owner_id)
        if label:
            stmt = stmt.where(EmailMessage.classification_label == label)
        if query:
            needle = f"%{query.lower()}%"
            stmt = stmt.where(
                sa.or_(
                    sa.func.lower(EmailMessage.subject).like(needle),
                    sa.func.lower(EmailMessage.from_address).like(needle),
                    sa.func.lower(sa.func.coalesce(EmailMessage.from_name, "")).like(needle),
                    sa.func.lower(sa.func.coalesce(EmailMessage.snippet, "")).like(needle),
                )
            )
        rows = list(
            self.session.execute(
                stmt.order_by(EmailMessage.received_at.desc()).limit(limit)
            ).scalars()
        )
        items = [
            {
                "id": m.id,
                "external_id": m.external_id,
                "from": m.from_name or m.from_address,
                "from_address": m.from_address,
                "subject": m.subject,
                "snippet": m.snippet,
                "received_at": m.received_at.isoformat(),
                "classification": m.classification_label,
                "requires_reply": m.requires_reply,
                "replied": m.replied_at is not None,
                "injection_suspected": m.injection_suspected,
            }
            for m in rows
        ]
        return ToolResult("email_search", items, [f"email:{m.id}" for m in rows])

    def email_get_body(self, email_id: str):
        """Load a message body as explicitly untrusted content.

        Returns an :class:`UntrustedContent`, not a string. Callers physically
        cannot drop it into a prompt without the wrapper, and anything derived
        from it inherits the taint.
        """
        from mybot_security.untrusted import UntrustedContent

        row = self.session.execute(
            sa.select(EmailMessage).where(
                EmailMessage.owner_id == self.owner_id, EmailMessage.id == email_id
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return UntrustedContent(
            text=row.body or row.snippet or "",
            source_id=f"email:{row.id}",
            source_kind="email",
            label=f"email from {row.from_address}",
            sender=row.from_address,
            received_at=row.received_at.isoformat(),
        )

    def document_list(self, document_type: str | None = None, limit: int = 25) -> ToolResult:
        stmt = sa.select(Document).where(
            Document.owner_id == self.owner_id, Document.archived.is_(False)
        )
        if document_type:
            stmt = stmt.where(Document.document_type == document_type)
        rows = list(
            self.session.execute(stmt.order_by(Document.created_at.desc()).limit(limit)).scalars()
        )
        items = [
            {
                "id": d.id,
                "filename": d.filename,
                "document_type": d.document_type,
                "issuer": d.issuer,
                "folder": d.folder,
                "fields": d.extracted_fields,
                "extraction_status": d.extraction_status,
            }
            for d in rows
        ]
        return ToolResult("document_list", items, [f"document:{d.id}" for d in rows])

    # ==================================================================
    # Mutation tools -- these produce proposals, never effects
    # ==================================================================

    def memory_write(
        self,
        content: str,
        kind: str = "fact",
        subject: str | None = None,
        *,
        actor_type: ActorType = ActorType.USER,
    ):
        """Store a durable memory.

        The one mutation that applies directly rather than proposing: it is
        internal, reversible, LOW risk, and the user just said it out loud.
        Still audited, still deletable.
        """
        return self.memory.remember(
            self.owner_id,
            content,
            kind=MemoryKind(kind),
            subject=subject,
            source_kind=SourceKind.USER_STATEMENT,
            actor_type=actor_type,
        )

    def calendar_propose_reschedule(
        self,
        event_external_id: str,
        new_start: dt.datetime,
        new_end: dt.datetime,
        reason: str,
        *,
        confidence: float = 0.9,
        source_ids: list[str] | None = None,
        derived_from_untrusted: bool = False,
        untrusted_source_ids: list[str] | None = None,
        original_start: dt.datetime | None = None,
    ):
        """Propose moving an event. Returns a proposal awaiting approval."""
        return self.firewall.propose(
            ProposalRequest(
                owner_id=self.owner_id,
                action_type="calendar.reschedule",
                params={
                    "event_id": event_external_id,
                    "new_start": new_start.isoformat(),
                    "new_end": new_end.isoformat(),
                    "calendar_id": "primary",
                },
                actor_type=ActorType.AGENT,
                actor_label="Calendar Assistant",
                reason=reason,
                resource="calendar:primary",
                confidence=confidence,
                source_ids=source_ids or [],
                derived_from_untrusted=derived_from_untrusted,
                untrusted_source_ids=untrusted_source_ids or [],
                context={"original_start": original_start.isoformat() if original_start else None},
            )
        )

    def email_create_draft(
        self,
        to: list[str],
        subject: str,
        body: str,
        reason: str,
        *,
        in_reply_to: str | None = None,
        confidence: float = 0.8,
        source_ids: list[str] | None = None,
        derived_from_untrusted: bool = False,
        untrusted_source_ids: list[str] | None = None,
    ):
        """Prepare a draft. Never sends -- ``email.send`` is a separate action."""
        return self.firewall.propose(
            ProposalRequest(
                owner_id=self.owner_id,
                action_type="email.draft",
                params={
                    "to": to,
                    "subject": subject,
                    "body": body,
                    "in_reply_to": in_reply_to,
                },
                actor_type=ActorType.AGENT,
                actor_label="Email Assistant",
                reason=reason,
                resource="email:draft",
                confidence=confidence,
                source_ids=source_ids or [],
                derived_from_untrusted=derived_from_untrusted,
                untrusted_source_ids=untrusted_source_ids or [],
            )
        )

    def obligation_create(
        self,
        title: str,
        due_at: dt.datetime,
        reason: str,
        *,
        kind: str = "generic",
        confidence: float = 0.8,
        source_ids: list[str] | None = None,
        derived_from_untrusted: bool = False,
        untrusted_source_ids: list[str] | None = None,
    ):
        return self.firewall.propose(
            ProposalRequest(
                owner_id=self.owner_id,
                action_type="obligation.create",
                params={"title": title, "due_date": due_at.isoformat(), "kind": kind},
                actor_type=ActorType.AGENT,
                actor_label="MyBot",
                reason=reason,
                confidence=confidence,
                source_ids=source_ids or [],
                derived_from_untrusted=derived_from_untrusted,
                untrusted_source_ids=untrusted_source_ids or [],
            )
        )


def _safe_attributes(attributes: dict | None) -> dict:
    """Strip internal bookkeeping before attributes reach the reasoning layer."""
    if not attributes:
        return {}
    return {k: v for k, v in attributes.items() if not k.startswith("_") and k != "possible_duplicate_of"}


#: Machine-readable descriptions for a provider that supports native tool
#: calling. Kept alongside the implementations so the two cannot drift.
TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "lifegraph_find_entity",
        "description": "Search the owner's Life Graph for people, organisations, vehicles, subscriptions, documents and other records.",
        "parameters": {"query": "string", "entity_type": "string?", "limit": "integer?"},
        "mutates": False,
    },
    {
        "name": "lifegraph_get_facts",
        "description": "Return the current attributed facts for one entity, with sources and confidence.",
        "parameters": {"entity_id": "string"},
        "mutates": False,
    },
    {
        "name": "memory_search",
        "description": "Search durable memories, preferences and standing rules.",
        "parameters": {"query": "string?", "kind": "string?"},
        "mutates": False,
    },
    {
        "name": "obligations_list",
        "description": "List open obligations, optionally within a number of days.",
        "parameters": {"within_days": "integer?", "kind": "string?"},
        "mutates": False,
    },
    {
        "name": "inbox_list",
        "description": "List open Life Inbox cards in priority order.",
        "parameters": {"limit": "integer?"},
        "mutates": False,
    },
    {
        "name": "calendar_list_events",
        "description": "List calendar events in a window.",
        "parameters": {"days_ahead": "integer?", "days_back": "integer?"},
        "mutates": False,
    },
    {
        "name": "email_search",
        "description": "Search email metadata. Returns subjects and senders, never bodies.",
        "parameters": {"query": "string?", "label": "string?", "limit": "integer?"},
        "mutates": False,
    },
    {
        "name": "document_list",
        "description": "List ingested documents and their extracted fields.",
        "parameters": {"document_type": "string?", "limit": "integer?"},
        "mutates": False,
    },
    {
        "name": "memory_write",
        "description": "Remember something durable the owner stated.",
        "parameters": {"content": "string", "kind": "string?", "subject": "string?"},
        "mutates": True,
        "risk": "LOW",
    },
    {
        "name": "calendar_propose_reschedule",
        "description": "Propose moving an event. Creates a proposal for approval; does not move anything.",
        "parameters": {"event_external_id": "string", "new_start": "datetime", "new_end": "datetime", "reason": "string"},
        "mutates": True,
        "risk": "MEDIUM",
        "requires_approval": True,
    },
    {
        "name": "email_create_draft",
        "description": "Prepare a draft reply for the owner to review. Never sends.",
        "parameters": {"to": "string[]", "subject": "string", "body": "string", "reason": "string"},
        "mutates": True,
        "risk": "LOW",
        "requires_approval": True,
    },
    {
        "name": "obligation_create",
        "description": "Track a new obligation with a due date and a source.",
        "parameters": {"title": "string", "due_at": "datetime", "reason": "string"},
        "mutates": True,
        "risk": "LOW",
    },
]


__all__ = ["AgentTools", "TOOL_SPECS", "ToolResult"]
