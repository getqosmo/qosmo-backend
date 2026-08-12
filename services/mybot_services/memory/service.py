"""Durable memory.

The product promise is "MyBot remembers what matters" -- note the last two
words. Storing every sentence of every conversation forever is both a privacy
liability and, practically, a way to make retrieval worse. So memory is
tiered:

===============  ==========================================================
WORKING          scratch context for one exchange; never persisted here
CONVERSATION     chat history, retained on its own schedule, not "memory"
FACT             a durable thing the owner told MyBot
PREFERENCE       a standing preference ("afternoon appointments")
RULE             a standing instruction ("remind me before renewals")
INSTRUCTION      a one-off directive with a scope
===============  ==========================================================

Only the bottom four are durable, and every one of them is timestamped,
attributed, editable and deletable by the owner. Memory the user cannot see or
correct is not a feature, it is a liability.

Preferences also get a ``structured`` payload so they are *usable* by
deterministic code -- ``{"appointment_time_of_day": "afternoon"}`` can be
checked by the scheduler; a sentence cannot.
"""

from __future__ import annotations

import re

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    Classification,
    MemoryKind,
    SourceKind,
)
from mybot_schemas.models import Memory
from sqlalchemy.orm import Session

from ..audit.service import AuditService

#: Patterns that turn a natural-language preference into something structured
#: enough for deterministic code to act on. Deliberately small and explicit --
#: a missed pattern degrades to a plain text memory, which is still useful.
_PREFERENCE_PATTERNS: tuple[tuple[re.Pattern[str], str, object], ...] = (
    (re.compile(r"(?i)\bafternoon\b.*\bappointment|appointment.*\bafternoon\b"),
     "appointment_time_of_day", "afternoon"),
    (re.compile(r"(?i)\bmorning\b.*\bappointment|appointment.*\bmorning\b"),
     "appointment_time_of_day", "morning"),
    (re.compile(r"(?i)\bno meetings?\b.*\b(before|until)\s+(\d{1,2})"),
     "no_meetings_before", None),
    (re.compile(r"(?i)\bwindow seat\b"), "flight_seat", "window"),
    (re.compile(r"(?i)\baisle seat\b"), "flight_seat", "aisle"),
    (re.compile(r"(?i)\bvegetarian\b"), "dietary", "vegetarian"),
    (re.compile(r"(?i)\bremind me\b.*\bbefore\b.*\brenew"), "remind_before_renewal", True),
)


def extract_structured_preference(content: str) -> dict:
    """Best-effort structuring of a stated preference.

    Returns ``{}`` when nothing matches. An empty result is fine: the memory is
    still stored and searchable, it just cannot drive automation yet.
    """
    out: dict = {}
    for pattern, key, value in _PREFERENCE_PATTERNS:
        match = pattern.search(content)
        if not match:
            continue
        if value is None and match.groups():
            digits = [g for g in match.groups() if g and g.isdigit()]
            if digits:
                out[key] = int(digits[0])
        else:
            out[key] = value
    return out


class MemoryService:
    def __init__(self, session: Session, audit: AuditService | None = None):
        self.session = session
        self.audit = audit or AuditService(session)

    def remember(
        self,
        owner_id: str,
        content: str,
        *,
        kind: MemoryKind = MemoryKind.FACT,
        subject: str | None = None,
        entity_id: str | None = None,
        tags: list[str] | None = None,
        structured: dict | None = None,
        classification: Classification = Classification.PERSONAL,
        source_kind: SourceKind = SourceKind.USER_STATEMENT,
        source_id: str | None = None,
        confidence: float = 1.0,
        inferred: bool = False,
        actor_type: ActorType = ActorType.USER,
        actor_id: str | None = None,
    ) -> Memory:
        """Store a durable memory.

        Refuses ``WORKING`` and ``CONVERSATION`` kinds: those belong to the
        chat layer's own retention, and letting them in here is how a memory
        store quietly becomes a transcript archive.
        """
        if kind in (MemoryKind.WORKING, MemoryKind.CONVERSATION):
            raise ValueError(
                f"{kind.value} is transient context and is not stored as durable memory"
            )

        if structured is None and kind == MemoryKind.PREFERENCE:
            structured = extract_structured_preference(content)

        memory = Memory(
            owner_id=owner_id,
            kind=kind.value,
            content=content.strip(),
            subject=subject or _derive_subject(content),
            entity_id=entity_id,
            tags=tags or [],
            structured=structured or {},
            classification=classification.value,
            source_kind=str(source_kind),
            source_id=source_id,
            confidence=confidence,
            inferred=inferred,
        )
        self.session.add(memory)
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.MEMORY_WRITTEN,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type="memory",
            resource_id=memory.id,
            reason=f"remembered a {kind.value}",
            details={
                "kind": kind.value,
                "subject": memory.subject,
                "source_kind": str(source_kind),
                "structured_keys": sorted((structured or {}).keys()),
            },
        )
        return memory

    def correct(
        self,
        owner_id: str,
        memory_id: str,
        new_content: str,
        *,
        actor_id: str | None = None,
    ) -> Memory:
        """Apply a user correction.

        The old memory is superseded, not deleted, so "why did you think that?"
        remains answerable. The replacement is attributed to
        ``USER_CORRECTION``, which outranks any inference in the graph.
        """
        old = self.get(owner_id, memory_id)
        if old is None:
            raise LookupError("memory not found")

        replacement = self.remember(
            owner_id,
            new_content,
            kind=MemoryKind(old.kind),
            subject=old.subject,
            entity_id=old.entity_id,
            tags=old.tags,
            classification=Classification(old.classification),
            source_kind=SourceKind.USER_CORRECTION,
            source_id=f"memory:{old.id}",
            confidence=1.0,
            inferred=False,
            actor_id=actor_id,
        )
        old.superseded_by_id = replacement.id
        old.archived = True
        old.archived_at = utcnow()
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.MEMORY_SUPERSEDED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="memory",
            resource_id=replacement.id,
            reason="corrected by the owner",
            details={"superseded_memory_id": old.id},
        )
        return replacement

    def forget(self, owner_id: str, memory_id: str, *, actor_id: str | None = None) -> bool:
        """Delete a memory for real.

        The content is removed, and so is anything derived from it. The audit
        log keeps the *fact* that a deletion happened -- id, kind, timestamp,
        who asked -- but records nothing about what the memory said. Note that
        ``subject`` is derived from the content, so it is deliberately not
        logged either; retaining it would leave a readable fragment of
        something the owner asked to be gone. See ``docs/DATA_MODEL.md``.
        """
        memory = self.get(owner_id, memory_id)
        if memory is None:
            return False
        kind = memory.kind
        self.session.delete(memory)
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.MEMORY_DELETED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="memory",
            resource_id=memory_id,
            reason="deleted at the owner's request",
            details={"kind": kind, "content_removed": True},
        )
        return True

    def get(self, owner_id: str, memory_id: str) -> Memory | None:
        return self.session.execute(
            sa.select(Memory).where(Memory.owner_id == owner_id, Memory.id == memory_id)
        ).scalar_one_or_none()

    def search(
        self,
        owner_id: str,
        query: str | None = None,
        *,
        kind: MemoryKind | str | None = None,
        limit: int = 50,
        include_archived: bool = False,
    ) -> list[Memory]:
        stmt = sa.select(Memory).where(Memory.owner_id == owner_id)
        if not include_archived:
            stmt = stmt.where(Memory.archived.is_(False))
        if kind:
            stmt = stmt.where(Memory.kind == str(kind))
        if query:
            needle = f"%{query.lower()}%"
            stmt = stmt.where(
                sa.or_(
                    sa.func.lower(Memory.content).like(needle),
                    sa.func.lower(sa.func.coalesce(Memory.subject, "")).like(needle),
                )
            )
        return list(
            self.session.execute(stmt.order_by(Memory.created_at.desc()).limit(limit)).scalars()
        )

    def preferences(self, owner_id: str) -> dict:
        """Merged structured preferences, newest wins.

        This is what deterministic code consults -- the scheduler asking "does
        this person prefer afternoons?" gets a value, not a paragraph.
        """
        merged: dict = {}
        rows = self.search(owner_id, kind=MemoryKind.PREFERENCE, limit=200)
        for memory in sorted(rows, key=lambda m: m.created_at):
            merged.update(memory.structured or {})
        return merged

    def rules(self, owner_id: str) -> list[Memory]:
        return self.search(owner_id, kind=MemoryKind.RULE, limit=100)

    def touch(self, memory: Memory) -> None:
        memory.last_used_at = utcnow()
        self.session.flush()


def _derive_subject(content: str) -> str:
    words = content.strip().split()
    return " ".join(words[:8]) + ("…" if len(words) > 8 else "")


__all__ = ["MemoryService", "extract_structured_preference"]
