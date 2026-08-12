"""Obligations.

An obligation is not a todo. A todo is something you decided to do; an
obligation is something that happens *to* you if you do not. That difference
is why the model carries ``consequence``, ``source_ids`` and ``recurrence`` --
they are what let MyBot explain "your registration expires August 16, four
days from now, and driving after that is a citation" instead of showing a
checkbox.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    ObligationStatus,
    Recurrence,
    SourceKind,
)
from mybot_schemas.models import Obligation
from sqlalchemy.orm import Session

from ..audit.service import AuditService

_RECURRENCE_DAYS = {
    Recurrence.DAILY: 1,
    Recurrence.WEEKLY: 7,
    Recurrence.MONTHLY: 30,
    Recurrence.QUARTERLY: 91,
    Recurrence.YEARLY: 365,
}


class ObligationService:
    def __init__(self, session: Session, audit: AuditService | None = None):
        self.session = session
        self.audit = audit or AuditService(session)

    def create(
        self,
        owner_id: str,
        *,
        title: str,
        due_at: dt.datetime | None = None,
        kind: str = "generic",
        description: str | None = None,
        consequence: str | None = None,
        amount: float | None = None,
        currency: str | None = None,
        recurrence: Recurrence = Recurrence.NONE,
        entity_id: str | None = None,
        source_ids: list[str] | None = None,
        source_kind: SourceKind = SourceKind.USER_STATEMENT,
        source_detail: str | None = None,
        confidence: float = 1.0,
        inferred: bool = False,
        recommended_action_type: str | None = None,
        depends_on_ids: list[str] | None = None,
        remind_at: dt.datetime | None = None,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_id: str | None = None,
    ) -> Obligation:
        obligation = Obligation(
            owner_id=owner_id,
            title=title,
            description=description,
            kind=kind,
            due_at=due_at,
            recurrence=recurrence.value,
            amount=amount,
            currency=currency,
            consequence=consequence,
            entity_id=entity_id,
            source_ids=source_ids or [],
            source_kind=str(source_kind),
            source_detail=source_detail,
            confidence=confidence,
            inferred=inferred,
            recommended_action_type=recommended_action_type,
            depends_on_ids=depends_on_ids or [],
            remind_at=remind_at,
        )
        self.session.add(obligation)
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.OBLIGATION_CREATED,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type="obligation",
            resource_id=obligation.id,
            reason=f"tracked obligation: {title}",
            details={
                "kind": kind,
                "due_at": due_at.isoformat() if due_at else None,
                "source_kind": str(source_kind),
                "confidence": confidence,
            },
        )
        return obligation

    def get(self, owner_id: str, obligation_id: str) -> Obligation | None:
        return self.session.execute(
            sa.select(Obligation).where(
                Obligation.owner_id == owner_id, Obligation.id == obligation_id
            )
        ).scalar_one_or_none()

    def list(
        self,
        owner_id: str,
        *,
        status: str | None = None,
        due_before: dt.datetime | None = None,
        include_archived: bool = False,
        limit: int = 200,
    ) -> list[Obligation]:
        stmt = sa.select(Obligation).where(Obligation.owner_id == owner_id)
        if not include_archived:
            stmt = stmt.where(Obligation.archived.is_(False))
        if status:
            stmt = stmt.where(Obligation.status == status)
        if due_before is not None:
            stmt = stmt.where(Obligation.due_at.is_not(None), Obligation.due_at <= due_before)
        return list(
            self.session.execute(
                stmt.order_by(
                    Obligation.due_at.is_(None), Obligation.due_at.asc()
                ).limit(limit)
            ).scalars()
        )

    def open_obligations(self, owner_id: str) -> list[Obligation]:
        return [
            o
            for o in self.list(owner_id)
            if o.status
            in (
                ObligationStatus.OPEN.value,
                ObligationStatus.IN_PROGRESS.value,
                ObligationStatus.OVERDUE.value,
                ObligationStatus.BLOCKED.value,
            )
        ]

    def complete(
        self, owner_id: str, obligation_id: str, *, actor_id: str | None = None
    ) -> Obligation:
        """Mark done, rolling a recurring obligation forward to its next date."""
        obligation = self.get(owner_id, obligation_id)
        if obligation is None:
            raise LookupError("obligation not found")
        obligation.status = ObligationStatus.DONE.value
        obligation.completed_at = utcnow()
        self.session.flush()

        next_obligation = None
        recurrence = Recurrence(obligation.recurrence)
        if recurrence != Recurrence.NONE and obligation.due_at is not None:
            next_due = obligation.due_at + dt.timedelta(days=_RECURRENCE_DAYS[recurrence])
            next_obligation = self.create(
                owner_id,
                title=obligation.title,
                due_at=next_due,
                kind=obligation.kind,
                description=obligation.description,
                consequence=obligation.consequence,
                amount=obligation.amount,
                currency=obligation.currency,
                recurrence=recurrence,
                entity_id=obligation.entity_id,
                source_ids=obligation.source_ids,
                source_kind=SourceKind(obligation.source_kind),
                confidence=obligation.confidence,
                recommended_action_type=obligation.recommended_action_type,
                actor_id=actor_id,
            )

        self.audit.record(
            owner_id,
            AuditEventType.OBLIGATION_UPDATED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="obligation",
            resource_id=obligation.id,
            reason="completed",
            result="done",
            details={"next_occurrence": next_obligation.id if next_obligation else None},
        )
        return obligation

    def update_status(
        self, owner_id: str, obligation_id: str, status: ObligationStatus, *, actor_id: str | None = None
    ) -> Obligation:
        obligation = self.get(owner_id, obligation_id)
        if obligation is None:
            raise LookupError("obligation not found")
        obligation.status = status.value
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.OBLIGATION_UPDATED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="obligation",
            resource_id=obligation.id,
            reason=f"status set to {status.value}",
            result=status.value,
        )
        return obligation

    def mark_overdue(self, owner_id: str, *, now: dt.datetime | None = None) -> int:
        """Flip past-due open obligations to OVERDUE. Pure bookkeeping."""
        now = now or utcnow()
        rows = list(
            self.session.execute(
                sa.select(Obligation).where(
                    Obligation.owner_id == owner_id,
                    Obligation.status == ObligationStatus.OPEN.value,
                    Obligation.due_at.is_not(None),
                    Obligation.due_at < now,
                    Obligation.archived.is_(False),
                )
            ).scalars()
        )
        for obligation in rows:
            obligation.status = ObligationStatus.OVERDUE.value
        self.session.flush()
        return len(rows)


__all__ = ["ObligationService"]
