"""The Life Inbox.

The homepage of MyBot is this, not a chat box. Cards are created by the
deterministic proactive engine and carry everything the UI needs to be
honest: what it is, why MyBot thinks so, where that came from, how confident
it is, and what could be done about it.

``dedupe_key`` does more work than it looks like. It is what keeps a
scheduler that runs every five minutes from producing 288 copies of "your
registration expires soon" a day, and it is what lets a card *update* --
urgency climbing as a deadline approaches -- rather than being replaced.
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
from mybot_schemas.models import InboxItem
from sqlalchemy.orm import Session

from ..audit.service import AuditService
from .priority import PriorityInputs, score


@dataclass
class CardDraft:
    """What a proactive rule produces. Not yet a database row."""

    dedupe_key: str
    rule_id: str
    category: InboxCategory
    title: str
    explanation: str
    reason: str | None = None
    confidence: float = 1.0
    due_at: dt.datetime | None = None
    financial_impact: float | None = None
    importance: float = 0.5
    irreversible: bool = False
    matches_user_rule: bool = False
    source_ids: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    obligation_id: str | None = None
    entity_id: str | None = None
    possible_actions: list[dict] = field(default_factory=list)
    recommended_action: str | None = None


class InboxService:
    def __init__(self, session: Session, audit: AuditService | None = None):
        self.session = session
        self.audit = audit or AuditService(session)

    def upsert(self, owner_id: str, draft: CardDraft, *, now: dt.datetime | None = None) -> InboxItem:
        """Create or refresh a card.

        Refreshing preserves the card's identity and any user state (snoozed,
        dismissed) while updating the fields that legitimately change over
        time: urgency, score, explanation, evidence.
        """
        now = now or utcnow()
        hours = (draft.due_at - now).total_seconds() / 3600.0 if draft.due_at else None
        result = score(
            PriorityInputs(
                category=draft.category.value,
                hours_until_due=hours,
                financial_impact=draft.financial_impact,
                importance=draft.importance,
                confidence=draft.confidence,
                irreversible=draft.irreversible,
                matches_user_rule=draft.matches_user_rule,
            )
        )

        existing = self.session.execute(
            sa.select(InboxItem).where(
                InboxItem.owner_id == owner_id, InboxItem.dedupe_key == draft.dedupe_key
            )
        ).scalar_one_or_none()

        evidence = list(draft.evidence)
        evidence.append({"priority_breakdown": result.breakdown})

        if existing is not None:
            existing.title = draft.title
            existing.explanation = draft.explanation
            existing.reason = draft.reason
            existing.confidence = draft.confidence
            existing.urgency = result.urgency.value
            existing.priority_score = result.score
            existing.due_at = draft.due_at
            existing.source_ids = draft.source_ids
            existing.evidence = evidence
            existing.possible_actions = draft.possible_actions
            existing.recommended_action = draft.recommended_action
            existing.updated_at = now
            # A snooze that has run out returns the card to the inbox.
            if (
                existing.state == InboxItemState.SNOOZED.value
                and existing.snoozed_until is not None
                and existing.snoozed_until <= now
            ):
                existing.state = InboxItemState.OPEN.value
                existing.snoozed_until = None
            self.session.flush()
            return existing

        item = InboxItem(
            owner_id=owner_id,
            dedupe_key=draft.dedupe_key,
            rule_id=draft.rule_id,
            category=draft.category.value,
            urgency=result.urgency.value,
            priority_score=result.score,
            state=InboxItemState.OPEN.value,
            title=draft.title,
            explanation=draft.explanation,
            reason=draft.reason,
            confidence=draft.confidence,
            source_ids=draft.source_ids,
            evidence=evidence,
            obligation_id=draft.obligation_id,
            entity_id=draft.entity_id,
            possible_actions=draft.possible_actions,
            recommended_action=draft.recommended_action,
            due_at=draft.due_at,
        )
        self.session.add(item)
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.INBOX_ITEM_CREATED,
            actor_type=ActorType.SYSTEM,
            actor_id=draft.rule_id,
            resource_type="inbox_item",
            resource_id=item.id,
            reason=draft.explanation[:300],
            details={
                "rule_id": draft.rule_id,
                "category": draft.category.value,
                "urgency": result.urgency.value,
                "score": result.score,
                "confidence": draft.confidence,
                "source_ids": draft.source_ids,
            },
        )
        return item

    def list_items(
        self,
        owner_id: str,
        *,
        state: str | None = InboxItemState.OPEN.value,
        category: str | None = None,
        limit: int = 100,
        now: dt.datetime | None = None,
    ) -> list[InboxItem]:
        now = now or utcnow()
        stmt = sa.select(InboxItem).where(InboxItem.owner_id == owner_id)
        if state:
            if state == InboxItemState.OPEN.value:
                # A snoozed card whose time has come counts as open.
                stmt = stmt.where(
                    sa.or_(
                        InboxItem.state == InboxItemState.OPEN.value,
                        sa.and_(
                            InboxItem.state == InboxItemState.SNOOZED.value,
                            InboxItem.snoozed_until.is_not(None),
                            InboxItem.snoozed_until <= now,
                        ),
                    )
                )
            else:
                stmt = stmt.where(InboxItem.state == state)
        if category:
            stmt = stmt.where(InboxItem.category == category)
        return list(
            self.session.execute(
                stmt.order_by(InboxItem.priority_score.desc(), InboxItem.created_at.desc()).limit(limit)
            ).scalars()
        )

    def needs_attention(self, owner_id: str, *, threshold: float = 35.0) -> list[InboxItem]:
        """Cards worth interrupting someone for.

        The threshold is what turns "here is everything" into "three things
        need you". FYI cards stay in the inbox but do not count.
        """
        return [
            item
            for item in self.list_items(owner_id)
            if item.priority_score >= threshold
            and item.category not in (InboxCategory.FYI.value, InboxCategory.HANDLED.value)
        ]

    def get(self, owner_id: str, item_id: str) -> InboxItem | None:
        return self.session.execute(
            sa.select(InboxItem).where(InboxItem.owner_id == owner_id, InboxItem.id == item_id)
        ).scalar_one_or_none()

    def resolve(self, owner_id: str, item_id: str, *, actor_id: str | None = None) -> InboxItem:
        item = self._require(owner_id, item_id)
        item.state = InboxItemState.RESOLVED.value
        item.resolved_at = utcnow()
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.INBOX_ITEM_RESOLVED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="inbox_item",
            resource_id=item.id,
            reason="resolved by the owner",
            result="resolved",
        )
        return item

    def dismiss(self, owner_id: str, item_id: str, *, actor_id: str | None = None) -> InboxItem:
        item = self._require(owner_id, item_id)
        item.state = InboxItemState.DISMISSED.value
        item.resolved_at = utcnow()
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.INBOX_ITEM_RESOLVED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="inbox_item",
            resource_id=item.id,
            reason="dismissed by the owner",
            result="dismissed",
        )
        return item

    def snooze(
        self, owner_id: str, item_id: str, until: dt.datetime, *, actor_id: str | None = None
    ) -> InboxItem:
        item = self._require(owner_id, item_id)
        item.state = InboxItemState.SNOOZED.value
        item.snoozed_until = until
        self.session.flush()
        return item

    def attach_proposal(self, owner_id: str, item_id: str, proposal_id: str) -> InboxItem:
        item = self._require(owner_id, item_id)
        item.action_proposal_id = proposal_id
        item.category = InboxCategory.APPROVAL.value
        self.session.flush()
        return item

    def counts_by_category(self, owner_id: str) -> dict[str, int]:
        rows = self.session.execute(
            sa.select(InboxItem.category, sa.func.count())
            .where(
                InboxItem.owner_id == owner_id,
                InboxItem.state == InboxItemState.OPEN.value,
            )
            .group_by(InboxItem.category)
        ).all()
        return {row[0]: int(row[1]) for row in rows}

    def _require(self, owner_id: str, item_id: str) -> InboxItem:
        item = self.get(owner_id, item_id)
        if item is None:
            raise LookupError("inbox item not found")
        return item


__all__ = ["CardDraft", "InboxService"]
