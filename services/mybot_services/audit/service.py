"""The audit log.

Every event answers the questions from the product spec: what happened, when,
why, what requested it, which model produced the recommendation, which
permission allowed it, who approved it and how, which integration executed it,
and what the outcome was.

Integrity is by hash chain.  Each event hashes its own canonical content
together with the previous event's hash, per owner.  Editing or removing a
historical event breaks every hash after it, and :func:`verify_chain` reports
exactly where.  Combined with the database triggers from
``mybot_schemas.db.session``, tampering requires both database write access
*and* the ability to recompute the entire tail -- and even then the sequence
numbers and hashes are visible to the user in the Security Center.

Deliberate constraint: this module offers no update and no delete. There is no
private helper that does it either. The AI has no path to one because one does
not exist.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import sqlalchemy as sa
from mybot_schemas.db.scope import session_system_scope
from mybot_schemas.db.types import new_uuid, utcnow
from mybot_schemas.enums import ActorType, AuditEventType
from mybot_schemas.models import AuditEvent
from mybot_security.crypto import canonical_json, sha256_hex
from mybot_security.logging import current_request_id, get_logger
from mybot_security.redaction import redact
from sqlalchemy.orm import Session

log = get_logger(__name__)

#: Hash of the notional event before the first one.
GENESIS_HASH = "0" * 64


def compute_event_hash(payload: dict, previous_hash: str) -> str:
    """Hash one event's content chained to its predecessor.

    The payload must be exactly the set of fields covered by the chain --
    changing this set changes every hash, so it is treated as a versioned
    format (``v1`` below).
    """
    return sha256_hex(f"mybot-audit-v1|{previous_hash}|{canonical_json(payload)}")


def _chain_payload(event: AuditEvent) -> dict:
    """The canonical, hashed view of an event.

    Includes everything security-relevant.  ``details`` is included too, so an
    attacker cannot rewrite the *reason* for an action while leaving the shape
    intact.
    """
    return {
        "id": event.id,
        "sequence": event.sequence,
        "timestamp": event.timestamp.isoformat(),
        "owner_id": event.owner_id,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "event_type": event.event_type,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "request_id": event.request_id,
        "reason": event.reason,
        "model_used": event.model_used,
        "policy_rule": event.policy_rule,
        "approval_method": event.approval_method,
        "approval_auth_level": event.approval_auth_level,
        "integration": event.integration,
        "result": event.result,
        "details": event.details,
    }


@dataclass
class ChainVerification:
    ok: bool
    checked: int
    first_bad_sequence: int | None = None
    problem: str | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "events_checked": self.checked,
            "first_bad_sequence": self.first_bad_sequence,
            "problem": self.problem,
        }


class AuditService:
    """Append-only audit writer and verifier."""

    def __init__(self, session: Session):
        self.session = session

    # -- writing ---------------------------------------------------------

    def record(
        self,
        owner_id: str,
        event_type: AuditEventType | str,
        *,
        actor_type: ActorType | str = ActorType.SYSTEM,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        reason: str | None = None,
        model_used: str | None = None,
        policy_rule: str | None = None,
        approval_method: str | None = None,
        approval_auth_level: str | None = None,
        integration: str | None = None,
        result: str | None = None,
        details: dict | None = None,
        request_id: str | None = None,
        timestamp: dt.datetime | None = None,
    ) -> AuditEvent:
        """Append one event and return it.

        ``details`` is redacted here rather than at the call site: relying on
        every caller to remember is exactly the failure this prevents.
        """
        # The tail lookup must see all events for this owner regardless of the
        # ambient scope (the writer may be a system job).
        with session_system_scope(self.session, "audit chain append requires reading the owner's tail"):
            last = self.session.execute(
                sa.select(AuditEvent)
                .where(AuditEvent.owner_id == owner_id)
                .order_by(AuditEvent.sequence.desc())
                .limit(1)
            ).scalar_one_or_none()

        previous_hash = last.event_hash if last is not None else GENESIS_HASH
        sequence = (last.sequence + 1) if last is not None else 1

        event = AuditEvent(
            id=new_uuid(),
            owner_id=owner_id,
            sequence=sequence,
            timestamp=timestamp or utcnow(),
            actor_type=str(ActorType(actor_type) if not isinstance(actor_type, str) else actor_type),
            actor_id=actor_id,
            event_type=str(event_type),
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id or current_request_id(),
            reason=reason,
            model_used=model_used,
            policy_rule=policy_rule,
            approval_method=approval_method,
            approval_auth_level=approval_auth_level,
            integration=integration,
            result=result,
            details=redact(details or {}),
            previous_event_hash=previous_hash,
            event_hash="",
        )
        event.event_hash = compute_event_hash(_chain_payload(event), previous_hash)
        self.session.add(event)
        self.session.flush()

        log.info(
            "audit.append",
            event_type=str(event_type),
            sequence=sequence,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
        )
        return event

    # -- reading ---------------------------------------------------------

    def list_events(
        self,
        owner_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        event_type: str | None = None,
        resource_id: str | None = None,
        since: dt.datetime | None = None,
    ) -> list[AuditEvent]:
        stmt = sa.select(AuditEvent).where(AuditEvent.owner_id == owner_id)
        if event_type:
            stmt = stmt.where(AuditEvent.event_type == event_type)
        if resource_id:
            stmt = stmt.where(AuditEvent.resource_id == resource_id)
        if since:
            stmt = stmt.where(AuditEvent.timestamp >= since)
        stmt = stmt.order_by(AuditEvent.sequence.desc()).limit(min(limit, 500)).offset(offset)
        return list(self.session.execute(stmt).scalars().all())

    def count_events(self, owner_id: str) -> int:
        return int(
            self.session.execute(
                sa.select(sa.func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.owner_id == owner_id)
            ).scalar_one()
        )

    # -- integrity -------------------------------------------------------

    def verify_chain(self, owner_id: str) -> ChainVerification:
        """Walk the owner's chain and confirm it is intact.

        Checks three things: the sequence has no gaps, each event's stored hash
        matches a recomputation of its content, and each event's
        ``previous_event_hash`` matches the actual predecessor.
        """
        with session_system_scope(self.session, "audit verification reads a single owner's full chain"):
            events = list(
                self.session.execute(
                    sa.select(AuditEvent)
                    .where(AuditEvent.owner_id == owner_id)
                    .order_by(AuditEvent.sequence.asc())
                )
                .scalars()
                .all()
            )

        previous_hash = GENESIS_HASH
        expected_sequence = 1
        for event in events:
            if event.sequence != expected_sequence:
                return ChainVerification(
                    ok=False,
                    checked=expected_sequence - 1,
                    first_bad_sequence=event.sequence,
                    problem=(
                        f"sequence gap: expected {expected_sequence}, found {event.sequence} "
                        "(an event was removed)"
                    ),
                )
            if event.previous_event_hash != previous_hash:
                return ChainVerification(
                    ok=False,
                    checked=expected_sequence - 1,
                    first_bad_sequence=event.sequence,
                    problem="previous_event_hash does not match the preceding event",
                )
            recomputed = compute_event_hash(_chain_payload(event), previous_hash)
            if recomputed != event.event_hash:
                return ChainVerification(
                    ok=False,
                    checked=expected_sequence - 1,
                    first_bad_sequence=event.sequence,
                    problem="event content does not match its hash (record was modified)",
                )
            previous_hash = event.event_hash
            expected_sequence += 1

        return ChainVerification(ok=True, checked=len(events))


__all__ = ["AuditService", "ChainVerification", "GENESIS_HASH", "compute_event_hash"]
