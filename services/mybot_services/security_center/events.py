"""Durable recording of security events.

## The bug this exists for

Security events were written on the caller's session. That is fine on a success
path and wrong on every failure path — and failure paths are where the events
that matter live:

* a non-human actor attempting to create a permission rule (Rule 2);
* an approval replay;
* a policy denial on content derived from an untrusted source;
* an account-connection callback that did not match a live request.

Each of those records an event and then raises. The exception propagates to the
request boundary, the session rolls back, and the record of the attempt is
destroyed along with the work it was refusing. The system was reliably keeping
evidence of the things that went *right*.

## The fix

Security events are written on their own short-lived session and committed
immediately, so they survive whatever happens to the transaction that produced
them. They are a log of attempts, not part of the unit of work being attempted,
and coupling their durability to the success of the thing they are recording is
exactly backwards.

Two safeguards, because a logging path must never become a failure path:

**It falls back rather than failing.** If the independent write cannot happen —
SQLite write contention is the realistic case, since the caller may be holding a
write transaction — the event is written on the caller's session instead. That
is the old behaviour, which is worse but not nothing.

**It never raises.** A security event that cannot be recorded at all is logged
and swallowed. Turning "we could not write the log line" into "your request
failed" would let anybody who can cause a write error cause an outage.

Note this is deliberately *not* how the audit chain works. ``AuditEvent`` is
hash-chained and must be written in sequence inside the transaction it
describes; writing it out of band would break the chain. Security events have no
chain, which is what makes this safe.
"""

from __future__ import annotations

from mybot_schemas.enums import SecurityEventType
from mybot_schemas.models import SecurityEvent
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

log = get_logger(__name__)


def record_security_event(
    session: Session,
    owner_id: str,
    event_type: SecurityEventType,
    summary: str,
    *,
    severity: str = "info",
    details: dict | None = None,
) -> SecurityEvent | None:
    """Record an attempt, durably.

    Returns the row written on the caller's session when the fallback path was
    used, and ``None`` when it was committed independently — callers should not
    depend on the return value, which is why every call site ignores it.
    """
    payload = {
        "owner_id": owner_id,
        "event_type": event_type.value,
        "severity": severity,
        "summary": summary,
        "details": details or {},
    }

    if _write_independently(payload):
        return None

    # Fallback: the caller's session. Worse -- it dies if they roll back -- but
    # better than losing the event entirely.
    try:
        row = SecurityEvent(**payload)
        session.add(row)
        session.flush()
        return row
    except Exception as exc:  # noqa: BLE001
        log.error(
            "security_event.unrecorded",
            event_type=event_type.value,
            severity=severity,
            error=type(exc).__name__,
        )
        return None


def _write_independently(payload: dict) -> bool:
    """Commit the event on its own connection.

    Uses the system scope: this is MyBot recording something about an owner
    rather than an owner reading their own data, and the write happens on a
    session that has no owner bound to it.
    """
    try:
        from mybot_schemas.db.scope import session_system_scope
        from mybot_schemas.db.session import get_session_factory

        factory = get_session_factory()
        with factory() as writer:
            with session_system_scope(
                writer, "security events are recorded outside the failing transaction"
            ):
                writer.add(SecurityEvent(**payload))
                writer.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        # Realistically SQLite write contention while the caller holds a write
        # transaction. Fall back rather than lose it.
        log.warning("security_event.independent_write_failed", error=type(exc).__name__)
        return False


__all__ = ["record_security_event"]
