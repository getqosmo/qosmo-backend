"""Connector sync.

Pulls calendar events and email into local storage, classifying as it goes.
Everything landing here is treated as untrusted: bodies are stored, scanned
and flagged, but never interpreted as instructions.

The return value carries availability. If Gmail could not be reached, the
caller must be able to tell the difference between "no unanswered emails" and
"MyBot could not look" -- and say so to the user.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import sqlalchemy as sa
from mybot_integrations.base import IntegrationUnavailable
from mybot_integrations.registry import IntegrationRegistry
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import ActorType, AuditEventType, IntegrationStatus
from mybot_schemas.models import (
    CalendarEvent,
    EgressEvent,
    EmailMessage,
    Entity,
    Integration,
)
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

from ..audit.service import AuditService
from .intel import classify_email

log = get_logger(__name__)


@dataclass
class SyncResult:
    calendar_events: int = 0
    emails: int = 0
    #: Provider -> reason, for anything that could not be reached.
    unavailable: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.unavailable

    def as_dict(self) -> dict:
        return {
            "calendar_events": self.calendar_events,
            "emails": self.emails,
            "unavailable": self.unavailable,
            "ok": self.ok,
        }


class ConnectorSync:
    def __init__(
        self,
        session: Session,
        registry: IntegrationRegistry,
        audit: AuditService | None = None,
    ):
        self.session = session
        self.registry = registry
        self.audit = audit or AuditService(session)

    def _record_egress(
        self,
        owner_id: str,
        *,
        kind: str,
        connector,
        status: str,
        detail: str | None = None,
        records: int = 0,
        latency_ms: int | None = None,
    ) -> None:
        """Log the outbound request, whatever happened to it.

        Written here rather than by a separate reporting path, so a sync cannot
        occur without the ledger knowing. Failures count: a request that timed
        out still left the machine.

        A connector with no ``host`` runs in-process -- the simulated ones --
        and is recorded as having stayed, so the ledger's local count stays
        truthful rather than simply omitting the event.
        """
        host = getattr(connector, "host", None)
        self.session.add(
            EgressEvent(
                owner_id=owner_id,
                kind=kind,
                provider=getattr(connector, "provider", "unknown"),
                destination=host,
                left_machine=bool(host),
                status=status,
                detail=(detail or None) and str(detail)[:500],
                records=records,
                latency_ms=latency_ms,
            )
        )

    def sync_all(
        self,
        owner_id: str,
        *,
        lookback_days: int = 30,
        lookahead_days: int = 60,
        now: dt.datetime | None = None,
    ) -> SyncResult:
        now = now or utcnow()
        result = SyncResult()
        self._sync_calendar(owner_id, now, lookback_days, lookahead_days, result)
        self._sync_email(owner_id, now, lookback_days, result)
        return result

    # -- calendar --------------------------------------------------------

    def _sync_calendar(
        self, owner_id: str, now: dt.datetime, lookback: int, lookahead: int, result: SyncResult
    ) -> None:
        connector = self.registry.calendar()
        if connector is None:
            result.unavailable["calendar"] = "no calendar is connected"
            return
        try:
            events = connector.list_events(
                owner_id,
                now - dt.timedelta(days=lookback),
                now + dt.timedelta(days=lookahead),
            )
        except IntegrationUnavailable as exc:
            result.unavailable["calendar"] = str(exc)
            self._mark_integration(owner_id, connector.provider, "error", str(exc))
            self._record_egress(
                owner_id, kind="connector.calendar", connector=connector,
                status="unavailable", detail=str(exc),
            )
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.calendar_failed")
            result.unavailable["calendar"] = f"unexpected error: {type(exc).__name__}"
            self._record_egress(
                owner_id, kind="connector.calendar", connector=connector,
                status="error", detail=type(exc).__name__,
            )
            return

        for data in events:
            row = self.session.execute(
                sa.select(CalendarEvent).where(
                    CalendarEvent.owner_id == owner_id,
                    CalendarEvent.provider == connector.provider,
                    CalendarEvent.external_id == data.external_id,
                )
            ).scalar_one_or_none()
            if row is None:
                row = CalendarEvent(
                    owner_id=owner_id,
                    provider=connector.provider,
                    external_id=data.external_id,
                )
                self.session.add(row)
            row.calendar_id = data.calendar_id
            row.title = data.title
            row.description = data.description
            row.location = data.location
            row.start_at = data.start_at
            row.end_at = data.end_at
            row.all_day = data.all_day
            row.attendees = list(data.attendees)
            row.organizer = data.organizer
            row.status = data.status
            row.importance = data.importance
            row.cancelled = data.status == "cancelled"
            result.calendar_events += 1

        self.session.flush()
        self._record_egress(
            owner_id, kind="connector.calendar", connector=connector,
            status="ok", records=result.calendar_events,
        )
        self._mark_integration(owner_id, connector.provider, "ok", None, count=result.calendar_events)

    # -- email -----------------------------------------------------------

    def _sync_email(self, owner_id: str, now: dt.datetime, lookback: int, result: SyncResult) -> None:
        connector = self.registry.email()
        if connector is None:
            result.unavailable["email"] = "no mailbox is connected"
            return
        try:
            messages = connector.list_messages(owner_id, now - dt.timedelta(days=lookback), limit=200)
        except IntegrationUnavailable as exc:
            result.unavailable["email"] = str(exc)
            self._mark_integration(owner_id, connector.provider, "error", str(exc))
            self._record_egress(
                owner_id, kind="connector.email", connector=connector,
                status="unavailable", detail=str(exc),
            )
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("sync.email_failed")
            result.unavailable["email"] = f"unexpected error: {type(exc).__name__}"
            self._record_egress(
                owner_id, kind="connector.email", connector=connector,
                status="error", detail=type(exc).__name__,
            )
            return

        known = self._known_contacts(owner_id)

        for data in messages:
            row = self.session.execute(
                sa.select(EmailMessage).where(
                    EmailMessage.owner_id == owner_id,
                    EmailMessage.provider == connector.provider,
                    EmailMessage.external_id == data.external_id,
                )
            ).scalar_one_or_none()
            created = row is None
            if created:
                row = EmailMessage(
                    owner_id=owner_id,
                    provider=connector.provider,
                    external_id=data.external_id,
                )
                self.session.add(row)

            row.thread_id = data.thread_id
            row.from_address = data.from_address
            row.from_name = data.from_name
            row.to_addresses = list(data.to_addresses)
            row.subject = data.subject
            row.snippet = data.snippet or (data.body or "")[:200]
            row.body = data.body
            row.received_at = data.received_at
            row.labels = list(data.labels)
            row.is_read = data.is_read

            # Classification is deterministic and re-run each sync so a fix to
            # the rules improves existing data without a migration.
            analysis = classify_email(
                subject=data.subject,
                body=data.body or "",
                from_address=data.from_address,
                to_addresses=list(data.to_addresses),
                known_contacts=known,
                now=now,
            )
            row.classification_label = analysis.label
            row.classification_confidence = analysis.confidence
            row.requires_reply = analysis.requires_reply
            row.injection_suspected = analysis.injection_suspected
            row.extracted = analysis.as_dict()
            result.emails += 1

        self.session.flush()
        self._record_egress(
            owner_id, kind="connector.email", connector=connector,
            status="ok", records=result.emails,
        )
        self._mark_integration(owner_id, connector.provider, "ok", None, count=result.emails)

    # -- helpers ---------------------------------------------------------

    def _known_contacts(self, owner_id: str) -> set[str]:
        """Email addresses of people already in the Life Graph.

        Being a known contact raises a message's importance -- and, notably, is
        the only place "who matters to this person" comes from. It is derived
        from their own graph, not from an external reputation service.
        """
        rows = self.session.execute(
            sa.select(Entity).where(
                Entity.owner_id == owner_id,
                Entity.entity_type.in_(["Person", "Organization"]),
                Entity.archived.is_(False),
            )
        ).scalars()
        contacts: set[str] = set()
        for entity in rows:
            email = (entity.attributes or {}).get("email")
            if email:
                contacts.add(str(email).lower())
            for extra in (entity.attributes or {}).get("emails", []) or []:
                contacts.add(str(extra).lower())
        return contacts

    def _mark_integration(
        self,
        owner_id: str,
        provider: str,
        status: str,
        error: str | None,
        *,
        count: int | None = None,
    ) -> None:
        row = self.session.execute(
            sa.select(Integration).where(
                Integration.owner_id == owner_id, Integration.provider == provider
            )
        ).scalar_one_or_none()
        if row is None:
            row = Integration(
                owner_id=owner_id,
                provider=provider,
                display_name=provider.replace("_", " ").title(),
                status=(
                    IntegrationStatus.MOCK.value
                    if provider.startswith("mock")
                    else IntegrationStatus.CONNECTED.value
                ),
            )
            self.session.add(row)
        row.last_sync_at = utcnow()
        row.last_sync_status = status
        row.last_error = error
        if error:
            row.status = IntegrationStatus.ERROR.value
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.INTEGRATION_SYNCED,
            actor_type=ActorType.SYSTEM,
            resource_type="integration",
            resource_id=row.id,
            integration=provider,
            result=status,
            details={"records": count, "error": error},
        )


__all__ = ["ConnectorSync", "SyncResult"]
