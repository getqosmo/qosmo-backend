"""The MyBot Core daemon.

Until now the proactive engine only ran when somebody opened the app, which
made "MyBot notices things" quietly untrue — it noticed things *while you were
looking*. This is the process that makes it real: on the Core it runs
continuously in the user's home; in development it is the same code under
`mybot daemon`.

Each tick, per owner:

    sync connectors → proactive scan → run automations → notify → housekeeping

Design points worth stating:

**Isolated per owner.** One owner's failure must not stop the others. Each is
processed in its own transaction, and an exception is logged and stepped over
rather than aborting the tick.

**Failures degrade, they do not escalate.** A connector being unreachable is a
normal condition recorded as coverage, not an error. The next tick tries again.
Nothing retries an *action* — that is the firewall's business and it
deliberately does not.

**Lockdown is respected at the top.** A locked owner is skipped entirely rather
than processed and then refused, so a locked MyBot makes no outbound calls at
all.

**No autonomy is added here.** The daemon runs the same engines the API runs,
through the same firewall. It cannot do anything a user-triggered scan could
not. That is why this file is short.
"""

from __future__ import annotations

import datetime as dt
import signal
import threading
import time
from dataclasses import dataclass, field

import sqlalchemy as sa
from mybot_schemas.config import get_settings
from mybot_schemas.db.scope import session_owner_scope, session_system_scope
from mybot_schemas.db.session import session_scope
from mybot_schemas.db.types import utcnow
from mybot_schemas.models import User
from mybot_security.logging import get_logger, request_context

log = get_logger(__name__)

#: Housekeeping runs on its own slower cadence -- purging read notifications
#: and expiring stale proposals does not need to happen every five minutes.
HOUSEKEEPING_INTERVAL_SECONDS = 3600


@dataclass
class TickResult:
    owners_processed: int = 0
    owners_skipped: int = 0
    cards_created: int = 0
    proposals_created: int = 0
    notifications_created: int = 0
    unavailable: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "owners_processed": self.owners_processed,
            "owners_skipped": self.owners_skipped,
            "cards_created": self.cards_created,
            "proposals_created": self.proposals_created,
            "notifications_created": self.notifications_created,
            "unavailable": self.unavailable,
            "errors": self.errors,
        }


class ProactiveDaemon:
    """Runs the proactive loop until stopped."""

    def __init__(self, *, registry=None, interval_seconds: int | None = None):
        from mybot_integrations.registry import build_default_registry

        settings = get_settings()
        self.settings = settings
        self.registry = registry or build_default_registry(settings.integrations_mode)
        self.interval = interval_seconds or settings.proactive_interval_seconds
        self._stop = threading.Event()
        self._last_housekeeping = 0.0

    # ------------------------------------------------------------------

    def request_stop(self, *_args) -> None:
        log.info("daemon.stop_requested")
        self._stop.set()

    def run_forever(self) -> None:
        """Tick until interrupted.

        Handles SIGTERM and SIGINT so a container stop is graceful: the current
        tick finishes and the process exits rather than being killed mid-write.
        """
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self.request_stop)
            except ValueError:  # pragma: no cover - not on the main thread
                pass

        log.info(
            "daemon.started",
            interval_seconds=self.interval,
            integrations=self.settings.integrations_mode,
        )
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                result = self.tick()
                log.info("daemon.tick", **result.as_dict())
            except Exception:  # noqa: BLE001
                # A tick that dies must not take the daemon with it. The next
                # one will very likely succeed, and a crash-looping assistant
                # is worse than a slow one.
                log.exception("daemon.tick_failed")

            elapsed = time.monotonic() - started
            self._stop.wait(max(1.0, self.interval - elapsed))

        log.info("daemon.stopped")

    # ------------------------------------------------------------------

    def tick(self, *, now: dt.datetime | None = None) -> TickResult:
        """One pass over every owner."""
        now = now or utcnow()
        result = TickResult()

        with session_scope() as session:
            with session_system_scope(session, "daemon enumerates owners to process"):
                owner_ids = [
                    row[0]
                    for row in session.execute(
                        sa.select(User.id).where(User.is_active.is_(True))
                    ).all()
                ]

        for owner_id in owner_ids:
            # One transaction per owner. A failure rolls back that owner only.
            try:
                with session_scope() as session, session_owner_scope(session, owner_id):
                    with request_context(owner_id=owner_id):
                        self._process_owner(session, owner_id, now, result)
                result.owners_processed += 1
            except Exception as exc:  # noqa: BLE001
                log.exception("daemon.owner_failed", owner_hint=owner_id[:8])
                result.errors.append(f"{owner_id[:8]}: {type(exc).__name__}")

        if time.monotonic() - self._last_housekeeping > HOUSEKEEPING_INTERVAL_SECONDS:
            self._housekeeping(owner_ids, result)
            self._last_housekeeping = time.monotonic()

        return result

    # ------------------------------------------------------------------

    def _process_owner(self, session, owner_id: str, now: dt.datetime, result: TickResult) -> None:
        from mybot_services.action_firewall.service import ActionFirewall
        from mybot_services.audit.service import AuditService
        from mybot_services.automations.engine import AutomationEngine
        from mybot_services.inbox.service import InboxService
        from mybot_services.notifications.service import NotificationService
        from mybot_services.policy.service import PolicyService
        from mybot_services.proactive.engine import ProactiveEngine
        from mybot_services.proactive.sync import ConnectorSync

        audit = AuditService(session)
        policy = PolicyService(session, audit)

        # Locked owners are skipped before any outbound call is made.
        state = policy.get_security_state(owner_id)
        if state.locked:
            result.owners_skipped += 1
            log.info("daemon.owner_locked", owner_hint=owner_id[:8])
            return

        sync = ConnectorSync(session, self.registry, audit).sync_all(owner_id, now=now)
        for name, reason in sync.unavailable.items():
            result.unavailable[name] = reason

        scan = ProactiveEngine(session).scan(owner_id, now=now)
        result.cards_created += scan.cards_created

        firewall = ActionFirewall(session, self.registry, policy=policy, audit=audit)
        notifications = NotificationService(session, audit)

        automation_report = AutomationEngine(
            session, firewall, policy=policy, audit=audit, notifications=notifications
        ).run(owner_id, now=now)
        result.proposals_created += automation_report.proposals_created
        result.notifications_created += sum(
            outcome.notifications_created for outcome in automation_report.ran
        )

        # Notify about anything that cleared the bar. The service decides what
        # is worth interrupting for; this just hands it the candidates.
        open_items = InboxService(session, audit).needs_attention(owner_id)
        result.notifications_created += notifications.notify_for_inbox_items(
            owner_id, open_items, now=now
        )

        firewall.expire_stale(owner_id)

    def _housekeeping(self, owner_ids: list[str], result: TickResult) -> None:
        from mybot_services.notifications.service import NotificationService

        for owner_id in owner_ids:
            try:
                with session_scope() as session, session_owner_scope(session, owner_id):
                    NotificationService(session).purge_read(owner_id)
            except Exception:  # noqa: BLE001
                log.exception("daemon.housekeeping_failed", owner_hint=owner_id[:8])


__all__ = ["HOUSEKEEPING_INTERVAL_SECONDS", "ProactiveDaemon", "TickResult"]
