"""Notifications.

The `notifications` table existed from the first commit and nothing wrote to
it. This is what makes MyBot actually reach out rather than waiting to be
opened.

The design constraint is restraint. A personal assistant that interrupts you
about everything is worse than one that interrupts you about nothing, because
you stop reading it. So:

* **A threshold, not a firehose.** Only cards above a priority score get a
  notification, and FYI never does.
* **Dedupe by source.** The proactive engine runs every few minutes and
  re-derives the same card each time; the same underlying thing produces one
  notification, not one per scan.
* **A quiet window.** Nothing is delivered overnight unless it is genuinely
  critical, because a bill due Friday is not worth waking somebody at 3am.
* **Bounded.** A hard daily cap per owner, so a misconfigured automation or a
  bad sync cannot produce a hundred alerts.

None of this is enforced by asking a model to be tasteful. It is arithmetic.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import ActorType, AuditEventType, InboxCategory, Urgency
from mybot_schemas.models import InboxItem, Notification, User
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

from ..audit.service import AuditService

log = get_logger(__name__)

#: Cards below this score never generate a notification. They still appear in
#: the Life Inbox -- being worth recording is not the same as being worth
#: interrupting someone for.
NOTIFY_THRESHOLD = 58.0

#: Categories that are informational by nature.
NEVER_NOTIFY_CATEGORIES = frozenset({InboxCategory.FYI.value, InboxCategory.HANDLED.value})

#: Local hours during which only CRITICAL gets through.
QUIET_START_HOUR = 22
QUIET_END_HOUR = 7

#: Hard ceiling per owner per rolling day.
DAILY_CAP = 12


class NotificationService:
    def __init__(self, session: Session, audit: AuditService | None = None):
        self.session = session
        self.audit = audit or AuditService(session)

    # ------------------------------------------------------------------

    def notify(
        self,
        owner_id: str,
        *,
        title: str,
        body: str,
        urgency: Urgency = Urgency.LOW,
        channel: str = "in_app",
        inbox_item_id: str | None = None,
        action_proposal_id: str | None = None,
        source: str | None = None,
        now: dt.datetime | None = None,
    ) -> Notification | None:
        """Create a notification, or decline to.

        Returns ``None`` when suppressed. The caller does not need to know why;
        the reason is logged.
        """
        now = now or utcnow()

        dedupe_key = source or (f"inbox:{inbox_item_id}" if inbox_item_id else None)
        if dedupe_key and self._already_notified(owner_id, dedupe_key):
            return None

        if self._in_quiet_hours(owner_id, now) and urgency != Urgency.CRITICAL:
            log.info("notification.deferred_quiet_hours", urgency=urgency.value)
            return None

        if self._daily_count(owner_id, now) >= DAILY_CAP and urgency != Urgency.CRITICAL:
            log.warning("notification.daily_cap_reached", owner_hint=owner_id[:8])
            return None

        notification = Notification(
            owner_id=owner_id,
            title=title,
            body=body,
            channel=channel,
            urgency=urgency.value,
            inbox_item_id=inbox_item_id,
            action_proposal_id=action_proposal_id,
            dedupe_key=dedupe_key,
            delivered_at=now if channel == "in_app" else None,
        )
        self.session.add(notification)
        self.session.flush()
        return notification

    def notify_for_inbox_items(
        self, owner_id: str, items: list[InboxItem], *, now: dt.datetime | None = None
    ) -> int:
        """Notify about the cards that clear the bar. Highest first.

        Ordering matters when the daily cap bites: the owner should hear about
        the registration expiring before the unused subscription.
        """
        created = 0
        for item in sorted(items, key=lambda i: -i.priority_score):
            if item.priority_score < NOTIFY_THRESHOLD:
                continue
            if item.category in NEVER_NOTIFY_CATEGORIES:
                continue
            notification = self.notify(
                owner_id,
                title=item.title,
                body=item.explanation,
                urgency=Urgency(item.urgency),
                inbox_item_id=item.id,
                action_proposal_id=item.action_proposal_id,
                source=(
                    f"source:{item.source_ids[0]}" if item.source_ids else f"inbox:{item.id}"
                ),
                now=now,
            )
            if notification is not None:
                created += 1
        return created

    # ------------------------------------------------------------------

    def list_for(
        self, owner_id: str, *, unread_only: bool = False, limit: int = 50
    ) -> list[Notification]:
        stmt = sa.select(Notification).where(Notification.owner_id == owner_id)
        if unread_only:
            stmt = stmt.where(Notification.read_at.is_(None))
        return list(
            self.session.execute(
                stmt.order_by(Notification.created_at.desc()).limit(limit)
            ).scalars()
        )

    def unread_count(self, owner_id: str) -> int:
        return int(
            self.session.execute(
                sa.select(sa.func.count())
                .select_from(Notification)
                .where(Notification.owner_id == owner_id, Notification.read_at.is_(None))
            ).scalar_one()
        )

    def mark_read(self, owner_id: str, notification_id: str) -> Notification:
        notification = self.session.execute(
            sa.select(Notification).where(
                Notification.owner_id == owner_id, Notification.id == notification_id
            )
        ).scalar_one_or_none()
        if notification is None:
            raise LookupError("notification not found")
        notification.read_at = utcnow()
        self.session.flush()
        return notification

    def mark_all_read(self, owner_id: str) -> int:
        result = self.session.execute(
            sa.update(Notification)
            .where(Notification.owner_id == owner_id, Notification.read_at.is_(None))
            .values(read_at=utcnow())
        )
        self.session.flush()
        return result.rowcount or 0

    def purge_read(self, owner_id: str, *, older_than_days: int = 30) -> int:
        """Delete read notifications past their useful life.

        Retention, not archival: a notification is a delivery mechanism, and
        keeping a permanent record of every ping is the kind of quiet
        accumulation this product is meant to avoid. The audit log already
        holds what actually happened.
        """
        cutoff = utcnow() - dt.timedelta(days=older_than_days)
        result = self.session.execute(
            sa.delete(Notification).where(
                Notification.owner_id == owner_id,
                Notification.read_at.is_not(None),
                Notification.read_at < cutoff,
            )
        )
        count = result.rowcount or 0
        if count:
            self.audit.record(
                owner_id,
                AuditEventType.DATA_DELETED,
                actor_type=ActorType.SYSTEM,
                resource_type="notification",
                reason="expired read notifications purged",
                result="deleted",
                details={"count": count, "older_than_days": older_than_days},
            )
        return count

    # ------------------------------------------------------------------

    def _already_notified(self, owner_id: str, dedupe_key: str) -> bool:
        """Has this underlying thing already produced a notification?

        Keyed on the source record rather than the text, so re-wording a card
        as its deadline approaches does not produce a second ping -- and so an
        automation and a proactive rule that noticed the same renewal produce
        one notification between them, not one each.
        """
        return (
            self.session.execute(
                sa.select(sa.func.count())
                .select_from(Notification)
                .where(
                    Notification.owner_id == owner_id,
                    Notification.dedupe_key == dedupe_key,
                )
            ).scalar_one()
            > 0
        )

    def _daily_count(self, owner_id: str, now: dt.datetime) -> int:
        return int(
            self.session.execute(
                sa.select(sa.func.count())
                .select_from(Notification)
                .where(
                    Notification.owner_id == owner_id,
                    Notification.created_at >= now - dt.timedelta(days=1),
                )
            ).scalar_one()
        )

    def _in_quiet_hours(self, owner_id: str, now: dt.datetime) -> bool:
        """Quiet hours in the owner's own timezone.

        Falls back to UTC if the zone is unknown rather than guessing, which
        would risk waking somebody at 3am to be helpful.
        """
        user = self.session.get(User, owner_id)
        local = now
        if user is not None and user.timezone:
            try:
                from zoneinfo import ZoneInfo

                local = now.astimezone(ZoneInfo(user.timezone))
            except Exception:  # noqa: BLE001 - unknown zone, stay on UTC
                pass
        hour = local.hour
        return hour >= QUIET_START_HOUR or hour < QUIET_END_HOUR


__all__ = [
    "DAILY_CAP",
    "NEVER_NOTIFY_CATEGORIES",
    "NOTIFY_THRESHOLD",
    "NotificationService",
    "QUIET_END_HOUR",
    "QUIET_START_HOUR",
]
