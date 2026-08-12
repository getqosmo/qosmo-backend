"""Automations, notifications and the proactive daemon.

The security question for automations is simple and absolute: can a standing
instruction do something the owner did not permit? These tests attack that from
several directions.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from mybot_schemas.enums import ActionStatus, ActorType, Urgency
from mybot_schemas.models import ActionProposal, AutomationRule


def _automation(owner_id: str, **kwargs) -> AutomationRule:
    return AutomationRule(
        owner_id=owner_id,
        name=kwargs.pop("name", "Test automation"),
        trigger_type=kwargs.pop("trigger_type", "obligation.due_within"),
        trigger_config=kwargs.pop("trigger_config", {"days_before": 7}),
        enabled=True,
        created_by="user:test",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------


def test_automation_cannot_execute_a_medium_risk_action(services, db, as_alice, now, registry):
    """An automation proposes. It does not act."""
    from mybot_integrations.base import CalendarEventData
    from mybot_services.automations.engine import AutomationEngine

    registry.calendar().seed(
        as_alice,
        [
            CalendarEventData(
                external_id="evt-1",
                title="Dentist",
                start_at=now + dt.timedelta(days=1),
                end_at=now + dt.timedelta(days=1, hours=1),
            )
        ],
    )
    services.sync.sync_all(as_alice, now=now)

    db.add(
        _automation(
            as_alice,
            name="Auto-move appointments",
            trigger_type="obligation.due_within",
            action_type="calendar.reschedule",
            action_params={
                "event_id": "evt-1",
                "new_start": (now + dt.timedelta(days=3)).isoformat(),
                "new_end": (now + dt.timedelta(days=3, hours=1)).isoformat(),
            },
        )
    )
    services.obligations.create(
        as_alice, title="Something due", due_at=now + dt.timedelta(days=2)
    )
    db.flush()

    report = AutomationEngine(db, services.firewall).run(as_alice, now=now)
    assert report.proposals_created == 1

    proposal = db.execute(
        sa.select(ActionProposal).where(ActionProposal.owner_id == as_alice)
    ).scalar_one()
    assert proposal.status == ActionStatus.PENDING_APPROVAL.value
    assert proposal.executed_at is None
    assert proposal.requested_by_type == ActorType.AUTOMATION.value


def test_automation_cannot_reach_a_high_risk_action(services, db, as_alice, now, grant):
    """Even with the most permissive standing grant a human could write."""
    from mybot_services.automations.engine import AutomationEngine

    grant(
        as_alice,
        "utilities.pay",
        max_amount=10_000.0,
        allowed_recipients=["*"],
        requires_confirmation=False,
        allow_automatic=True,
    )
    db.add(
        _automation(
            as_alice,
            name="Auto-pay everything",
            action_type="utilities.pay",
            action_params={"payee": "Anyone", "amount": 500.0, "account_ref": "cred:bank"},
        )
    )
    services.obligations.create(as_alice, title="A bill", due_at=now + dt.timedelta(days=2))
    db.flush()

    AutomationEngine(db, services.firewall).run(as_alice, now=now)

    proposals = db.execute(
        sa.select(ActionProposal).where(ActionProposal.owner_id == as_alice)
    ).scalars().all()
    for proposal in proposals:
        assert proposal.executed_at is None
        assert proposal.requires_approval is True
        assert proposal.required_auth_level in ("STRONG", "PHYSICAL")


def test_lockdown_stops_automations_before_they_evaluate(services, db, as_alice, now):
    from mybot_services.automations.engine import AutomationEngine

    db.add(_automation(as_alice))
    services.obligations.create(as_alice, title="Due soon", due_at=now + dt.timedelta(days=1))
    db.flush()

    services.security.lock(as_alice, actor_id="user:alice", reason="test")
    report = AutomationEngine(db, services.firewall).run(as_alice, now=now)

    assert report.disabled_by_lockdown is True
    assert report.ran == []
    assert report.proposals_created == 0


def test_unknown_trigger_is_skipped_not_guessed(services, db, as_alice, now):
    from mybot_services.automations.engine import AutomationEngine

    db.add(_automation(as_alice, trigger_type="whenever.it.seems.important"))
    db.flush()

    report = AutomationEngine(db, services.firewall).run(as_alice, now=now)
    assert report.ran[0].skipped_reason is not None
    assert report.proposals_created == 0


def test_a_refused_action_is_recorded_not_swallowed(services, db, as_alice, now):
    """The owner should be able to see their automation asking for something
    they have not permitted."""
    from mybot_services.automations.engine import AutomationEngine

    db.add(
        _automation(
            as_alice,
            action_type="utilities.pay",
            action_params={"payee": "X", "amount": 10.0, "account_ref": "r"},
        )
    )
    services.obligations.create(as_alice, title="A bill", due_at=now + dt.timedelta(days=2))
    db.flush()

    report = AutomationEngine(db, services.firewall).run(as_alice, now=now)
    assert report.proposals_created == 0
    assert report.ran[0].errors, "a refusal must be surfaced"


def test_automations_are_owner_scoped(services, db, alice, bob, now):
    from mybot_schemas.db.scope import session_owner_scope
    from mybot_services.automations.engine import AutomationEngine

    with session_owner_scope(db, alice.id):
        db.add(_automation(alice.id, name="Alice's rule"))
        db.flush()

    with session_owner_scope(db, bob.id):
        report = AutomationEngine(db, services.firewall).run(bob.id, now=now)
        assert report.ran == []


def test_api_rejects_an_unknown_trigger(api, registered):
    account = registered("auto1@example.com", "Auto")
    response = api.post(
        "/api/v1/automations",
        json={"name": "Bad", "trigger_type": "arbitrary.sql; DROP TABLE users"},
        headers=account["headers"],
    )
    assert response.status_code == 400


def test_api_rejects_an_unregistered_action(api, registered):
    account = registered("auto2@example.com", "Auto")
    response = api.post(
        "/api/v1/automations",
        json={
            "name": "Bad",
            "trigger_type": "obligation.due_within",
            "action_type": "shell.execute",
        },
        headers=account["headers"],
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def _daytime(now: dt.datetime) -> dt.datetime:
    """A timestamp inside the notification window, whatever 'now' is."""
    return now.replace(hour=14, minute=0, second=0, microsecond=0)


def test_low_priority_cards_do_not_interrupt(services, db, as_alice, now):
    from mybot_schemas.enums import InboxCategory
    from mybot_services.inbox.service import CardDraft
    from mybot_services.notifications.service import NotificationService

    item = services.inbox.upsert(
        as_alice,
        CardDraft(
            dedupe_key="quiet:1",
            rule_id="test",
            category=InboxCategory.FYI,
            title="Something minor",
            explanation="Barely worth mentioning.",
        ),
        now=now,
    )
    created = NotificationService(db).notify_for_inbox_items(
        as_alice, [item], now=_daytime(now)
    )
    assert created == 0


def test_the_same_card_notifies_once(services, db, as_alice, now):
    """The scan runs every few minutes; the ping happens once."""
    from mybot_schemas.enums import InboxCategory
    from mybot_services.inbox.service import CardDraft
    from mybot_services.notifications.service import NotificationService

    draft = CardDraft(
        dedupe_key="loud:1",
        rule_id="test",
        category=InboxCategory.URGENT,
        title="Registration expires",
        explanation="Four days away.",
        due_at=now + dt.timedelta(days=1),
        importance=0.9,
    )
    notifications = NotificationService(db)
    daytime = _daytime(now)

    total = 0
    for _ in range(5):
        item = services.inbox.upsert(as_alice, draft, now=now)
        total += notifications.notify_for_inbox_items(as_alice, [item], now=daytime)

    assert total == 1
    assert notifications.unread_count(as_alice) == 1


def test_quiet_hours_defer_everything_except_critical(services, db, as_alice, now):
    from mybot_services.notifications.service import NotificationService

    notifications = NotificationService(db)
    night = now.replace(hour=3, minute=0, second=0, microsecond=0)

    assert (
        notifications.notify(
            as_alice, title="Bill", body="Due Friday.", urgency=Urgency.HIGH, now=night
        )
        is None
    )
    assert (
        notifications.notify(
            as_alice,
            title="Security",
            body="MyBot was locked from a new device.",
            urgency=Urgency.CRITICAL,
            now=night,
        )
        is not None
    )


def test_daily_cap_bounds_the_noise(services, db, as_alice, now):
    from mybot_services.notifications.service import DAILY_CAP, NotificationService

    notifications = NotificationService(db)
    daytime = _daytime(now)
    created = sum(
        1
        for index in range(DAILY_CAP + 10)
        if notifications.notify(
            as_alice, title=f"Thing {index}", body="...", urgency=Urgency.MEDIUM, now=daytime
        )
        is not None
    )
    assert created == DAILY_CAP


def test_notifications_are_owner_scoped(api, registered):
    alice = registered("notif-a@example.com", "Alice")
    bob = registered("notif-b@example.com", "Bob")
    assert api.get("/api/v1/notifications", headers=alice["headers"]).json()["items"] == []
    assert api.get("/api/v1/notifications", headers=bob["headers"]).json()["items"] == []


def test_purging_read_notifications_is_audited(services, db, as_alice, now):
    from mybot_schemas.db.types import utcnow
    from mybot_services.notifications.service import NotificationService

    notifications = NotificationService(db, services.audit)
    created = notifications.notify(
        as_alice, title="Old", body="...", urgency=Urgency.MEDIUM, now=_daytime(now)
    )
    assert created is not None
    created.read_at = utcnow() - dt.timedelta(days=60)
    db.flush()

    assert notifications.purge_read(as_alice) == 1
    assert services.audit.list_events(as_alice, event_type="data.deleted")


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


def test_daemon_tick_processes_owners_and_skips_locked(engine, db, alice, bob, registry, now):
    """A locked owner is skipped before any outbound call."""
    from mybot_core.daemon import ProactiveDaemon
    from mybot_schemas.db.scope import session_owner_scope
    from mybot_services.audit.service import AuditService
    from mybot_services.policy.service import PolicyService
    from mybot_services.security_center.service import SecurityCenterService

    with session_owner_scope(db, bob.id):
        audit = AuditService(db)
        SecurityCenterService(db, policy=PolicyService(db, audit), audit=audit).lock(
            bob.id, actor_id="user:bob", reason="test"
        )
    db.commit()

    result = ProactiveDaemon(registry=registry, interval_seconds=1).tick(now=now)
    assert result.owners_skipped >= 1
    assert result.owners_processed >= 1
    assert result.errors == []


def test_daemon_survives_one_owner_failing(engine, db, alice, bob, registry, now, monkeypatch):
    """One owner's failure must not stop the tick."""
    from mybot_core.daemon import ProactiveDaemon
    from mybot_services.proactive import engine as proactive_engine

    calls = {"n": 0}
    original = proactive_engine.ProactiveEngine.scan

    def flaky(self, owner_id, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated failure for one owner")
        return original(self, owner_id, **kwargs)

    monkeypatch.setattr(proactive_engine.ProactiveEngine, "scan", flaky)
    db.commit()

    result = ProactiveDaemon(registry=registry, interval_seconds=1).tick(now=now)
    assert len(result.errors) == 1
    assert result.owners_processed >= 1


def test_daemon_adds_no_authority(engine, db, alice, registry, now, grant):
    """The daemon runs the same engines through the same firewall.

    Asserted by giving it the most permissive possible setup and confirming
    nothing executes.
    """
    import sqlalchemy as sa
    from mybot_core.daemon import ProactiveDaemon
    from mybot_schemas.db.scope import session_owner_scope
    from mybot_services.obligations.service import ObligationService

    with session_owner_scope(db, alice.id):
        grant(
            alice.id,
            "utilities.pay",
            max_amount=100_000.0,
            allowed_recipients=["*"],
            requires_confirmation=False,
            allow_automatic=True,
        )
        db.add(
            _automation(
                alice.id,
                action_type="utilities.pay",
                action_params={"payee": "X", "amount": 50.0, "account_ref": "r"},
            )
        )
        ObligationService(db).create(
            alice.id, title="A bill", due_at=now + dt.timedelta(days=2)
        )
    db.commit()

    ProactiveDaemon(registry=registry, interval_seconds=1).tick(now=now)

    with session_owner_scope(db, alice.id):
        db.expire_all()
        executed = db.execute(
            sa.select(ActionProposal).where(
                ActionProposal.owner_id == alice.id,
                ActionProposal.executed_at.is_not(None),
            )
        ).scalars().all()
    assert executed == [], "the daemon must not execute anything on its own"
