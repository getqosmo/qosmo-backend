"""Lockdown, approval replay, expiry and parameter binding.

These cover the window between "a human said yes" and "the effect happened",
which is where the interesting attacks live.
"""

from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import ActionStatus, ActorType, AuthLevel
from mybot_schemas.models import ActionApproval, AutomationRule
from mybot_services.action_firewall.service import ActionRejected, ProposalRequest
from mybot_services.security_center.service import LockdownError


def _calendar_proposal(services, owner_id, event_id="evt-1"):
    return services.firewall.propose(
        ProposalRequest(
            owner_id=owner_id,
            action_type="calendar.reschedule",
            params={
                "event_id": event_id,
                "new_start": "2030-01-01T10:00:00+00:00",
                "new_end": "2030-01-01T11:00:00+00:00",
            },
            actor_type=ActorType.USER,
            reason="test",
        )
    )


# ---------------------------------------------------------------------------
# Lockdown
# ---------------------------------------------------------------------------


def test_lockdown_blocks_new_external_actions(services, as_alice):
    services.security.lock(as_alice, actor_id="user:alice", reason="lost my phone")
    with pytest.raises(ActionRejected) as exc:
        _calendar_proposal(services, as_alice)
    assert "locked" in str(exc.value).lower()


def test_lockdown_permits_internal_actions(services, as_alice):
    """Locking down stops MyBot reaching outside; it does not brick the app."""
    services.security.lock(as_alice, actor_id="user:alice")
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="obligation.create",
            params={"title": "Renew passport", "due_date": "2030-01-01T00:00:00+00:00"},
            actor_type=ActorType.USER,
        )
    )
    assert proposal.status != ActionStatus.BLOCKED.value


def test_lockdown_invalidates_pending_approvals(services, as_alice, db):
    proposal = _calendar_proposal(services, as_alice)
    assert proposal.status == ActionStatus.PENDING_APPROVAL.value

    services.security.lock(as_alice, actor_id="user:alice", reason="panic")
    db.refresh(proposal)
    assert proposal.status == ActionStatus.BLOCKED.value

    with pytest.raises(ActionRejected):
        services.firewall.approve(
            as_alice, proposal.id, approver_user_id=as_alice, auth_level=AuthLevel.BASIC
        )


def test_lockdown_disables_automations(services, as_alice, db):
    db.add(
        AutomationRule(
            owner_id=as_alice,
            name="Nightly tidy",
            trigger_type="schedule",
            enabled=True,
        )
    )
    db.flush()
    result = services.security.lock(as_alice, actor_id="user:alice")
    assert result.automations_disabled == 1
    assert services.policy.get_security_state(as_alice).automations_enabled is False


def test_unlock_requires_strong_auth(services, as_alice):
    services.security.lock(as_alice, actor_id="user:alice")
    with pytest.raises(LockdownError):
        services.security.unlock(as_alice, actor_id="user:alice", auth_level=AuthLevel.BASIC)
    # STRONG works.
    result = services.security.unlock(
        as_alice, actor_id="user:alice", auth_level=AuthLevel.STRONG
    )
    assert result.locked is False


def test_locking_is_cheaper_than_unlocking(services, as_alice):
    """Asymmetry check: panic must never be gated behind a second factor."""
    result = services.security.lock(as_alice, actor_id="user:alice")
    assert result.locked is True
    with pytest.raises(LockdownError):
        services.security.unlock(as_alice, actor_id="user:alice", auth_level=AuthLevel.BASIC)


def test_unlock_leaves_automations_off_by_default(services, as_alice):
    services.security.lock(as_alice, actor_id="user:alice")
    services.security.unlock(as_alice, actor_id="user:alice", auth_level=AuthLevel.STRONG)
    assert services.policy.get_security_state(as_alice).automations_enabled is False


def test_lockdown_bumps_the_approval_epoch(services, as_alice):
    before = services.policy.get_security_state(as_alice).approval_epoch
    services.security.lock(as_alice, actor_id="user:alice")
    after = services.policy.get_security_state(as_alice).approval_epoch
    assert after == before + 1


def test_api_lockdown_flow(api, registered, elevate):
    account = registered("lock@example.com", "Lock Tester")

    locked = api.post(
        "/api/v1/security/lockdown", json={"reason": "testing"}, headers=account["headers"]
    )
    assert locked.status_code == 200
    assert locked.json()["locked"] is True

    blocked = api.post(
        "/api/v1/actions",
        json={
            "action_type": "calendar.create",
            "params": {
                "title": "x",
                "start": "2030-01-01T10:00:00+00:00",
                "end": "2030-01-01T11:00:00+00:00",
            },
        },
        headers=account["headers"],
    )
    assert blocked.status_code == 403

    # Basic auth cannot unlock.
    assert (
        api.post("/api/v1/security/unlock", json={}, headers=account["headers"]).status_code == 403
    )

    elevate(account)
    unlocked = api.post("/api/v1/security/unlock", json={}, headers=account["headers"])
    assert unlocked.status_code == 200
    assert unlocked.json()["locked"] is False


# ---------------------------------------------------------------------------
# Approvals: replay, expiry, binding
# ---------------------------------------------------------------------------


def test_approval_cannot_be_used_twice(services, as_alice):
    proposal = _calendar_proposal(services, as_alice)
    services.firewall.approve(
        as_alice, proposal.id, approver_user_id=as_alice, auth_level=AuthLevel.BASIC
    )
    with pytest.raises(ActionRejected) as exc:
        services.firewall.approve(
            as_alice, proposal.id, approver_user_id=as_alice, auth_level=AuthLevel.BASIC
        )
    assert "no longer be approved" in str(exc.value)


def test_expired_proposal_cannot_be_approved(services, as_alice, db):
    proposal = _calendar_proposal(services, as_alice)
    proposal.expires_at = utcnow() - dt.timedelta(minutes=1)
    db.flush()

    with pytest.raises(ActionRejected) as exc:
        services.firewall.approve(
            as_alice, proposal.id, approver_user_id=as_alice, auth_level=AuthLevel.BASIC
        )
    assert "expired" in str(exc.value).lower()
    db.refresh(proposal)
    assert proposal.status == ActionStatus.EXPIRED.value


def test_parameters_cannot_change_between_approval_and_execution(services, as_alice, db):
    """The bait-and-switch case.

    An approval is bound to a hash of exactly what the user saw. Editing the
    proposal afterwards voids it.
    """
    proposal = _calendar_proposal(services, as_alice)

    approval = ActionApproval(
        owner_id=as_alice,
        proposal_id=proposal.id,
        decision="approve",
        method="in_app",
        auth_level=AuthLevel.BASIC.value,
        approver_user_id=as_alice,
        params_hash="hash-of-what-the-user-actually-saw",
        expires_at=utcnow() + dt.timedelta(minutes=10),
    )
    db.add(approval)
    db.flush()

    with pytest.raises(ActionRejected) as exc:
        services.firewall._execute(proposal, approval=approval)
    assert "changed after you approved" in str(exc.value)


def test_consumed_approval_is_rejected_on_reuse(services, as_alice, db):
    from mybot_services.action_firewall.service import params_fingerprint

    proposal = _calendar_proposal(services, as_alice)
    approval = ActionApproval(
        owner_id=as_alice,
        proposal_id=proposal.id,
        decision="approve",
        method="in_app",
        auth_level=AuthLevel.BASIC.value,
        approver_user_id=as_alice,
        params_hash=params_fingerprint(proposal.action_type, proposal.params),
        expires_at=utcnow() + dt.timedelta(minutes=10),
        consumed_at=utcnow(),
    )
    db.add(approval)
    db.flush()

    with pytest.raises(ActionRejected) as exc:
        services.firewall._execute(proposal, approval=approval)
    assert "already been used" in str(exc.value)


def test_revoking_a_permission_blocks_a_pending_high_risk_action(services, as_alice, grant):
    """Policy is re-evaluated at approval time, not just at proposal time."""
    rule = grant(
        as_alice,
        "utilities.pay",
        max_amount=600.0,
        allowed_recipients=["PSE&G"],
        requires_strong_auth=True,
    )
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="utilities.pay",
            params={"payee": "PSE&G", "amount": 100.0, "account_ref": "cred:bank"},
            actor_type=ActorType.USER,
        )
    )
    assert proposal.status == ActionStatus.PENDING_APPROVAL.value

    services.policy.revoke_rule(
        as_alice, rule.id, actor_type=ActorType.USER, actor_id="user:alice"
    )

    with pytest.raises(ActionRejected) as exc:
        services.firewall.approve(
            as_alice, proposal.id, approver_user_id=as_alice, auth_level=AuthLevel.STRONG
        )
    assert "no longer permitted" in str(exc.value).lower()


def test_duplicate_submission_uses_one_idempotency_key(services, as_alice, db):
    """Two proposals with the same key cannot both exist."""
    key = "same-key-twice"
    services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="calendar.create",
            params={
                "title": "Standup",
                "start": "2030-01-01T10:00:00+00:00",
                "end": "2030-01-01T11:00:00+00:00",
            },
            actor_type=ActorType.USER,
            idempotency_key=key,
        )
    )
    with pytest.raises(Exception):  # noqa: B017 - unique constraint, dialect specific
        services.firewall.propose(
            ProposalRequest(
                owner_id=as_alice,
                action_type="calendar.create",
                params={
                    "title": "Standup again",
                    "start": "2030-01-01T10:00:00+00:00",
                    "end": "2030-01-01T11:00:00+00:00",
                },
                actor_type=ActorType.USER,
                idempotency_key=key,
            )
        )
    db.rollback()


def test_adapter_replay_returns_the_first_result(services, as_alice, registry):
    """The mock adapter must not repeat an effect for the same key."""
    from mybot_integrations.base import ExecutionContext

    adapter = registry.adapter_for("calendar.create")
    ctx = ExecutionContext(
        owner_id=as_alice,
        action_type="calendar.create",
        params={
            "title": "Once",
            "start": "2030-01-01T10:00:00+00:00",
            "end": "2030-01-01T11:00:00+00:00",
        },
        idempotency_key="idem-1",
        proposal_id="p1",
    )
    first = adapter.execute(ctx)
    second = adapter.execute(ctx)
    assert first.external_ref == second.external_ref
    assert first is second


def test_ambiguous_outcome_becomes_unknown_not_success(services, as_alice, registry, db):
    """Never claim success MyBot did not observe."""
    from mybot_integrations.adapters.mock import FlakyAdapter

    registry._adapters.insert(0, FlakyAdapter())
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="calendar.create",
            params={
                "title": "Ambiguous",
                "start": "2030-01-01T10:00:00+00:00",
                "end": "2030-01-01T11:00:00+00:00",
            },
            actor_type=ActorType.USER,
        )
    )
    result = services.firewall.approve(
        as_alice, proposal.id, approver_user_id=as_alice, auth_level=AuthLevel.BASIC
    )
    assert result.status == ActionStatus.UNKNOWN.value
    assert result.execution_outcome == "unknown"
    assert "not retry" in result.execution_result["message"].lower()

    # And it is surfaced as a security event for investigation.
    from mybot_schemas.models import SecurityEvent

    events = db.execute(
        sa.select(SecurityEvent).where(SecurityEvent.owner_id == as_alice)
    ).scalars().all()
    assert any("unknown" in e.summary.lower() for e in events)


def test_payments_never_report_success(services, as_alice, grant):
    """The payments adapter is honest about not existing."""
    grant(
        as_alice,
        "utilities.pay",
        max_amount=600.0,
        allowed_recipients=["PSE&G"],
        requires_strong_auth=True,
    )
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="utilities.pay",
            params={"payee": "PSE&G", "amount": 100.0, "account_ref": "cred:bank"},
            actor_type=ActorType.USER,
        )
    )
    result = services.firewall.approve(
        as_alice, proposal.id, approver_user_id=as_alice, auth_level=AuthLevel.STRONG
    )
    assert result.status == ActionStatus.FAILED.value
    assert result.execution_outcome != "confirmed"
    assert "cannot move money" in result.execution_result["message"]


def test_rejected_action_is_never_executed(services, as_alice, db):
    proposal = _calendar_proposal(services, as_alice)
    services.firewall.reject(as_alice, proposal.id, approver_user_id=as_alice)
    db.refresh(proposal)
    assert proposal.status == ActionStatus.REJECTED.value
    assert proposal.executed_at is None
    assert proposal.execution_outcome is None


def test_rejection_needs_no_elevation(api, registered):
    """Saying no must always be as easy as possible."""
    account = registered("reject@example.com", "Rejecter")
    created = api.post(
        "/api/v1/actions",
        json={
            "action_type": "calendar.create",
            "params": {
                "title": "x",
                "start": "2030-01-01T10:00:00+00:00",
                "end": "2030-01-01T11:00:00+00:00",
            },
        },
        headers=account["headers"],
    )
    action_id = created.json()["id"]
    response = api.post(
        f"/api/v1/actions/{action_id}/reject", json={}, headers=account["headers"]
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"


def test_unauthenticated_requests_are_refused(api):
    protected_gets = [
        "/api/v1/today",
        "/api/v1/inbox",
        "/api/v1/brief",
        "/api/v1/worry",
        "/api/v1/entities",
        "/api/v1/memory",
        "/api/v1/obligations",
        "/api/v1/actions",
        "/api/v1/audit",
        "/api/v1/audit/verify",
        "/api/v1/security",
        "/api/v1/security/permissions",
        "/api/v1/integrations",
        "/api/v1/documents",
        "/api/v1/account/export",
        "/api/v1/auth/me",
    ]
    for path in protected_gets:
        assert api.get(path).status_code == 401, f"GET {path} was not protected"

    protected_posts = [
        ("/api/v1/chat", {"message": "hello"}),
        ("/api/v1/security/lockdown", {}),
        ("/api/v1/security/unlock", {}),
        ("/api/v1/security/permissions", {"action_type": "email.send"}),
        ("/api/v1/actions", {"action_type": "calendar.create", "params": {}}),
        ("/api/v1/account/data/delete", {"confirm": "DELETE MY DATA"}),
    ]
    for path, body in protected_posts:
        assert api.post(path, json=body).status_code == 401, f"POST {path} was not protected"


def test_garbage_and_expired_tokens_are_refused(api, registered, db):
    assert api.get("/api/v1/today", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    assert api.get("/api/v1/today", headers={"Authorization": "notbearer x"}).status_code == 401

    account = registered("expiry@example.com", "Expiry")
    assert api.get("/api/v1/auth/me", headers=account["headers"]).status_code == 200

    # Expire the session server-side; the token is now worthless.
    from mybot_schemas.db.scope import session_system_scope
    from mybot_schemas.db.session import get_session_factory
    from mybot_schemas.models import AuthSession

    session = get_session_factory()()
    with session_system_scope(session, "test expires a session"):
        session.execute(
            sa.update(AuthSession)
            .where(AuthSession.owner_id == account["user_id"])
            .values(expires_at=utcnow() - dt.timedelta(seconds=1))
        )
        session.commit()
    session.close()

    assert api.get("/api/v1/auth/me", headers=account["headers"]).status_code == 401


def test_logout_revokes_the_session(api, registered):
    account = registered("logout@example.com", "Logout")
    assert api.post("/api/v1/auth/logout", headers=account["headers"]).status_code == 200
    assert api.get("/api/v1/auth/me", headers=account["headers"]).status_code == 401


def test_strong_elevation_expires(api, registered, elevate, db):
    """A STRONG elevation must not persist on an unattended device."""
    account = registered("elev@example.com", "Elevated")
    elevate(account)
    assert api.get("/api/v1/auth/me", headers=account["headers"]).json()["auth_level"] == "STRONG"

    from mybot_schemas.db.scope import session_system_scope
    from mybot_schemas.db.session import get_session_factory
    from mybot_schemas.models import AuthSession

    session = get_session_factory()()
    with session_system_scope(session, "test ages an elevation"):
        session.execute(
            sa.update(AuthSession)
            .where(AuthSession.owner_id == account["user_id"])
            .values(elevated_until=utcnow() - dt.timedelta(seconds=1))
        )
        session.commit()
    session.close()

    assert api.get("/api/v1/auth/me", headers=account["headers"]).json()["auth_level"] == "BASIC"
