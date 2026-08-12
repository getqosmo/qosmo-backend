"""The five critical security rules, asserted directly.

Each test names the rule it defends. If one of these fails, a foundational
promise of the product is broken and the build should not ship.
"""

from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa
from mybot_schemas.actions import ACTION_REGISTRY, AGENT_PROPOSABLE, UNTRUSTED_FORBIDDEN
from mybot_schemas.enums import ActionStatus, ActorType, AuthLevel, PolicyOutcome, RiskLevel
from mybot_schemas.models import PermissionRule
from mybot_services.action_firewall.service import ActionRejected, ProposalRequest
from mybot_services.policy.service import PermissionDenied

# ===========================================================================
# RULE 1 — AI never holds master keys
# ===========================================================================


def test_rule1_llm_package_cannot_reach_the_vault():
    """The reasoning layer has no import path to key material.

    Enforced by dependency direction: if ``mybot_llm`` ever imports the Vault,
    this fails. That is a stronger guarantee than a policy document, because it
    breaks the build rather than the trust model.
    """
    import pkgutil

    import mybot_llm

    offenders = []
    for module_info in pkgutil.walk_packages(mybot_llm.__path__, "mybot_llm."):
        source = _module_source(module_info.name)
        if "mybot_security.vault" in source or "from mybot_security import" in source and "Vault" in source:
            offenders.append(module_info.name)
    assert offenders == [], f"LLM modules must not import the Vault: {offenders}"


def test_rule1_agent_tools_expose_no_credential_access():
    """No agent tool reads a secret, lists credentials or names a vault ref."""
    from mybot_services.chat import tools as tools_module

    source = _module_source("mybot_services.chat.tools")
    for forbidden in ("reveal_secret", "Vault(", "vault.", "CredentialReference", "put_secret"):
        assert forbidden not in source, f"agent tool surface references {forbidden!r}"

    public = [n for n in dir(tools_module.AgentTools) if not n.startswith("_")]
    for name in public:
        assert "credential" not in name and "secret" not in name and "vault" not in name


def test_rule1_agent_cannot_propose_money_actions(services, as_alice):
    """An agent actor may only propose from the allowlist, which excludes money."""
    for action_type in ("payment.transfer", "payment.pay_bill", "utilities.pay", "vault.export"):
        assert action_type not in AGENT_PROPOSABLE
        with pytest.raises(ActionRejected):
            services.firewall.propose(
                ProposalRequest(
                    owner_id=as_alice,
                    action_type=action_type,
                    params={"payee": "X", "amount": 1.0, "account_ref": "r"}
                    if "pay" in action_type
                    else {"destination_ref": "x", "amount": 1.0}
                    if action_type == "payment.transfer"
                    else {"scope": "all"},
                    actor_type=ActorType.AGENT,
                    reason="the model wanted to",
                )
            )


# ===========================================================================
# RULE 2 — AI can never modify its own permissions
# ===========================================================================


@pytest.mark.parametrize(
    "actor", [ActorType.AGENT, ActorType.SYSTEM, ActorType.AUTOMATION, ActorType.INTEGRATION]
)
def test_rule2_only_a_human_can_create_a_permission(services, as_alice, actor):
    with pytest.raises(PermissionDenied):
        services.policy.create_rule(
            as_alice,
            action_type="calendar.reschedule",
            actor_type=actor,
            auth_level=AuthLevel.PHYSICAL,
            created_by=str(actor),
        )


def test_rule2_permission_creation_requires_strong_auth(services, as_alice):
    with pytest.raises(PermissionDenied):
        services.policy.create_rule(
            as_alice,
            action_type="calendar.reschedule",
            actor_type=ActorType.USER,
            auth_level=AuthLevel.BASIC,
            created_by="user",
        )


def test_rule2_no_permission_rules_exist_after_agent_attempts(services, as_alice):
    for _ in range(3):
        with pytest.raises(PermissionDenied):
            services.policy.create_rule(
                as_alice,
                action_type="payment.transfer",
                actor_type=ActorType.AGENT,
                auth_level=AuthLevel.PHYSICAL,
                created_by="agent",
                max_amount=10_000_000,
                allow_automatic=True,
            )
    count = services.db.execute(
        sa.select(sa.func.count()).select_from(PermissionRule).where(
            PermissionRule.owner_id == as_alice
        )
    ).scalar_one()
    assert count == 0


def test_rule2_api_permission_endpoint_requires_elevation(api, registered):
    account = registered()
    response = api.post(
        "/api/v1/security/permissions",
        json={"action_type": "payment.transfer", "max_amount": 999999, "allow_automatic": True},
        headers=account["headers"],
    )
    assert response.status_code == 403
    assert "STRONG" in response.json()["detail"]


def test_rule2_no_service_grants_permissions_with_a_non_user_actor():
    """Nothing in the codebase calls create_rule with a non-user actor.

    A grep-level assertion, deliberately. The runtime check above can be
    satisfied while a future caller quietly hard-codes ``ActorType.USER`` from
    a machine context; this catches the shape of that mistake in review.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    offenders = []
    for path in list(root.glob("services/**/*.py")) + list(root.glob("apps/**/*.py")):
        if path.name in ("service.py",) and "policy" in str(path):
            continue
        text = path.read_text(encoding="utf-8")
        if "create_rule(" not in text:
            continue
        for actor in ("ActorType.AGENT", "ActorType.SYSTEM", "ActorType.AUTOMATION"):
            index = text.find("create_rule(")
            snippet = text[index : index + 600]
            if actor in snippet:
                offenders.append(f"{path}: {actor}")
    assert offenders == [], offenders


# ===========================================================================
# RULE 3 — Thinking and authority are separate
# ===========================================================================


def test_rule3_proposal_cannot_declare_its_own_risk():
    """``ProposalRequest`` has no field for risk, approval or auth level."""
    from dataclasses import fields

    names = {f.name for f in fields(ProposalRequest)}
    for forbidden in ("risk", "requires_approval", "required_auth_level", "policy_outcome", "status"):
        assert forbidden not in names, f"a caller must not be able to set {forbidden}"


def test_rule3_risk_comes_from_the_registry_not_the_caller(services, as_alice):
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="calendar.reschedule",
            params={
                "event_id": "e1",
                "new_start": "2030-01-01T10:00:00+00:00",
                "new_end": "2030-01-01T11:00:00+00:00",
            },
            actor_type=ActorType.AGENT,
            reason="model suggestion",
        )
    )
    assert proposal.risk == RiskLevel.MEDIUM.value
    assert proposal.base_risk == ACTION_REGISTRY["calendar.reschedule"].risk.value
    assert proposal.status == ActionStatus.PENDING_APPROVAL.value


def test_rule3_execution_only_happens_through_the_firewall():
    """No module outside the firewall calls ``adapter.execute``."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    offenders = []
    for path in list(root.glob("services/**/*.py")) + list(root.glob("apps/**/*.py")):
        if "action_firewall" in str(path):
            continue
        text = path.read_text(encoding="utf-8")
        if ".execute(ctx" in text or "adapter.execute(" in text:
            offenders.append(str(path.relative_to(root)))
    assert offenders == [], f"only the Action Firewall may execute adapters: {offenders}"


# ===========================================================================
# RULE 4 — High-risk actions pass through the deterministic policy engine
# ===========================================================================


def test_rule4_high_risk_requires_a_standing_grant(services, as_alice):
    with pytest.raises(ActionRejected) as exc:
        services.firewall.propose(
            ProposalRequest(
                owner_id=as_alice,
                action_type="utilities.pay",
                params={"payee": "PSE&G", "amount": 100.0, "account_ref": "cred:bank"},
                actor_type=ActorType.USER,
            )
        )
    assert "permission rule" in str(exc.value)


def test_rule4_amount_cap_is_enforced(services, as_alice, grant):
    grant(
        as_alice,
        "utilities.pay",
        max_amount=600.0,
        allowed_recipients=["PSE&G"],
        requires_strong_auth=True,
    )
    # Within the cap: allowed to proceed to approval.
    ok = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="utilities.pay",
            params={"payee": "PSE&G", "amount": 599.99, "account_ref": "cred:bank"},
            actor_type=ActorType.USER,
        )
    )
    assert ok.status == ActionStatus.PENDING_APPROVAL.value

    # Over the cap: refused outright.
    with pytest.raises(ActionRejected) as exc:
        services.firewall.propose(
            ProposalRequest(
                owner_id=as_alice,
                action_type="utilities.pay",
                params={"payee": "PSE&G", "amount": 600.01, "account_ref": "cred:bank"},
                actor_type=ActorType.USER,
            )
        )
    assert "exceeds" in str(exc.value) or "permission rule" in str(exc.value)


def test_rule4_recipient_allowlist_is_enforced(services, as_alice, grant):
    grant(as_alice, "utilities.pay", max_amount=600.0, allowed_recipients=["PSE&G"])
    with pytest.raises(ActionRejected):
        services.firewall.propose(
            ProposalRequest(
                owner_id=as_alice,
                action_type="utilities.pay",
                params={"payee": "Attacker LLC", "amount": 10.0, "account_ref": "cred:bank"},
                actor_type=ActorType.USER,
            )
        )


def test_rule4_ten_thousand_dollar_transfer_is_never_automatic(services, as_alice, grant):
    """The spec's example: an LLM must not decide a $10,000 wire is fine."""
    grant(
        as_alice,
        "payment.transfer",
        max_amount=1_000_000.0,
        allowed_recipients=["*"],
        requires_confirmation=False,
        allow_automatic=True,  # the most permissive grant a human could write
    )
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="payment.transfer",
            params={"destination_ref": "acct-1", "amount": 10_000.0},
            actor_type=ActorType.USER,
        )
    )
    assert proposal.requires_approval is True
    assert proposal.required_auth_level == AuthLevel.PHYSICAL.value
    assert proposal.status == ActionStatus.PENDING_APPROVAL.value


def test_rule4_policy_engine_is_deterministic(services, as_alice, grant):
    """The same input yields the same decision, every time."""
    from mybot_services.policy.engine import PolicyEngine, PolicyRequest

    grant(as_alice, "utilities.pay", max_amount=500.0, allowed_recipients=["PSE&G"])
    engine = PolicyEngine()
    rules = services.policy.rule_views(as_alice)
    request = PolicyRequest(
        owner_id=as_alice,
        action_type="utilities.pay",
        params={"payee": "PSE&G", "amount": 100.0, "account_ref": "r"},
        actor_type=ActorType.USER,
        now=dt.datetime(2026, 6, 1, 12, tzinfo=dt.UTC),
    )
    decisions = [engine.evaluate(request, rules).as_dict() for _ in range(25)]
    assert all(d == decisions[0] for d in decisions)


def test_rule4_unknown_action_type_is_refused(services, as_alice):
    with pytest.raises(ActionRejected):
        services.firewall.propose(
            ProposalRequest(
                owner_id=as_alice,
                action_type="totally.made.up",
                params={},
                actor_type=ActorType.USER,
            )
        )


def test_rule4_policy_engine_fails_closed_on_internal_error(as_alice):
    """If evaluation raises, the answer is DENY."""
    from mybot_services.policy.engine import PolicyEngine, PolicyRequest

    engine = PolicyEngine()

    class Exploding(list):
        def __iter__(self):
            raise RuntimeError("simulated policy subsystem failure")

    decision = engine.evaluate(
        PolicyRequest(
            owner_id=as_alice,
            action_type="calendar.reschedule",
            params={
                "event_id": "e",
                "new_start": "2030-01-01T10:00:00+00:00",
                "new_end": "2030-01-01T11:00:00+00:00",
            },
            actor_type=ActorType.USER,
        ),
        Exploding(),
    )
    assert decision.outcome == PolicyOutcome.DENY
    assert decision.allowed is False


# ===========================================================================
# RULE 5 — Everything important is auditable
# ===========================================================================


def test_rule5_every_action_produces_a_complete_audit_trail(services, as_alice):
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=as_alice,
            action_type="calendar.reschedule",
            params={
                "event_id": "evt-1",
                "new_start": "2030-01-01T10:00:00+00:00",
                "new_end": "2030-01-01T11:00:00+00:00",
            },
            actor_type=ActorType.AGENT,
            actor_label="Calendar Assistant",
            reason="conflict with investor meeting",
        )
    )
    services.firewall.approve(
        as_alice,
        proposal.id,
        approver_user_id=as_alice,
        auth_level=AuthLevel.BASIC,
    )

    events = services.audit.list_events(as_alice, resource_id=proposal.id, limit=50)
    types = {e.event_type for e in events}
    assert "action.proposed" in types
    assert "action.approved" in types
    assert "action.executed" in types
    assert "action.result" in types

    # The spec's questions must all be answerable.
    approved = next(e for e in events if e.event_type == "action.approved")
    assert approved.timestamp is not None            # when
    assert approved.actor_type == ActorType.USER.value  # who approved
    assert approved.approval_auth_level is not None   # how strongly
    assert approved.resource_id == proposal.id        # what
    proposed = next(e for e in events if e.event_type == "action.proposed")
    assert proposed.reason == "conflict with investor meeting"  # why
    assert proposed.actor_type == ActorType.AGENT.value          # what requested it
    result = next(e for e in events if e.event_type == "action.result")
    assert result.integration is not None             # what executed it
    assert result.result is not None                  # outcome


def test_rule5_database_triggers_block_raw_audit_rewrites(services, as_alice, db):
    """Even a caller holding a raw connection cannot edit history."""
    from mybot_schemas.db.scope import session_system_scope
    from mybot_schemas.models import AuditEvent

    services.audit.record(as_alice, "test.event", reason="original")
    with session_system_scope(db, "test attempts a raw rewrite"):
        target = db.execute(
            sa.select(AuditEvent).where(AuditEvent.owner_id == as_alice).limit(1)
        ).scalar_one()

    with pytest.raises(Exception):  # noqa: B017 - dialect-specific integrity error
        db.execute(sa.text("UPDATE audit_events SET reason='rewritten' WHERE id=:i"), {"i": target.id})
        db.commit()
    db.rollback()

    with pytest.raises(Exception):  # noqa: B017
        db.execute(sa.text("DELETE FROM audit_events WHERE id=:i"), {"i": target.id})
        db.commit()
    db.rollback()


def test_rule5_hash_chain_detects_tampering_even_without_triggers(services, as_alice, db):
    """The chain is the second line of defence, independent of the triggers.

    Triggers are dropped for this test to simulate an attacker with full
    database control. The hash chain must still make the edit visible -- that
    is the whole reason for chaining rather than merely appending.
    """
    from mybot_schemas.db.scope import session_system_scope
    from mybot_schemas.models import AuditEvent

    for index in range(5):
        services.audit.record(as_alice, "test.event", reason=f"event {index}")
    assert services.audit.verify_chain(as_alice).ok

    with session_system_scope(db, "test simulates an attacker with raw database access"):
        target = db.execute(
            sa.select(AuditEvent)
            .where(AuditEvent.owner_id == as_alice)
            .order_by(AuditEvent.sequence)
            .offset(2)
            .limit(1)
        ).scalar_one()
        tampered_sequence = target.sequence

    db.execute(sa.text("DROP TRIGGER IF EXISTS audit_events_no_update"))
    db.execute(
        sa.text("UPDATE audit_events SET reason='rewritten by an attacker' WHERE id=:i"),
        {"i": target.id},
    )
    db.commit()
    db.expire_all()

    result = services.audit.verify_chain(as_alice)
    assert result.ok is False
    assert result.first_bad_sequence == tampered_sequence
    assert "hash" in (result.problem or "").lower()


def test_rule5_hash_chain_detects_a_removed_event(services, as_alice, db):
    from mybot_schemas.db.scope import session_system_scope
    from mybot_schemas.models import AuditEvent

    for index in range(5):
        services.audit.record(as_alice, "test.event", reason=f"event {index}")

    with session_system_scope(db, "test simulates an attacker deleting an event"):
        target = db.execute(
            sa.select(AuditEvent)
            .where(AuditEvent.owner_id == as_alice)
            .order_by(AuditEvent.sequence)
            .offset(2)
            .limit(1)
        ).scalar_one()
        removed_sequence = target.sequence

    db.execute(sa.text("DROP TRIGGER IF EXISTS audit_events_no_delete"))
    db.execute(sa.text("DELETE FROM audit_events WHERE id=:i"), {"i": target.id})
    db.commit()
    db.expire_all()

    result = services.audit.verify_chain(as_alice)
    assert result.ok is False
    assert result.first_bad_sequence == removed_sequence + 1
    assert "gap" in (result.problem or "").lower()


def test_rule5_audit_events_cannot_be_deleted_through_the_orm(services, as_alice, db):
    from mybot_schemas.db.session import AuditImmutableError

    event = services.audit.record(as_alice, "test.event", reason="delete me")
    db.delete(event)
    with pytest.raises(AuditImmutableError):
        db.flush()
    db.rollback()


def test_rule5_audit_events_cannot_be_modified_through_the_orm(services, as_alice, db):
    from mybot_schemas.db.session import AuditImmutableError

    event = services.audit.record(as_alice, "test.event", reason="original")
    event.reason = "modified"
    with pytest.raises(AuditImmutableError):
        db.flush()
    db.rollback()


def test_rule5_no_delete_path_exists_in_the_audit_service():
    source = _module_source("mybot_services.audit.service")
    for forbidden in ("def delete", "def remove", "def purge", "session.delete", "sa.delete"):
        assert forbidden not in source, f"audit service must not contain {forbidden!r}"


def test_rule5_untrusted_forbidden_covers_every_high_risk_action():
    for action_type, spec in ACTION_REGISTRY.items():
        if spec.risk.at_least(RiskLevel.HIGH):
            assert action_type in UNTRUSTED_FORBIDDEN


# ---------------------------------------------------------------------------


def _module_source(module_name: str) -> str:
    import importlib
    import inspect

    module = importlib.import_module(module_name)
    try:
        return inspect.getsource(module)
    except OSError:  # pragma: no cover
        return ""
