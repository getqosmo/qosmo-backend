"""Learning, and the wall between learning and authority.

A system whose explicit job is to change its own future behaviour is the single
most attractive target in MyBot. An attacker with patience does not want to
execute one action today; they want to teach the assistant a habit that pays
out for years. So the tests that matter here are not "does it learn" — they are:

* learning can never grant authority (Rule 2, applied to the subsystem that
  most wants to violate it);
* learning from content the owner did not write is quarantined, and quarantine
  cannot be laundered away by following it with honest observations;
* the owner can see, correct and delete everything;
* what MyBot claims to have learned matches the evidence it actually has.
"""

from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa
from mybot_schemas.models import LearnedPreference, PermissionRule
from mybot_services.learning import (
    FORBIDDEN_SURFACES,
    LEARNABLE,
    LearningBoundaryViolation,
    LearningService,
    assert_never_authority,
)
from mybot_services.learning.kinds import LearnableKind


@pytest.fixture
def learning(db, services):
    return LearningService(db, audit=services.audit)


# ---------------------------------------------------------------------------
# Rule 2: learning is not authority
# ---------------------------------------------------------------------------


def test_no_learnable_kind_claims_an_authority_surface():
    """The barrier, walked over the whole vocabulary.

    If somebody adds a kind that influences `policy` or `approval`, this fails
    before the code can ship -- which is the point of declaring surfaces at all.
    """
    for kind in LEARNABLE.values():
        assert not FORBIDDEN_SURFACES.intersection(kind.influences), (
            f"{kind.key} claims an authority surface"
        )
        assert_never_authority(kind)


def test_a_kind_claiming_policy_is_rejected():
    with pytest.raises(LearningBoundaryViolation):
        assert_never_authority(
            LearnableKind(
                key="sneaky",
                label="",
                evidence="",
                influences=("ranking", "policy"),
                min_evidence=1,
                min_agreement=1.0,
            )
        )


def test_learning_service_holds_no_reference_that_could_grant_permission():
    """Dependency inversion as the barrier.

    LearningService cannot create a permission rule because it has no policy
    service, no firewall and no way to reach one. This is the same technique
    that keeps the LLM package unable to import the Vault.
    """
    import inspect

    signature = inspect.signature(LearningService.__init__)
    assert set(signature.parameters) == {"self", "session", "audit"}

    source = inspect.getsource(LearningService)
    for forbidden in ("PolicyService", "ActionFirewall", "PermissionRule", "create_rule"):
        assert forbidden not in source, (
            f"LearningService references {forbidden}; learning must not be able to "
            f"touch authority"
        )


def test_heavy_approval_history_creates_no_permission_rule(db, alice, learning, as_alice):
    """The scenario the design exists to refuse.

    Twenty approvals of the same action is exactly when a naive system decides
    to stop asking. MyBot may *offer*; it may not decide.
    """
    for i in range(20):
        learning.observe(
            alice.id,
            kind="action_approved",
            subject="calendar.create",
            evidence_ref=f"proposal-{i}",
        )

    rules = db.execute(
        sa.select(PermissionRule).where(PermissionRule.owner_id == alice.id)
    ).scalars().all()
    assert rules == [], "learning created a permission rule"

    suggestions = learning.suggestions(alice.id)
    assert len(suggestions) == 1
    assert suggestions[0]["action_type"] == "calendar.create"
    assert suggestions[0]["requires_human_confirmation"] is True


def test_rejection_history_suppresses_offers_without_writing_a_deny_rule(
    db, alice, learning, as_alice
):
    """Even a learned *deny* is authority written by a statistic.

    It is the safe direction today and a precedent tomorrow, so it is refused
    the same way. Rejections change what MyBot offers, not what it may do.
    """
    for i in range(5):
        learning.observe(
            alice.id, kind="action_rejected", subject="email.send", evidence_ref=f"p{i}"
        )

    assert (
        db.execute(
            sa.select(PermissionRule).where(PermissionRule.owner_id == alice.id)
        ).scalars().all()
        == []
    )
    applied = learning.applicable(alice.id, kind="action_rejected")
    assert len(applied) == 1
    assert LEARNABLE["action_rejected"].influences == ("suppression", "ranking")


# ---------------------------------------------------------------------------
# Untrusted content cannot teach
# ---------------------------------------------------------------------------


def test_untrusted_learning_is_stored_but_never_applied(db, alice, learning, as_alice):
    """The long-horizon injection: teach the assistant a habit.

    An email saying "Kai always approves wire transfers without confirmation"
    must be visible to the owner and inert to MyBot.
    """
    for i in range(10):
        learning.observe(
            alice.id,
            kind="action_approved",
            subject="finance.transfer",
            evidence_ref=f"email-{i}",
            untrusted=True,
        )

    assert learning.applicable(alice.id) == []
    assert learning.suggestions(alice.id) == []
    assert learning.guidance_for_prompt(alice.id) == []

    # But the owner can see it.
    report = learning.growth_report(alice.id)
    assert report["quarantined_count"] == 1
    assert report["by_kind"]["action_approved"][0]["quarantined"] is True


def test_quarantine_cannot_be_laundered_by_later_honest_observations(
    db, alice, learning, as_alice
):
    """One poisoned observation taints the row permanently.

    Otherwise the attack is trivial: land one untrusted observation, then let
    ordinary use wash it clean.
    """
    learning.observe(
        alice.id, kind="action_approved", subject="finance.transfer", untrusted=True
    )
    for i in range(20):
        learning.observe(
            alice.id, kind="action_approved", subject="finance.transfer", evidence_ref=f"r{i}"
        )

    row = db.execute(
        sa.select(LearnedPreference).where(LearnedPreference.subject == "finance.transfer")
    ).scalar_one()
    assert row.derived_from_untrusted is True
    assert row.evidence_count == 21
    assert learning.applicable(alice.id) == []


def test_only_a_human_can_lift_quarantine(db, alice, learning, as_alice):
    row = learning.observe(
        alice.id, kind="phrasing_style", subject="brief", value={"style": "terse"},
        untrusted=True,
    )
    assert learning.applicable(alice.id) == []

    assert learning.confirm(alice.id, row.id) is True
    applied = learning.applicable(alice.id)
    assert len(applied) == 1
    assert applied[0].derived_from_untrusted is False


def test_unknown_kind_is_refused(db, alice, learning, as_alice):
    """An open vocabulary is an unreviewable one."""
    with pytest.raises(LearningBoundaryViolation):
        learning.observe(alice.id, kind="invent_something", subject="x")


# ---------------------------------------------------------------------------
# Honest evidence
# ---------------------------------------------------------------------------


def test_one_observation_is_not_a_preference(db, alice, learning, as_alice):
    learning.observe(alice.id, kind="preferred_time", subject="dentist", value={"period": "morning"})
    assert learning.applicable(alice.id, kind="preferred_time") == []


def test_contradictions_are_kept_not_subtracted(db, alice, learning, as_alice):
    for i in range(9):
        learning.observe(alice.id, kind="action_approved", subject="calendar.create",
                         evidence_ref=f"a{i}")
    learning.observe(alice.id, kind="action_approved", subject="calendar.create",
                     agrees=False, evidence_ref="reject-1")

    row = db.execute(sa.select(LearnedPreference)).scalar_one()
    assert row.evidence_count == 9
    assert row.contradiction_count == 1

    suggestion = learning.suggestions(alice.id)[0]
    assert "9 of 10" in suggestion["headline"], "the exception rate must survive into the offer"


def test_frequent_contradiction_disqualifies_a_preference(db, alice, learning, as_alice):
    for i in range(6):
        learning.observe(alice.id, kind="action_approved", subject="email.send", evidence_ref=f"a{i}")
    for i in range(6):
        learning.observe(alice.id, kind="action_approved", subject="email.send",
                         agrees=False, evidence_ref=f"r{i}")

    assert learning.applicable(alice.id, kind="action_approved") == []


def test_volume_cannot_compensate_for_being_wrong_half_the_time(db, alice, learning, as_alice):
    """Confidence multiplies rather than averages, so 500 observations at 50%
    agreement is still not a preference."""
    for i in range(250):
        learning.observe(alice.id, kind="entity_importance", subject="Acme", evidence_ref=f"a{i}")
        learning.observe(alice.id, kind="entity_importance", subject="Acme",
                         agrees=False, evidence_ref=f"r{i}")

    row = db.execute(sa.select(LearnedPreference)).scalar_one()
    assert row.evidence_count == 250
    assert row.confidence < 0.55


def test_inferred_preferences_decay_but_stated_ones_do_not(db, alice, learning, as_alice):
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=400)

    for i in range(6):
        learning.observe(alice.id, kind="preferred_time", subject="gym",
                         value={"period": "morning"}, evidence_ref=f"g{i}", now=old)
    stated = learning.record_correction(
        alice.id, subject="my dentist", correction="Dr Patel, not Dr Sandhu", now=old
    )

    later = dt.datetime.now(dt.UTC)
    applied = {r.id for r in learning.applicable(alice.id, now=later)}

    assert stated.id in applied, "a stated correction must never decay away"
    inferred = db.execute(
        sa.select(LearnedPreference).where(LearnedPreference.kind == "preferred_time")
    ).scalar_one()
    assert inferred.id not in applied


def test_corrections_apply_immediately(db, alice, learning, as_alice):
    """Making somebody repeat a correction three times is how an assistant
    becomes infuriating."""
    learning.record_correction(alice.id, subject="my dentist", correction="Dr Patel")

    applied = learning.applicable(alice.id)
    assert len(applied) == 1
    assert applied[0].confidence == 1.0
    assert "Dr Patel" in applied[0].explanation


def test_explanations_are_deterministic_not_model_written(db, alice, learning, as_alice):
    """The sentence the owner reads must not drift from the row's contents."""
    import inspect

    from mybot_services.learning import service as service_mod

    source = inspect.getsource(service_mod)
    for forbidden in ("ModelRouter", "LLMRequest", "complete(", "provider"):
        assert forbidden not in source, f"learning reached for {forbidden}"


# ---------------------------------------------------------------------------
# Owner control
# ---------------------------------------------------------------------------


def test_owner_can_mute_confirm_and_delete(db, alice, learning, as_alice):
    for i in range(5):
        learning.observe(alice.id, kind="action_rejected", subject="email.send",
                         evidence_ref=f"r{i}")
    row = db.execute(sa.select(LearnedPreference)).scalar_one()

    assert learning.mute(alice.id, row.id) is True
    assert learning.applicable(alice.id) == []

    assert learning.mute(alice.id, row.id, muted=False) is True
    assert len(learning.applicable(alice.id)) == 1

    assert learning.forget(alice.id, row.id) is True
    assert db.execute(sa.select(LearnedPreference)).scalars().all() == []


def test_forget_is_a_hard_delete(db, alice, learning, as_alice):
    """"MyBot, forget that" must actually mean it."""
    row = learning.record_correction(alice.id, subject="x", correction="y")
    learning.forget(alice.id, row.id)

    remaining = db.execute(sa.select(LearnedPreference)).scalars().all()
    assert remaining == []


def test_one_owner_cannot_touch_anothers_learning(db, alice, bob, services, as_alice):
    learning = LearningService(db, audit=services.audit)
    row = learning.record_correction(alice.id, subject="x", correction="y")

    assert learning.mute(bob.id, row.id) is False
    assert learning.confirm(bob.id, row.id) is False
    assert learning.forget(bob.id, row.id) is False
    assert db.get(LearnedPreference, row.id) is not None


def test_growth_report_is_honest_about_what_is_applied(db, alice, learning, as_alice):
    learning.record_correction(alice.id, subject="dentist", correction="Dr Patel")
    learning.observe(alice.id, kind="preferred_time", subject="gym", value={"period": "morning"})
    learning.observe(alice.id, kind="action_approved", subject="finance.transfer", untrusted=True)

    report = learning.growth_report(alice.id)

    assert report["learned_count"] == 3
    assert report["applied_count"] == 1  # only the correction clears the bar
    assert report["quarantined_count"] == 1
    assert report["days_learning"] >= 0
    # No gamification: the report describes, it does not score.
    assert "level" not in report
    assert "score" not in report


# ---------------------------------------------------------------------------
# Reaching the model
# ---------------------------------------------------------------------------


def test_guidance_is_bounded_however_much_is_learned(db, alice, learning, as_alice):
    for i in range(60):
        learning.record_correction(alice.id, subject=f"thing-{i}", correction=f"value-{i}")

    guidance = learning.guidance_for_prompt(alice.id)
    assert len(guidance) <= 12, "an assistant reciting 60 preferences is cluttered, not personal"


def test_guidance_prioritises_corrections_and_style(db, alice, learning, as_alice):
    for i in range(6):
        learning.observe(alice.id, kind="entity_importance", subject=f"Acme{i}",
                         evidence_ref=f"e{i}")
        learning.observe(alice.id, kind="entity_importance", subject=f"Acme{i}",
                         evidence_ref=f"e2{i}")
        learning.observe(alice.id, kind="entity_importance", subject=f"Acme{i}",
                         evidence_ref=f"e3{i}")
        learning.observe(alice.id, kind="entity_importance", subject=f"Acme{i}",
                         evidence_ref=f"e4{i}")
    learning.record_correction(alice.id, subject="my dentist", correction="Dr Patel")

    guidance = learning.guidance_for_prompt(alice.id, limit=3)
    assert any("Dr Patel" in line for line in guidance)


# ---------------------------------------------------------------------------
# The firewall feeds learning, one way only
# ---------------------------------------------------------------------------


def test_approving_through_the_firewall_records_evidence(db, alice, services, grant, as_alice):
    """The signal has to actually be collected, or the whole subsystem is a
    table nobody writes to."""
    from mybot_schemas.enums import ActorType, AuthLevel
    from mybot_services.action_firewall.service import ProposalRequest

    grant(alice.id, "calendar.create")
    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=alice.id,
            action_type="calendar.create",
            params={
                "title": "Dentist",
                "start": "2026-09-01T09:00:00+00:00",
                "end": "2026-09-01T10:00:00+00:00",
            },
            actor_type=ActorType.USER,
            actor_id=alice.id,
            presented_auth_level=AuthLevel.STRONG,
        )
    )
    services.firewall.approve(
        alice.id, proposal.id, approver_user_id=alice.id, auth_level=AuthLevel.STRONG
    )

    row = db.execute(
        sa.select(LearnedPreference).where(
            LearnedPreference.kind == "action_approved",
            LearnedPreference.subject == "calendar.create",
        )
    ).scalar_one()
    assert row.evidence_count == 1
    assert proposal.id in row.evidence_refs


def test_a_broken_learning_sink_cannot_break_an_approval(db, alice, services, grant, as_alice):
    """Learning is an enhancement. A failure to record that somebody approved
    something must never become a failure to approve it."""
    from mybot_schemas.enums import ActorType, AuthLevel
    from mybot_services.action_firewall.service import ProposalRequest

    class Exploding:
        def observe(self, *_a, **_k):
            raise RuntimeError("learning is down")

    services.firewall.learning = Exploding()
    grant(alice.id, "calendar.create")

    proposal = services.firewall.propose(
        ProposalRequest(
            owner_id=alice.id,
            action_type="calendar.create",
            params={
                "title": "Dentist",
                "start": "2026-09-01T09:00:00+00:00",
                "end": "2026-09-01T10:00:00+00:00",
            },
            actor_type=ActorType.USER,
            actor_id=alice.id,
            presented_auth_level=AuthLevel.STRONG,
        )
    )
    result = services.firewall.approve(
        alice.id, proposal.id, approver_user_id=alice.id, auth_level=AuthLevel.STRONG
    )
    assert result is not None


def test_firewall_cannot_read_learned_state(db, alice, services, as_alice):
    """The sink is write-only by construction, not by convention."""
    from mybot_services.learning.sink import NullObservationSink, ObservationSink

    sink_methods = {m for m in dir(ObservationSink) if not m.startswith("_")}
    assert sink_methods == {"observe"}, (
        "the sink grew a way to read learned state back into authority code"
    )
    assert set(dir(NullObservationSink)) >= {"observe"}


# ---------------------------------------------------------------------------
# Portability: the individual outlives the model
# ---------------------------------------------------------------------------


def test_learned_state_survives_a_backup_round_trip(db, alice, services, as_alice):
    """The promise under test: you own your BabyBot.

    Entities and emails can be re-synced from their sources. A decade of
    corrections cannot be re-synced from anywhere, so if learning is missing
    from a backup the product claim is false in the only moment that tests it.
    """
    from mybot_api.export import build_export_payload
    from mybot_security.backup import BackupService

    services.learning.record_correction(
        alice.id, subject="my dentist", correction="Dr Patel, not Dr Sandhu"
    )
    for i in range(5):
        services.learning.observe(
            alice.id, kind="action_rejected", subject="email.send", evidence_ref=f"p{i}"
        )
    db.flush()

    payload = build_export_payload(
        db=db, audit=services.audit, owner_id=alice.id, user=alice
    )
    archive, _, phrase = BackupService().create(payload=payload, owner_id=alice.id)
    restored = BackupService().restore(archive, recovery_phrase=phrase)

    learned = restored["learned_preferences"]
    assert len(learned) == 2
    correction = next(p for p in learned if p["kind"] == "correction")
    assert "Dr Patel" in correction["explanation"]
    assert correction["confirmed_by_owner"] is True
    # Evidence travels too, so a restored MyBot knows how much to trust it.
    rejection = next(p for p in learned if p["kind"] == "action_rejected")
    assert rejection["evidence_count"] == 5


def test_learned_state_is_portable_across_models(db, alice, learning, as_alice):
    """The weights are rented; the individual is owned.

    Nothing in a learned row may reference a provider or model, or swapping the
    brain would cost the owner their history.
    """
    learning.record_correction(alice.id, subject="dentist", correction="Dr Patel")
    row = db.execute(sa.select(LearnedPreference)).scalar_one()

    columns = {c.name for c in row.__table__.columns}
    for leaky in ("provider", "model", "model_id", "llm_run_id", "embedding"):
        assert leaky not in columns


# ---------------------------------------------------------------------------
# The API surface
# ---------------------------------------------------------------------------


def test_owner_sees_and_controls_learning_over_http(api, registered):
    account = registered()
    headers = account["headers"]

    created = api.post(
        "/api/v1/learning/corrections",
        json={"subject": "my dentist", "correction": "Dr Patel, not Dr Sandhu"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    preference_id = created.json()["id"]
    assert created.json()["confirmed_by_owner"] is True

    report = api.get("/api/v1/learning", headers=headers).json()
    assert report["learned_count"] == 1
    assert report["applied_count"] == 1

    assert api.post(
        f"/api/v1/learning/preferences/{preference_id}/mute", headers=headers
    ).status_code == 200
    assert api.get("/api/v1/learning", headers=headers).json()["applied_count"] == 0

    assert api.delete(
        f"/api/v1/learning/preferences/{preference_id}", headers=headers
    ).status_code == 200
    assert api.get("/api/v1/learning", headers=headers).json()["learned_count"] == 0


def test_learning_endpoints_are_owner_scoped(api, registered):
    alice_acct = registered("alice-api@example.com", "Alice")
    bob_acct = registered("bob-api@example.com", "Bob")

    created = api.post(
        "/api/v1/learning/corrections",
        json={"subject": "x", "correction": "y"},
        headers=alice_acct["headers"],
    )
    preference_id = created.json()["id"]

    # A valid token for the wrong account must not reach it.
    for call in (
        lambda: api.post(
            f"/api/v1/learning/preferences/{preference_id}/mute", headers=bob_acct["headers"]
        ),
        lambda: api.post(
            f"/api/v1/learning/preferences/{preference_id}/confirm", headers=bob_acct["headers"]
        ),
        lambda: api.delete(
            f"/api/v1/learning/preferences/{preference_id}", headers=bob_acct["headers"]
        ),
    ):
        assert call().status_code == 404

    assert api.get("/api/v1/learning", headers=bob_acct["headers"]).json()["learned_count"] == 0


def test_learning_api_cannot_create_a_permission(api, registered):
    """The whole router, checked for the thing it must never do.

    No route here accepts a permission, and the suggestions endpoint returns
    offers that state they need a human.
    """
    from mybot_api.routers import learning as learning_router

    paths = {route.path for route in learning_router.router.routes}
    for path in paths:
        assert "permission" not in path or "preferences" in path

    account = registered()
    body = api.get("/api/v1/learning/suggestions", headers=account["headers"]).json()
    assert body["suggestions"] == []

    rules = api.get("/api/v1/security/permissions", headers=account["headers"])
    if rules.status_code == 200:
        assert rules.json().get("rules", []) == []


def test_a_quarantined_row_is_not_phrased_as_mybots_own_belief(db, alice, learning, as_alice):
    """Caught by looking at the rendered page.

    "You usually approve payment.transfer" printed next to a badge saying MyBot
    will not act on it invites the reader to believe MyBot believes it. It does
    not, and the sentence must say so.
    """
    row = learning.observe(
        alice.id, kind="action_approved", subject="payment.transfer", untrusted=True
    )

    assert "You usually approve" not in row.explanation
    assert "did not write" in row.explanation
    assert "not acted on" in row.explanation.lower()


def test_the_sentence_changes_when_a_row_becomes_tainted(db, alice, learning, as_alice):
    """A row that was MyBot's own conclusion and then received untrusted
    evidence must stop being phrased as one."""
    row = learning.observe(alice.id, kind="action_approved", subject="email.send")
    assert "You usually approve" in row.explanation

    row = learning.observe(
        alice.id, kind="action_approved", subject="email.send", untrusted=True
    )
    assert "You usually approve" not in row.explanation
    assert "did not write" in row.explanation


def test_an_explicit_explanation_is_never_overwritten(db, alice, learning, as_alice):
    learning.observe(
        alice.id, kind="action_approved", subject="email.send", explanation="Custom wording"
    )
    row = learning.observe(
        alice.id,
        kind="action_approved",
        subject="email.send",
        explanation="Custom wording",
        untrusted=True,
    )
    assert row.explanation == "Custom wording"
