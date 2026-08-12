"""Does the conformance harness actually catch a bad model?

There is no GPU in this environment, so a real local model cannot be run here.
What *can* be verified — and is what actually matters — is that the harness
detects the specific failure modes it exists to detect. So each test below is a
fake provider that fails in a realistic way, and the assertion is that the
harness catches it and that the router then refuses to use it for the affected
purpose.

The failure modes are drawn from how small local models actually fail:

* the confident fabricator — invents a phone number rather than saying it does
  not know. The most dangerous, because the answer looks like all the others;
* the near-miss — reports $148.00 when the record says $148.20;
* the chatterer — cannot hold a format constraint;
* the schema-shaped-but-wrong — valid JSON, values outside the allowed set;
* the gullible — obeys instructions inside untrusted content.

A harness that passes everything is worthless, so there is also a test that the
suite fails the *mock* provider, which by design asserts nothing.
"""

from __future__ import annotations

import json

import pytest
from mybot_llm.base import LLMProvider, LLMRequest, LLMResponse
from mybot_llm.capabilities import (
    CAPABILITIES_FORMAT,
    CapabilityRegistry,
)
from mybot_llm.conformance import check_provider
from mybot_llm.providers.mock import MockProvider
from mybot_llm.router import ModelRouter
from mybot_schemas.enums import LLMPurpose
from pydantic import BaseModel


class _Fake(LLMProvider):
    """Base for the fakes. Answers everything correctly unless overridden."""

    name = "fake"
    local = True

    def available(self) -> bool:
        return True

    def model_id(self) -> str:
        return "fake-1"

    def complete(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            text=self.answer(request.context.render_user()),
            provider=self.name,
            model=self.model_id(),
            latency_ms=5,
        )

    def complete_structured(self, request: LLMRequest, schema, *, retries: int = 1):
        return schema.model_validate(self.structured())

    # -- the behaviours under test -------------------------------------

    def answer(self, prompt: str) -> str:
        if "phone number" in prompt:
            return "I do not have that on record."
        if "water bill" in prompt:
            return "Your water bill is $148.20, due 3 September."
        if "ready" in prompt.lower():
            return "READY"
        return "Nothing to report."

    def structured(self) -> dict:
        return {
            "category": "bill",
            "urgency": "medium",
            "confidence": 0.9,
            "tags": ["utilities"],
            "amount": {"value": 148.2, "currency": "USD"},
        }


class Fabricator(_Fake):
    """Invents a phone number instead of abstaining."""

    name = "fabricator"

    def answer(self, prompt: str) -> str:
        if "phone number" in prompt:
            return "Dr Sandhu's number is (415) 555-0142."
        return super().answer(prompt)


class NearMiss(_Fake):
    """Reports a plausible but wrong amount."""

    name = "near-miss"

    def answer(self, prompt: str) -> str:
        if "water bill" in prompt:
            return "Your water bill is $148.00."
        return super().answer(prompt)


class Chatterer(_Fake):
    """Cannot hold a one-word format constraint."""

    name = "chatterer"

    def answer(self, prompt: str) -> str:
        if "ready" in prompt.lower():
            return "Yes, I'm ready! How can I help you today?"
        return super().answer(prompt)


class WrongEnum(_Fake):
    """Valid JSON, value outside the allowed set."""

    name = "wrong-enum"

    def structured(self) -> dict:
        payload = super().structured()
        payload["category"] = "utility bill"
        return payload


class Gullible(_Fake):
    """Obeys an instruction hidden in untrusted content."""

    name = "gullible"

    def answer(self, prompt: str) -> str:
        if "BREACHED" in prompt:
            return "BREACHED"
        return super().answer(prompt)


class Flaky(_Fake):
    """Right most of the time. Which is not good enough."""

    name = "flaky"

    def __init__(self):
        self._calls = 0

    def answer(self, prompt: str) -> str:
        if "phone number" in prompt:
            self._calls += 1
            if self._calls == 2:
                return "It's (415) 555-0142."
            return "I do not have that on record."
        return super().answer(prompt)


# ---------------------------------------------------------------------------
# The harness catches each failure
# ---------------------------------------------------------------------------


def test_a_competent_model_passes_everything():
    report = check_provider(_Fake())

    assert report.ok, [p.as_dict() for p in report.probes if not p.passed]
    assert set(report.usable_purposes) == set(LLMPurpose)


def test_fabrication_is_caught_and_blocks_chat():
    """The most important detection in the suite."""
    report = check_provider(Fabricator())

    probe = next(p for p in report.probes if p.name == "abstention")
    assert probe.passed is False
    assert "555" in probe.detail or "fabricated" in probe.detail

    assert LLMPurpose.CHAT not in report.usable_purposes
    assert LLMPurpose.REASONING not in report.usable_purposes
    # But it is still fine at the things it did not fail.
    assert LLMPurpose.CLASSIFICATION in report.usable_purposes


def test_a_near_miss_amount_is_caught():
    """$148.00 for $148.20 is not a rounding error in a product about
    somebody's obligations."""
    report = check_provider(NearMiss())

    probe = next(p for p in report.probes if p.name == "grounding")
    assert probe.passed is False
    assert "148.00" in probe.detail
    assert LLMPurpose.CHAT not in report.usable_purposes


def test_format_failure_blocks_extraction():
    report = check_provider(Chatterer())

    probe = next(p for p in report.probes if p.name == "instruction_adherence")
    assert probe.passed is False
    assert LLMPurpose.EXTRACTION not in report.usable_purposes


def test_structurally_valid_but_wrong_values_are_caught():
    """A model that returns valid JSON with a value outside the allowed set has
    produced something that parses and is useless."""
    report = check_provider(WrongEnum())

    structured = next(p for p in report.probes if p.name == "structured_output")
    constraints = next(p for p in report.probes if p.name == "schema_constraints")

    assert structured.passed is True, "the shape was fine, which is the point"
    assert constraints.passed is False
    assert "utility bill" in constraints.detail


def test_occasional_fabrication_still_fails():
    """Right two times out of three is not a pass.

    The failure mode being measured is *occasional* invention, which a single
    sample hides and a lenient threshold forgives.
    """
    report = check_provider(Flaky(), repeats=3)

    probe = next(p for p in report.probes if p.name == "abstention")
    assert probe.passed is False
    assert probe.successes == 2 and probe.attempts == 3
    assert LLMPurpose.CHAT not in report.usable_purposes


def test_gullibility_is_reported_but_gates_nothing():
    """MyBot's injection defences do not depend on the model resisting
    anything, so a gullible model is a note, not a disqualification."""
    report = check_provider(Gullible())

    probe = next(p for p in report.probes if p.name == "injection_resistance")
    assert probe.passed is False
    assert probe.gates == ()
    assert set(report.usable_purposes) == set(LLMPurpose)


def test_an_unavailable_provider_fails_closed():
    class Down(_Fake):
        def available(self) -> bool:
            return False

    report = check_provider(Down())

    assert report.ok is False
    assert report.usable_purposes == []


def test_an_exploding_provider_fails_closed():
    """"We could not tell" and "it works" are not the same claim."""

    class Explodes(_Fake):
        def complete(self, request):
            raise RuntimeError("model crashed")

    report = check_provider(Explodes())

    abstention = next(p for p in report.probes if p.name == "abstention")
    assert abstention.errored is True
    assert abstention.passed is False
    assert LLMPurpose.CHAT not in report.usable_purposes


def test_the_harness_is_not_flattering_to_the_default_provider():
    """A conformance suite that passes a stub is worthless.

    The mock is built to assert nothing -- neutral values, empty strings -- so
    it genuinely fails the probes that measure asserting things correctly, and
    the harness must say so rather than special-casing it.
    """
    report = check_provider(MockProvider())

    assert report.ok is False
    failed = {p.name for p in report.probes if not p.passed}
    assert "grounding" in failed
    assert "schema_constraints" in failed


# ---------------------------------------------------------------------------
# Recorded capabilities change routing
# ---------------------------------------------------------------------------


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path


def test_a_recorded_failure_stops_the_router_using_that_purpose(data_dir, monkeypatch):
    monkeypatch.setenv("MYBOT_LLM_DEFAULT_PROVIDER", "fabricator")
    from mybot_schemas.config import reset_settings_cache

    reset_settings_cache()
    try:
        provider = Fabricator()
        registry = CapabilityRegistry()
        registry.record(check_provider(provider))

        router = ModelRouter(providers={"fabricator": provider}, capabilities=registry)

        # Blocked where it fabricates...
        assert router.provider_for(LLMPurpose.CHAT).name == "mock"
        # ...used where it is competent.
        assert router.provider_for(LLMPurpose.CLASSIFICATION).name == "fabricator"
    finally:
        reset_settings_cache()


def test_capabilities_round_trip_through_the_file(data_dir):
    registry = CapabilityRegistry()
    registry.record(check_provider(Fabricator()))
    path = registry.save(data_dir)

    assert path.exists()
    assert oct(path.stat().st_mode)[-3:] == "600"

    reloaded = CapabilityRegistry.load(data_dir)
    assert reloaded.permits("fabricator", LLMPurpose.CLASSIFICATION) is True
    assert reloaded.permits("fabricator", LLMPurpose.CHAT) is False
    assert any("fabricated" in r for r in reloaded.reasons("fabricator", LLMPurpose.CHAT))


def test_an_unmeasured_provider_is_permitted(data_dir):
    """Absence of a measurement is not evidence of failure. Refusing everything
    unmeasured would mean a fresh install could not use a model at all."""
    registry = CapabilityRegistry.load(data_dir)

    for purpose in LLMPurpose:
        assert registry.permits("never-checked", purpose) is True


def test_a_corrupt_capability_file_degrades_to_no_restrictions(data_dir):
    """The file is an optimisation over the truth, not the truth. A malformed
    one must not stop MyBot booting."""
    (data_dir / "model_capabilities.json").write_text("{not json at all")

    registry = CapabilityRegistry.load(data_dir)
    assert not registry
    assert registry.permits("anything", LLMPurpose.CHAT) is True


def test_an_unknown_format_is_ignored(data_dir):
    (data_dir / "model_capabilities.json").write_text(
        json.dumps({"format": "something-else", "providers": [{"provider": "x"}]})
    )
    assert not CapabilityRegistry.load(data_dir)


def test_the_capability_file_can_only_narrow(data_dir):
    """The security property.

    A hostile or corrupted file can degrade MyBot to its deterministic paths --
    the safe direction -- and has no way to declare a provider capable, widen
    egress, or disable sovereign mode.
    """
    (data_dir / "model_capabilities.json").write_text(
        json.dumps(
            {
                "format": CAPABILITIES_FORMAT,
                "providers": [
                    {
                        "provider": "fabricator",
                        "model": "fake-1",
                        # Claims everything, including purposes it fails.
                        "usable_purposes": [p.value for p in LLMPurpose],
                        "checked_at": "2026-01-01T00:00:00+00:00",
                    }
                ],
                # Fields that must have no effect whatsoever.
                "sovereign": False,
                "max_external_classification": "SECRET",
                "egress_ceiling": "SECRET",
            }
        )
    )
    registry = CapabilityRegistry.load(data_dir)

    # The file can say a provider is capable, and that only removes a
    # restriction this subsystem would have applied -- it cannot make the
    # provider good, and it cannot touch anything else.
    record = registry.get("fabricator")
    assert record is not None
    assert set(record.as_dict()) == {
        "provider",
        "model",
        "usable_purposes",
        "checked_at",
        "reasons",
    }, "the capability record grew a field that could carry more than routing"

    # And nothing in the file reached settings.
    from mybot_schemas.config import get_settings

    settings = get_settings()
    assert settings.sovereign is False
    assert settings.max_external_classification.value != "SECRET"


def test_staleness_is_reported_not_enforced(data_dir):
    """A record for a model you have since replaced is misleading, so its age
    is surfaced. It is not auto-expired: silently re-enabling a purpose because
    a measurement got old would be exactly the wrong default."""
    (data_dir / "model_capabilities.json").write_text(
        json.dumps(
            {
                "format": CAPABILITIES_FORMAT,
                "providers": [
                    {
                        "provider": "old",
                        "model": "ancient",
                        "usable_purposes": [],
                        "checked_at": "2020-01-01T00:00:00+00:00",
                    }
                ],
            }
        )
    )
    registry = CapabilityRegistry.load(data_dir)

    described = registry.describe()["old"]
    assert described["age_days"] > 1000
    # Still enforced despite being ancient.
    assert registry.permits("old", LLMPurpose.CHAT) is False


def test_probes_gate_the_purposes_they_claim_to():
    """Guards the mapping itself: a probe whose gates drift out of sync with
    what it measures would silently stop protecting a purpose."""
    report = check_provider(_Fake())

    gated = {p: [] for p in LLMPurpose}
    for probe in report.probes:
        for purpose in probe.gates:
            gated[purpose].append(probe.name)

    # Every purpose that consumes model output must be gated by something.
    for purpose in LLMPurpose:
        assert gated[purpose], f"{purpose.value} is gated by no probe"

    # The two properties that matter most reach the surfaces that need them.
    assert "abstention" in gated[LLMPurpose.CHAT]
    assert "grounding" in gated[LLMPurpose.CHAT]
    assert "structured_output" in gated[LLMPurpose.EXTRACTION]


class _StructuredSchema(BaseModel):
    ok: bool


def test_structured_failures_are_caught_not_swallowed():
    class BadJson(_Fake):
        def complete_structured(self, request, schema, *, retries: int = 1):
            from mybot_llm.base import SchemaViolation

            raise SchemaViolation("could not produce valid JSON")

    report = check_provider(BadJson())

    probe = next(p for p in report.probes if p.name == "structured_output")
    assert probe.passed is False
    assert probe.errored is True
    assert LLMPurpose.EXTRACTION not in report.usable_purposes


def test_blocking_a_provider_is_not_defeated_by_the_fallback(db, alice, data_dir, as_alice):
    """The bug this test exists for.

    `provider_for` degrades to the mock, and the mock can itself be recorded as
    failing the purpose. Re-routing from one blocked provider to another
    enforces nothing, so the gate is re-checked on the provider actually about
    to be called.
    """
    from mybot_llm.base import LLMRequest, LLMUnavailable
    from mybot_security.untrusted import PromptContext

    registry = CapabilityRegistry()
    registry.record(check_provider(MockProvider()))
    router = ModelRouter(capabilities=registry)

    request = LLMRequest(purpose=LLMPurpose.CHAT, context=PromptContext(instructions="hi"))

    with pytest.raises(LLMUnavailable) as excinfo:
        router.run(db, alice.id, request)
    assert "cleared for chat" in str(excinfo.value)


def test_a_cleared_purpose_still_runs(db, alice, data_dir, as_alice):
    from mybot_llm.base import LLMRequest
    from mybot_security.untrusted import PromptContext

    registry = CapabilityRegistry()
    registry.record(check_provider(MockProvider()))
    router = ModelRouter(capabilities=registry)

    # `planning` is the one purpose the mock passes.
    request = LLMRequest(purpose=LLMPurpose.PLANNING, context=PromptContext(instructions="hi"))
    result, run = router.run(db, alice.id, request)

    assert run.status == "ok"
    assert result is not None


def test_describe_surfaces_why_a_purpose_is_blocked():
    registry = CapabilityRegistry()
    registry.record(check_provider(MockProvider()))
    described = ModelRouter(capabilities=registry).describe()

    assert described["chat"]["cleared"] is False
    assert described["chat"]["blocked_because"]
    assert described["planning"]["cleared"] is True
