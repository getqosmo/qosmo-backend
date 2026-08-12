"""Sovereign mode: MyBot that depends on nobody.

The product promise is that a person can buy a MyBot and own it — not rent
access to somebody's API with a local cache in front. That promise is only real
if there is a configuration in which *nothing* leaves the machine, and if that
configuration is enforced rather than described.

The tests below check the two places a "local only" setting typically leaks:

* provider **selection** — a fallback quietly picks a cloud model when the
  local one is unavailable;
* provider **use** — some new code path calls a provider directly and skips
  whatever guard the router applies.

Both are covered, because a control with one enforcement point is one refactor
away from being decorative.
"""

from __future__ import annotations

import pytest
from mybot_llm.base import LLMProvider, LLMRequest, LLMResponse
from mybot_llm.minimizer import EgressBlocked, assert_egress_allowed
from mybot_llm.router import ModelRouter
from mybot_schemas.config import get_settings, reset_settings_cache
from mybot_schemas.enums import Classification, LLMPurpose
from mybot_security.untrusted import PromptContext


class FakeCloud(LLMProvider):
    name = "fake-cloud"
    local = False

    def available(self) -> bool:
        return True

    def model_id(self) -> str:
        return "cloud-1"

    def complete(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(text="{}", provider=self.name, model="cloud-1")


class FakeLocal(FakeCloud):
    name = "fake-local"
    local = True

    def model_id(self) -> str:
        return "local-1"


@pytest.fixture
def sovereign(monkeypatch):
    monkeypatch.setenv("MYBOT_SOVEREIGN", "true")
    reset_settings_cache()
    yield get_settings()
    reset_settings_cache()


def _request(classification=Classification.NORMAL) -> LLMRequest:
    context = PromptContext(instructions="test")
    return LLMRequest(
        purpose=LLMPurpose.CHAT, context=context, max_classification=classification
    )


# ---------------------------------------------------------------------------
# The egress guard
# ---------------------------------------------------------------------------


def test_sovereign_blocks_remote_even_for_public_data():
    """Not a classification judgement. Nothing leaves, at any sensitivity."""
    with pytest.raises(EgressBlocked) as excinfo:
        assert_egress_allowed(
            provider_is_local=False,
            payload_classification=Classification.PUBLIC,
            ceiling=Classification.HIGHLY_SENSITIVE,
            sovereign=True,
        )
    assert "sovereign" in str(excinfo.value).lower()


def test_sovereign_permits_local_at_any_classification():
    assert_egress_allowed(
        provider_is_local=True,
        payload_classification=Classification.SECRET,
        ceiling=Classification.PUBLIC,
        sovereign=True,
    )


def test_without_sovereign_the_graduated_ceiling_still_applies():
    assert_egress_allowed(
        provider_is_local=False,
        payload_classification=Classification.NORMAL,
        ceiling=Classification.PERSONAL,
        sovereign=False,
    )
    with pytest.raises(EgressBlocked):
        assert_egress_allowed(
            provider_is_local=False,
            payload_classification=Classification.SENSITIVE,
            ceiling=Classification.PERSONAL,
            sovereign=False,
        )


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------


def test_sovereign_never_selects_a_remote_provider(sovereign, monkeypatch):
    """The leak that matters: an available cloud provider being chosen because
    it was configured, with the guard left to catch it later."""
    monkeypatch.setenv("MYBOT_LLM_DEFAULT_PROVIDER", "fake-cloud")
    reset_settings_cache()

    router = ModelRouter(providers={"fake-cloud": FakeCloud()})
    chosen = router.provider_for(LLMPurpose.CHAT)

    assert chosen.local is True, "sovereign mode selected a provider that leaves the machine"
    assert chosen.name == "mock"


def test_sovereign_selects_a_local_provider_normally(sovereign, monkeypatch):
    monkeypatch.setenv("MYBOT_LLM_DEFAULT_PROVIDER", "fake-local")
    reset_settings_cache()

    router = ModelRouter(providers={"fake-local": FakeLocal()})
    assert router.provider_for(LLMPurpose.CHAT).name == "fake-local"


def test_the_fallback_provider_is_itself_local():
    """The degraded path must not be an escape hatch. If the fallback reached
    the network, every unavailable-provider event would become an egress."""
    router = ModelRouter()
    assert router.provider_for(LLMPurpose.CHAT).local is True


def test_run_refuses_a_remote_provider_under_sovereign(sovereign, db, alice, as_alice):
    """Belt and braces: even if selection is bypassed by passing a provider in
    directly, the call itself is refused."""
    router = ModelRouter(providers={"mock": FakeCloud()})
    router._fallback = FakeCloud()

    with pytest.raises(EgressBlocked):
        router.run(db, alice.id, _request())


def test_describe_reports_sovereign_and_locality(sovereign):
    router = ModelRouter()
    described = router.describe()

    assert described["_sovereign"] is True
    assert described["_fully_local"] is True
    for purpose in LLMPurpose:
        assert described[purpose.value]["local"] is True


def test_describe_reports_when_something_leaves_the_machine(monkeypatch):
    monkeypatch.setenv("MYBOT_SOVEREIGN", "false")
    monkeypatch.setenv("MYBOT_LLM_DEFAULT_PROVIDER", "fake-cloud")
    reset_settings_cache()
    try:
        router = ModelRouter(providers={"fake-cloud": FakeCloud()})
        described = router.describe()
        assert described["_sovereign"] is False
        assert described["_fully_local"] is False
    finally:
        reset_settings_cache()


def test_sovereign_defaults_off_but_is_a_one_line_change():
    """Off by default because a fresh clone has no local model and would
    otherwise appear broken. It must be trivially switchable."""
    reset_settings_cache()
    assert get_settings().sovereign is False
