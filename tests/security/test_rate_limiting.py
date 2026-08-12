"""Rate limiting and brute-force protection.

Closes a gap earlier builds documented as a known weakness: failed logins were
recorded but not throttled.
"""

from __future__ import annotations

import pytest
from mybot_security.ratelimit import (
    LIMITS,
    InMemoryRateLimitStore,
    RateLimit,
    RateLimiter,
)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


def test_bucket_allows_up_to_capacity_then_refuses():
    clock = FakeClock()
    limiter = RateLimiter(InMemoryRateLimitStore(clock=clock))
    limit = RateLimit(capacity=3, per_seconds=60)
    LIMITS["test.bucket"] = limit

    results = [limiter.check("test.bucket", client_ip="1.2.3.4") for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[-1].retry_after_seconds > 0


def test_bucket_refills_over_time():
    clock = FakeClock()
    limiter = RateLimiter(InMemoryRateLimitStore(clock=clock))
    LIMITS["test.refill"] = RateLimit(capacity=2, per_seconds=60)

    assert limiter.check("test.refill", client_ip="1.2.3.4").allowed
    assert limiter.check("test.refill", client_ip="1.2.3.4").allowed
    assert not limiter.check("test.refill", client_ip="1.2.3.4").allowed

    clock.advance(31)  # half the window -> one token back
    assert limiter.check("test.refill", client_ip="1.2.3.4").allowed


def test_buckets_are_isolated_per_key():
    """One caller exhausting their allowance must not affect anybody else."""
    limiter = RateLimiter(InMemoryRateLimitStore())
    LIMITS["test.isolated"] = RateLimit(capacity=1, per_seconds=60)

    assert limiter.check("test.isolated", owner_id="alice").allowed
    assert not limiter.check("test.isolated", owner_id="alice").allowed
    assert limiter.check("test.isolated", owner_id="bob").allowed


def test_client_addresses_are_not_stored_in_the_clear():
    """A rate limiter must not become a record of who connected from where."""
    store = InMemoryRateLimitStore()
    limiter = RateLimiter(store)
    limiter.check("read", client_ip="203.0.113.42")
    assert all("203.0.113.42" not in key for key in store._buckets)


def test_limiter_fails_open_when_the_store_breaks():
    """An availability control must not become an outage."""

    class Broken(InMemoryRateLimitStore):
        def consume(self, key, limit, cost=1.0):
            raise RuntimeError("store is down")

    assert RateLimiter(Broken()).check("auth.login", client_ip="1.2.3.4").allowed


def test_idle_buckets_are_evicted():
    """A spray of distinct keys must not exhaust memory."""
    clock = FakeClock()
    store = InMemoryRateLimitStore(clock=clock)
    for index in range(200):
        store.consume(f"k{index}", LIMITS["read"])
    assert len(store._buckets) == 200

    clock.advance(store.IDLE_EVICTION_SECONDS + 120)
    store.consume("fresh", LIMITS["read"])
    assert len(store._buckets) == 1


# ---------------------------------------------------------------------------
# Through the API
# ---------------------------------------------------------------------------


@pytest.fixture
def throttled(monkeypatch):
    """Enable the limiter, which the test profile disables by default.

    Substitutes the accessor rather than the cached instance, which is why
    every call site resolves the limiter through ``get_rate_limiter()``.
    """
    from mybot_api import deps

    limiter = RateLimiter(InMemoryRateLimitStore(), enabled=True)
    monkeypatch.setattr(deps, "get_rate_limiter", lambda: limiter)
    return limiter


def test_login_brute_force_is_throttled(api, registered, throttled):
    registered("brute@example.com", "Target")

    statuses = [
        api.post(
            "/api/v1/auth/login",
            json={"email": "brute@example.com", "password": f"wrong-guess-{i}"},
        ).status_code
        for i in range(10)
    ]
    assert 429 in statuses, "password guessing was not throttled"
    assert statuses.count(401) <= LIMITS["auth.login"].capacity


def test_throttled_response_tells_the_client_when_to_retry(api, registered, throttled):
    registered("retry@example.com", "Target")
    response = None
    for _ in range(10):
        response = api.post(
            "/api/v1/auth/login",
            json={"email": "retry@example.com", "password": "wrong"},
        )
        if response.status_code == 429:
            break
    assert response is not None and response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1
    # A message written for a person, not a log line.
    assert "try again" in response.json()["detail"].lower()


def test_a_correct_password_clears_the_throttle(api, registered, throttled):
    from tests.conftest import TEST_PASSWORD

    registered("clears@example.com", "Target")
    for _ in range(3):
        api.post(
            "/api/v1/auth/login",
            json={"email": "clears@example.com", "password": "wrong"},
        )

    good = api.post(
        "/api/v1/auth/login",
        json={"email": "clears@example.com", "password": TEST_PASSWORD},
    )
    assert good.status_code == 200

    # The allowance is back: several more wrong guesses are still accepted as
    # 401 rather than immediately throttled.
    after = [
        api.post(
            "/api/v1/auth/login",
            json={"email": "clears@example.com", "password": "wrong"},
        ).status_code
        for _ in range(3)
    ]
    assert after.count(401) == 3


def test_second_factor_guessing_is_throttled(api, registered, elevate, throttled):
    """The tightest limit: a six-digit code is a small space."""
    account = registered("totp@example.com", "Target")

    statuses = [
        api.post(
            "/api/v1/auth/elevate",
            json={"code": f"{i:06d}"},
            headers=account["headers"],
        ).status_code
        for i in range(10)
    ]
    assert 429 in statuses
    assert statuses.count(401) <= LIMITS["auth.elevate"].capacity

    # Still BASIC -- no code was guessed.
    assert api.get("/api/v1/auth/me", headers=account["headers"]).json()["auth_level"] == "BASIC"


def test_per_identity_buckets_are_independent(throttled):
    """Guessing at one account does not consume another account's allowance.

    Asserted against the limiter directly rather than over HTTP, because login
    is limited by *both* identity and network: two people behind one address do
    share the network bucket. That is a deliberate trade -- a per-address limit
    is the only thing available before the caller has proven who they are --
    and it is stated in SECURITY.md rather than papered over here.
    """
    for _ in range(LIMITS["auth.login"].capacity):
        assert throttled.check("auth.login", identifier="noisy@example.com").allowed
    assert not throttled.check("auth.login", identifier="noisy@example.com").allowed

    assert throttled.check("auth.login", identifier="quiet@example.com").allowed


def test_authenticated_limits_are_per_owner(throttled):
    """Once identity is known, one owner cannot deny service to another."""
    for _ in range(LIMITS["chat"].capacity):
        assert throttled.check("chat", owner_id="alice").allowed
    assert not throttled.check("chat", owner_id="alice").allowed
    assert throttled.check("chat", owner_id="bob").allowed


def test_chat_is_rate_limited(api, registered, throttled):
    account = registered("chatty@example.com", "Chatty")
    statuses = [
        api.post("/api/v1/chat", json={"message": "hello"}, headers=account["headers"]).status_code
        for _ in range(LIMITS["chat"].capacity + 3)
    ]
    assert 429 in statuses
