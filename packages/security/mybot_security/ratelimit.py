"""Rate limiting and brute-force protection.

Closes a gap this build previously documented as a known weakness: failed
logins were recorded but not throttled, so nothing stood between an attacker
and an unlimited password-guessing loop.

Three deliberate design points:

**Cost-shaped, not uniform.** A read of the Life Inbox and an attempt to sign
in are not the same event. Limits are attached to *what an endpoint costs to
abuse* — cheap for reads, tight for authentication, tighter still for
second-factor verification, which is a six-digit space and therefore the
easiest thing in the system to brute force.

**Keyed by identity where possible, by network otherwise.** An authenticated
caller is limited per owner, so one person hammering the API cannot deny
service to anyone else. Unauthenticated calls fall back to a hashed client
address — hashed, because a rate limiter should not quietly become a table of
who connected from where.

**In-process by default, with an interface for Redis.** MyBot Core is a
single-node appliance where an in-process limiter is exactly right and a Redis
dependency would be absurd. A multi-node deployment needs shared state, so the
store is an interface with an obvious second implementation.

Failing *open* is the deliberate choice here, and it is the opposite of the
rule everywhere else in MyBot. A rate limiter is an availability control, not
an authorization control: if it breaks, the correct behaviour is to let the
request through and let the real authorization checks do their job, rather than
locking the owner out of their own life. Nothing security-critical depends on
it.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .crypto import sha256_hex


@dataclass(frozen=True)
class RateLimit:
    """A token bucket: ``capacity`` requests, refilled over ``per_seconds``."""

    capacity: int
    per_seconds: float
    #: Human sentence shown to the user when they hit it.
    message: str = "Too many requests. Please wait a moment."

    @property
    def refill_per_second(self) -> float:
        return self.capacity / self.per_seconds


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: float
    limit: RateLimit


#: Named limits. Tuned so a person using the product normally never sees one,
#: and an automated attempt hits a wall almost immediately.
LIMITS: dict[str, RateLimit] = {
    # Five attempts, then roughly one more every twelve seconds. A human who
    # mistyped their password twice notices nothing.
    "auth.login": RateLimit(
        capacity=5,
        per_seconds=60,
        message="Too many sign-in attempts. Wait a minute and try again.",
    ),
    # A six-digit code is a million possibilities; without a limit an attacker
    # walks it in minutes. This makes that take years.
    "auth.elevate": RateLimit(
        capacity=5,
        per_seconds=300,
        message="Too many verification attempts. Wait five minutes before trying again.",
    ),
    "auth.register": RateLimit(
        capacity=3,
        per_seconds=3600,
        message="Too many accounts created from this network.",
    ),
    # Expensive: syncs connectors, runs the proactive engine, may call a model.
    "chat": RateLimit(
        capacity=20,
        per_seconds=60,
        message="You're asking faster than MyBot can think. Give it a second.",
    ),
    "documents.upload": RateLimit(
        capacity=30,
        per_seconds=300,
        message="Too many uploads at once.",
    ),
    # Creating a proposal is cheap, but a flood of them is a good way to bury a
    # real one in the approval queue.
    "actions.propose": RateLimit(
        capacity=30,
        per_seconds=60,
        message="Too many actions proposed at once.",
    ),
    # Ordinary reads. Generous — this exists to stop a runaway client, not to
    # ration normal use.
    "read": RateLimit(capacity=300, per_seconds=60),
}


class RateLimitStore(ABC):
    """Where bucket state lives."""

    @abstractmethod
    def consume(self, key: str, limit: RateLimit, cost: float = 1.0) -> RateLimitResult:
        ...

    @abstractmethod
    def reset(self, key: str) -> None:
        """Clear a bucket. Called after a *successful* login, so one bad
        password does not eat into an honest person's allowance."""


class InMemoryRateLimitStore(RateLimitStore):
    """Token buckets in process memory.

    Correct for the single-node Core. Thread-safe, and prunes idle buckets so a
    long-running process does not accumulate one entry per address that ever
    touched it — which would be both a leak and a slow memory exhaustion.
    """

    #: Buckets untouched for this long are dropped.
    IDLE_EVICTION_SECONDS = 3600
    #: Hard ceiling on tracked buckets, so a spray of distinct keys cannot
    #: exhaust memory. Oldest are evicted first.
    MAX_BUCKETS = 50_000

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        #: key -> (tokens, last_refill_at)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._last_prune = clock()

    def consume(self, key: str, limit: RateLimit, cost: float = 1.0) -> RateLimitResult:
        now = self._clock()
        with self._lock:
            self._maybe_prune(now)
            tokens, last = self._buckets.get(key, (float(limit.capacity), now))
            tokens = min(
                float(limit.capacity), tokens + (now - last) * limit.refill_per_second
            )

            if tokens >= cost:
                self._buckets[key] = (tokens - cost, now)
                return RateLimitResult(
                    allowed=True,
                    remaining=int(tokens - cost),
                    retry_after_seconds=0.0,
                    limit=limit,
                )

            self._buckets[key] = (tokens, now)
            deficit = cost - tokens
            return RateLimitResult(
                allowed=False,
                remaining=0,
                retry_after_seconds=round(deficit / limit.refill_per_second, 1),
                limit=limit,
            )

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def _maybe_prune(self, now: float) -> None:
        if now - self._last_prune < 60 and len(self._buckets) < self.MAX_BUCKETS:
            return
        self._last_prune = now
        cutoff = now - self.IDLE_EVICTION_SECONDS
        self._buckets = {k: v for k, v in self._buckets.items() if v[1] > cutoff}
        if len(self._buckets) >= self.MAX_BUCKETS:
            # Keep the most recently active half.
            ordered = sorted(self._buckets.items(), key=lambda kv: kv[1][1], reverse=True)
            self._buckets = dict(ordered[: self.MAX_BUCKETS // 2])


class RateLimiter:
    """Front door for the limits."""

    def __init__(self, store: RateLimitStore | None = None, *, enabled: bool = True):
        self.store = store or InMemoryRateLimitStore()
        self.enabled = enabled

    @staticmethod
    def key_for(bucket: str, *, owner_id: str | None = None, client_ip: str | None = None,
                identifier: str | None = None) -> str:
        """Build a bucket key.

        Prefers the owner id, then a supplied identifier (an email being tried
        at the login endpoint), then a hash of the client address. Addresses are
        hashed so the limiter does not become a log of who connected from where.
        """
        if owner_id:
            return f"{bucket}|owner:{owner_id}"
        if identifier:
            return f"{bucket}|id:{sha256_hex(identifier.lower())[:24]}"
        if client_ip:
            return f"{bucket}|net:{sha256_hex(f'mybot-rl|{client_ip}')[:24]}"
        return f"{bucket}|anonymous"

    def check(
        self,
        bucket: str,
        *,
        owner_id: str | None = None,
        client_ip: str | None = None,
        identifier: str | None = None,
        cost: float = 1.0,
    ) -> RateLimitResult:
        limit = LIMITS.get(bucket, LIMITS["read"])
        if not self.enabled:
            return RateLimitResult(True, limit.capacity, 0.0, limit)
        key = self.key_for(bucket, owner_id=owner_id, client_ip=client_ip, identifier=identifier)
        try:
            return self.store.consume(key, limit, cost)
        except Exception:  # noqa: BLE001
            # Availability control, not an authorization control. If it breaks,
            # let the request through -- the real checks still apply.
            return RateLimitResult(True, limit.capacity, 0.0, limit)

    def clear(
        self,
        bucket: str,
        *,
        owner_id: str | None = None,
        client_ip: str | None = None,
        identifier: str | None = None,
    ) -> None:
        try:
            self.store.reset(
                self.key_for(
                    bucket, owner_id=owner_id, client_ip=client_ip, identifier=identifier
                )
            )
        except Exception:  # noqa: BLE001
            pass


__all__ = [
    "InMemoryRateLimitStore",
    "LIMITS",
    "RateLimit",
    "RateLimitResult",
    "RateLimitStore",
    "RateLimiter",
]
