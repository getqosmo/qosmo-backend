"""The one-way valve between deciding and learning.

The Action Firewall must be able to *tell* the learning system what happened —
that is where the highest-quality signal in MyBot lives, because an approval or
a rejection is an unambiguous statement of intent by the owner.

What the firewall must never be able to do is *ask* the learning system
anything. The moment authority code can read learned state, someone will
eventually write ``if learned.confidence > 0.9: skip_approval()``, and it will
look reasonable in the diff.

So the firewall depends on this Protocol, which has exactly one method and no
way to return learned state. It is the same technique that keeps ``mybot_llm``
unable to import the Vault: make the wrong thing unexpressible rather than
forbidden.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mybot_security.logging import get_logger

log = get_logger(__name__)


@runtime_checkable
class ObservationSink(Protocol):
    """Somewhere to report what the owner did. Write-only, by construction."""

    def observe(
        self,
        owner_id: str,
        *,
        kind: str,
        subject: str,
        value: dict | None = ...,
        agrees: bool = ...,
        evidence_ref: str | None = ...,
        explanation: str | None = ...,
        untrusted: bool = ...,
        now=...,
    ): ...


class NullObservationSink:
    """Discards observations.

    The default. A MyBot with learning switched off must behave identically to
    one with learning switched on but no history — never worse, never with a
    different code path through the firewall.
    """

    def observe(self, owner_id: str, **_kwargs) -> None:
        return None


def safely_observe(sink, owner_id: str, **kwargs) -> None:
    """Report an observation, swallowing anything that goes wrong.

    Learning is an enhancement. A failure to record that somebody approved
    something must never turn into a failure to approve it — the action already
    happened, and raising here would roll back a transaction that contains a
    real decision and its audit event.

    Logged rather than silent, because a sink that has been broken for a month
    should be discoverable without noticing the absence of learning.
    """
    if sink is None:
        return
    try:
        sink.observe(owner_id, **kwargs)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "learning.observation_failed",
            error=type(exc).__name__,
            kind=kwargs.get("kind"),
        )


__all__ = ["NullObservationSink", "ObservationSink", "safely_observe"]
