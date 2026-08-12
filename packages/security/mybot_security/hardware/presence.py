"""Hardware-adjacent abstractions that the MyBot Core will implement for real.

Three interfaces, each with a software stand-in that is *labelled as a
simulation everywhere it surfaces*.  The Security Center shows the backend
name, so a user on the development build can see that "physical presence" is
being simulated rather than being told a comforting lie.
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class PresenceProof:
    """Evidence that a human was physically at the device."""

    granted: bool
    method: str
    device_id: str | None
    at: dt.datetime
    simulated: bool
    detail: str | None = None


class PhysicalPresenceProvider(ABC):
    """Proof that a person is standing in front of the machine.

    Gates CRITICAL actions.  On the Core this is a physical button wired to
    the secure element; a remote attacker with full software control still
    cannot press it.
    """

    @abstractmethod
    def request_presence(self, owner_id: str, device_id: str | None, purpose: str) -> PresenceProof:
        ...

    @property
    @abstractmethod
    def simulated(self) -> bool:
        ...


class SimulatedPresenceProvider(PhysicalPresenceProvider):
    """Development stand-in.

    Grants presence only for a device explicitly registered as capable of it,
    so the *shape* of the check is exercised in development even though the
    proof itself is not real.
    """

    def __init__(self, capable_device_ids: set[str] | None = None):
        self._capable = capable_device_ids or set()

    def register_capable_device(self, device_id: str) -> None:
        self._capable.add(device_id)

    def request_presence(self, owner_id: str, device_id: str | None, purpose: str) -> PresenceProof:
        granted = device_id is not None and device_id in self._capable
        return PresenceProof(
            granted=granted,
            method="simulated_button",
            device_id=device_id,
            at=dt.datetime.now(dt.UTC),
            simulated=True,
            detail=(
                "Simulated physical presence (development build). "
                "No hardware root of trust is involved."
            ),
        )

    @property
    def simulated(self) -> bool:
        return True


@dataclass(frozen=True)
class AttestationResult:
    trusted: bool
    device_kind: str
    simulated: bool
    claims: dict


class DeviceAttestationProvider(ABC):
    """Answers "is this device what it claims to be?"."""

    @abstractmethod
    def attest(self, device_id: str, evidence: dict | None) -> AttestationResult:
        ...


class SimulatedAttestationProvider(DeviceAttestationProvider):
    """Development stand-in: trusts nothing by default.

    Returns ``trusted=False`` unless the device was explicitly marked trusted
    through the Security Center, so the default posture in development matches
    the default posture on real hardware.
    """

    def __init__(self, trusted_device_ids: set[str] | None = None):
        self._trusted = trusted_device_ids or set()

    def trust(self, device_id: str) -> None:
        self._trusted.add(device_id)

    def attest(self, device_id: str, evidence: dict | None) -> AttestationResult:
        return AttestationResult(
            trusted=device_id in self._trusted,
            device_kind="simulated",
            simulated=True,
            claims={"note": "no hardware attestation available in this build"},
        )


class LocalModelRuntime(ABC):
    """Inference that never leaves the house.

    Declared here alongside the other hardware interfaces because on the Core
    it *is* hardware -- the NPU is what makes keeping HIGHLY_SENSITIVE context
    local practical rather than aspirational.
    """

    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def describe(self) -> dict:
        ...


class NullLocalModelRuntime(LocalModelRuntime):
    """No local inference in this build.

    Reports unavailable rather than silently forwarding to a cloud model --
    the whole point of asking is to decide whether sensitive context can be
    used at all.
    """

    def available(self) -> bool:
        return False

    def describe(self) -> dict:
        return {
            "available": False,
            "reason": "no local model runtime configured",
            "roadmap": "MyBot Core ships with on-device inference; see docs/ROADMAP.md",
        }


__all__ = [
    "AttestationResult",
    "DeviceAttestationProvider",
    "LocalModelRuntime",
    "NullLocalModelRuntime",
    "PhysicalPresenceProvider",
    "PresenceProof",
    "SimulatedAttestationProvider",
    "SimulatedPresenceProvider",
]
