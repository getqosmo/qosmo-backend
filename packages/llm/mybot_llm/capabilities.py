"""Recorded conformance results, and routing that respects them.

Running ``mybot model-check --apply`` writes what a provider was *measured* to
do into ``data_dir/model_capabilities.json``. The router reads it and refuses to
send a purpose to a provider that failed the probes gating it.

Without this, a conformance report is a document somebody reads once. With it,
discovering that your local 3B model fabricates phone numbers actually stops it
from answering questions about your life — which is the only outcome that
matters.

## The direction of the file is deliberately one-way

The registry can only **narrow** what a provider is used for. It has no way to
declare a provider capable, to raise the egress ceiling, to disable sovereign
mode, or to affect anything outside purpose routing. A corrupted or hostile
capability file can therefore degrade MyBot to the deterministic paths and the
mock provider — annoying, and the safe direction. It cannot cause a model to be
trusted with something it failed.

That asymmetry is why this is a plain JSON file rather than something signed:
the worst it can do is make MyBot more cautious.

## Staleness is reported, not enforced

A record for a model you have since replaced is misleading, so entries carry
the model id and a timestamp, and the Security Center shows how old they are.
They are not auto-expired: silently re-enabling a purpose because a measurement
got old would be exactly the wrong default.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from mybot_schemas.enums import LLMPurpose
from mybot_security.logging import get_logger

log = get_logger(__name__)

CAPABILITIES_FILENAME = "model_capabilities.json"
CAPABILITIES_FORMAT = "mybot-model-capabilities-v1"


@dataclass
class CapabilityRecord:
    provider: str
    model: str
    usable_purposes: tuple[str, ...]
    checked_at: str
    #: Why each unusable purpose was ruled out, so the Security Center can say
    #: "chat is unavailable on this model because it fabricated a phone number"
    #: rather than only that it is unavailable.
    reasons: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "usable_purposes": list(self.usable_purposes),
            "checked_at": self.checked_at,
            "reasons": self.reasons,
        }

    def age_days(self, now: dt.datetime | None = None) -> int | None:
        """How stale this measurement is, or None if it cannot be read."""
        try:
            checked = dt.datetime.fromisoformat(self.checked_at)
        except (TypeError, ValueError):
            return None
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=dt.UTC)
        return max(((now or dt.datetime.now(dt.UTC)) - checked).days, 0)


class CapabilityRegistry:
    """What each provider has been measured to handle."""

    def __init__(self, records: dict[str, CapabilityRecord] | None = None):
        self._records: dict[str, CapabilityRecord] = records or {}

    # -- loading and saving ---------------------------------------------

    @classmethod
    def load(cls, data_dir: Path | str) -> CapabilityRegistry:
        """Read the file, tolerating its absence and its corruption.

        A missing file is the normal case — nobody has run the check yet — and
        means "no restrictions recorded". A malformed one is logged and treated
        the same way rather than crashing MyBot on boot, because the file is an
        optimisation over the truth, not the truth.
        """
        path = Path(data_dir) / CAPABILITIES_FILENAME
        if not path.exists():
            return cls()
        try:
            payload = json.loads(path.read_text())
            if payload.get("format") != CAPABILITIES_FORMAT:
                log.warning("capabilities.unknown_format", format=payload.get("format"))
                return cls()
            records = {}
            for raw in payload.get("providers", []):
                record = CapabilityRecord(
                    provider=raw["provider"],
                    model=raw.get("model", "unknown"),
                    usable_purposes=tuple(raw.get("usable_purposes", [])),
                    checked_at=raw.get("checked_at", ""),
                    reasons=raw.get("reasons", {}),
                )
                records[record.provider] = record
            return cls(records)
        except (json.JSONDecodeError, KeyError, TypeError, OSError) as exc:
            log.warning("capabilities.unreadable", error=type(exc).__name__)
            return cls()

    def save(self, data_dir: Path | str) -> Path:
        path = Path(data_dir) / CAPABILITIES_FILENAME
        payload = {
            "format": CAPABILITIES_FORMAT,
            "note": (
                "Written by `mybot model-check --apply`. This file can only "
                "narrow which purposes a provider is used for; it cannot grant "
                "a capability or affect egress rules."
            ),
            "providers": [r.as_dict() for r in self._records.values()],
        }
        path.write_text(json.dumps(payload, indent=2))
        path.chmod(0o600)
        return path

    # -- use -------------------------------------------------------------

    def record(self, report) -> CapabilityRecord:
        """Store a conformance report's conclusions."""
        entry = CapabilityRecord(
            provider=report.provider,
            model=report.model,
            usable_purposes=tuple(p.value for p in report.usable_purposes),
            checked_at=dt.datetime.now(dt.UTC).isoformat(),
            reasons={
                p.value: report.reasons_for(p)
                for p in LLMPurpose
                if p not in report.usable_purposes
            },
        )
        self._records[report.provider] = entry
        return entry

    def permits(self, provider_name: str, purpose: LLMPurpose) -> bool:
        """May this provider be used for this purpose?

        Unknown providers are permitted. Absence of a measurement is not
        evidence of failure, and refusing everything unmeasured would mean a
        fresh install could not use a model at all.
        """
        record = self._records.get(provider_name)
        if record is None:
            return True
        return purpose.value in record.usable_purposes

    def reasons(self, provider_name: str, purpose: LLMPurpose) -> list[str]:
        record = self._records.get(provider_name)
        if record is None:
            return []
        return list(record.reasons.get(purpose.value, []))

    def get(self, provider_name: str) -> CapabilityRecord | None:
        return self._records.get(provider_name)

    def describe(self) -> dict:
        now = dt.datetime.now(dt.UTC)
        out = {}
        for name, record in self._records.items():
            entry = record.as_dict()
            entry["age_days"] = record.age_days(now)
            out[name] = entry
        return out

    def __bool__(self) -> bool:
        return bool(self._records)


__all__ = [
    "CAPABILITIES_FILENAME",
    "CAPABILITIES_FORMAT",
    "CapabilityRecord",
    "CapabilityRegistry",
]
