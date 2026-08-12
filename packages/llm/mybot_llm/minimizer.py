"""Context minimisation and PII tokenisation.

Before anything leaves this machine, two questions get asked:

1. **Does the model actually need this field?**  A loan question needs the
   balance, the rate and the credit tier. It does not need a name, an address
   or a social security number. :class:`ContextMinimizer` enforces a per-purpose
   allowlist, so the default is exclusion rather than inclusion.

2. **Can the identifier be replaced with a placeholder?**  A model reasoning
   about a scheduling conflict works just as well with ``PERSON_001`` as with a
   real name. :class:`PiiTokenizer` substitutes deterministically and hands the
   mapping to a :class:`TokenSecretStore` for encrypted local storage, so the
   same person is the same token across calls (which preserves the model's
   ability to reason) while the mapping never leaves the machine.

There is also a hard ceiling: :func:`assert_egress_allowed` refuses to send
data above the configured classification to a non-local provider. That check
is not advisory -- it raises.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from mybot_schemas.enums import Classification, LLMPurpose
from mybot_schemas.models import PiiToken
from mybot_security.crypto import hmac_hex
from sqlalchemy.orm import Session


class EgressBlocked(PermissionError):
    """Refusal to send data outside the machine."""


#: Fields each purpose is allowed to see. Anything not listed is dropped.
#: Written as an allowlist on purpose: a denylist silently leaks every field
#: somebody forgets to add.
PURPOSE_FIELD_ALLOWLIST: dict[LLMPurpose, frozenset[str]] = {
    LLMPurpose.CLASSIFICATION: frozenset(
        {"subject", "snippet", "sender_domain", "labels", "received_at", "has_attachment"}
    ),
    LLMPurpose.EXTRACTION: frozenset(
        {"text", "document_type", "issuer", "page", "field_hints", "language"}
    ),
    LLMPurpose.REASONING: frozenset(
        {
            "event_titles", "event_times", "conflict", "obligation_titles", "due_dates",
            "amounts", "categories", "preferences", "confidence",
        }
    ),
    LLMPurpose.PLANNING: frozenset(
        {"goal", "available_actions", "constraints", "obligation_titles", "due_dates"}
    ),
    LLMPurpose.SUMMARIZATION: frozenset({"items", "counts", "period"}),
    LLMPurpose.CHAT: frozenset(
        {
            "question", "tool_results", "entity_names", "obligation_titles", "due_dates",
            "amounts", "preferences", "conversation_summary",
        }
    ),
}


@dataclass
class MinimizationResult:
    payload: dict
    dropped: list[str] = field(default_factory=list)
    max_classification: Classification = Classification.NORMAL

    def as_dict(self) -> dict:
        return {
            "kept": sorted(self.payload.keys()),
            "dropped": self.dropped,
            "max_classification": self.max_classification.value,
        }


class ContextMinimizer:
    """Drops fields a given purpose has no business seeing."""

    def minimize(
        self,
        purpose: LLMPurpose,
        payload: dict,
        *,
        classifications: dict[str, Classification] | None = None,
    ) -> MinimizationResult:
        allowed = PURPOSE_FIELD_ALLOWLIST.get(purpose, frozenset())
        classifications = classifications or {}
        kept: dict = {}
        dropped: list[str] = []
        highest = Classification.PUBLIC

        for key, value in payload.items():
            if key not in allowed:
                dropped.append(key)
                continue
            kept[key] = value
            level = classifications.get(key, Classification.NORMAL)
            if level.rank > highest.rank:
                highest = level

        return MinimizationResult(payload=kept, dropped=dropped, max_classification=highest)


def assert_egress_allowed(
    *, provider_is_local: bool, payload_classification: Classification, ceiling: Classification
) -> None:
    """Refuse to send over-classified data to a remote model.

    Local providers are exempt: the whole point of on-device inference is that
    sensitive context can be used without leaving the house.
    """
    if provider_is_local:
        return
    if payload_classification.rank > ceiling.rank:
        raise EgressBlocked(
            f"refusing to send {payload_classification.value} data to a non-local model "
            f"(ceiling is {ceiling.value}); use a local model or reduce the context"
        )


# ---------------------------------------------------------------------------
# PII tokenisation
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE_RE = re.compile(r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")
_ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+[A-Z][a-zA-Z]*(?:\s+[A-Z][a-zA-Z]*)*\s+"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b"
)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


@runtime_checkable
class TokenSecretStore(Protocol):
    """The narrow slice of secret storage the tokenizer needs.

    Deliberately *not* the Vault. This package must not be able to reach key
    material or credential storage -- that is Rule 1, and a security test
    asserts that no module under ``mybot_llm`` imports the Vault. Declaring the
    dependency as a protocol this package owns means the arrow points inward:
    the API layer passes an adapter, and the tokenizer can do exactly two
    things -- derive its lookup key and hand a value to be stored -- and
    nothing else.

    Note there is no ``read`` method. The tokenizer writes the mapping and
    never needs it back; de-tokenisation uses the in-memory map from the same
    request.
    """

    def pii_lookup_key(self) -> bytes:
        """Return the keyed-hash key for the token index."""
        ...

    def store_pii_value(self, session: Session, owner_id: str, ref: str, value: str) -> None:
        """Persist a real identifier under ``ref``, encrypted."""
        ...


@dataclass
class TokenizationResult:
    text: str
    mapping: dict[str, str]
    replaced: int = 0


class PiiTokenizer:
    """Deterministic, per-owner substitution of identifiers with placeholders.

    Stable across calls -- the same address is always ``HOME_PRIMARY`` for this
    owner -- because a model that sees a new random token every turn cannot
    reason about continuity. Stability comes from a keyed hash of the value, so
    the index itself does not store a searchable plaintext.
    """

    CATEGORY_PREFIX = {
        "person": "PERSON",
        "email": "EMAIL",
        "phone": "PHONE",
        "address": "ADDRESS",
        "org": "ORG",
        "ssn": "GOVID",
        "account": "ACCOUNT",
    }

    def __init__(self, session: Session, store: TokenSecretStore, owner_id: str):
        self.session = session
        self.store = store
        self.owner_id = owner_id
        self._lookup_key = store.pii_lookup_key()

    def _token_for(self, value: str, category: str) -> str:
        value_hash = hmac_hex(self._lookup_key, f"{category}|{value.strip().lower()}")
        existing = self.session.execute(
            sa.select(PiiToken).where(
                PiiToken.owner_id == self.owner_id, PiiToken.value_hash == value_hash
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing.token

        prefix = self.CATEGORY_PREFIX.get(category, "VALUE")
        count = self.session.execute(
            sa.select(sa.func.count())
            .select_from(PiiToken)
            .where(PiiToken.owner_id == self.owner_id, PiiToken.category == category)
        ).scalar_one()
        token = f"{prefix}_{count + 1:03d}"

        ref = f"pii:{self.owner_id}:{token}"
        self.store.store_pii_value(self.session, self.owner_id, ref, value)
        self.session.add(
            PiiToken(
                owner_id=self.owner_id,
                token=token,
                category=category,
                value_hash=value_hash,
                value_ref=ref,
            )
        )
        self.session.flush()
        return token

    def tokenize(self, text: str, *, known_names: list[str] | None = None) -> TokenizationResult:
        """Replace identifiers with stable placeholders."""
        mapping: dict[str, str] = {}
        result = text or ""

        # Names first: they are the most identifying and the least
        # pattern-detectable, so they come from the Life Graph rather than a
        # regex. Longest first so "Alex Morgan" wins over "Alex".
        for name in sorted(known_names or [], key=len, reverse=True):
            if len(name) < 3 or name.lower() not in result.lower():
                continue
            token = self._token_for(name, "person")
            mapping[token] = name
            result = re.sub(re.escape(name), token, result, flags=re.IGNORECASE)

        for pattern, category in (
            (_SSN_RE, "ssn"),
            (_EMAIL_RE, "email"),
            (_PHONE_RE, "phone"),
            (_ADDRESS_RE, "address"),
        ):
            for match in set(pattern.findall(result)):
                value = match if isinstance(match, str) else match[0]
                token = self._token_for(value, category)
                mapping[token] = value
                result = result.replace(value, token)

        return TokenizationResult(text=result, mapping=mapping, replaced=len(mapping))

    def detokenize(self, text: str, mapping: dict[str, str]) -> str:
        """Put the real values back, locally, after the model has answered."""
        out = text or ""
        for token, value in sorted(mapping.items(), key=lambda kv: len(kv[0]), reverse=True):
            out = out.replace(token, value)
        return out


__all__ = [
    "ContextMinimizer",
    "TokenSecretStore",
    "EgressBlocked",
    "MinimizationResult",
    "PURPOSE_FIELD_ALLOWLIST",
    "PiiTokenizer",
    "TokenizationResult",
    "assert_egress_allowed",
]
