"""Model provider contract.

MyBot must not be architecturally married to one vendor -- partly for
commercial reasons, mostly because the endgame is a local model on the Core
that never sends anything anywhere. So every provider implements the same
narrow interface, and the rest of the system only ever talks to that.

Two properties every provider must honour:

* **Structured output is validated.** :meth:`LLMProvider.complete_structured`
  returns a parsed, schema-conformant object or raises. Nothing downstream
  parses prose to decide anything.
* **Prompts are assembled, not concatenated.** Requests carry a
  :class:`PromptContext`, so the trust boundary between MyBot's instructions
  and third-party content survives all the way to the provider call.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from mybot_schemas.enums import Classification, LLMPurpose
from mybot_security.untrusted import PromptContext
from pydantic import BaseModel, ValidationError


class LLMError(RuntimeError):
    pass


class LLMUnavailable(LLMError):
    """Provider not configured or unreachable.

    Callers must degrade -- fall back to deterministic behaviour, or tell the
    user a feature is unavailable. Never silently produce a worse answer while
    implying it is a good one.
    """


class SchemaViolation(LLMError):
    """The model returned something that does not fit the required schema.

    Always a hard failure. A malformed structured output is discarded, never
    coerced or partially salvaged.
    """


@dataclass
class LLMRequest:
    purpose: LLMPurpose
    context: PromptContext
    max_tokens: int = 1024
    temperature: float = 0.0
    #: Highest classification present in the payload, after minimisation.
    max_classification: Classification = Classification.NORMAL
    #: True when PII placeholders were substituted before the call.
    tokenized: bool = False
    request_id: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int | None = None
    raw: dict = field(default_factory=dict)


class LLMProvider(ABC):
    name: str = "unset"
    #: True when inference happens on this machine. Determines whether
    #: sensitive context may be included at all.
    local: bool = False

    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResponse:
        ...

    @abstractmethod
    def available(self) -> bool:
        ...

    def model_id(self) -> str:
        return "unknown"

    def complete_structured(
        self, request: LLMRequest, schema: type[BaseModel], *, retries: int = 1
    ) -> BaseModel:
        """Call the model and validate the result against ``schema``.

        One retry with an explicit correction, then failure. Retrying forever
        against a model that cannot produce the shape wastes tokens and delays
        the fallback the caller needs to take anyway.
        """
        instruction = _schema_instruction(schema)
        attempt_context = request.context
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            enriched = LLMRequest(
                purpose=request.purpose,
                context=_with_instruction(attempt_context, instruction, attempt, last_error),
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                max_classification=request.max_classification,
                tokenized=request.tokenized,
                request_id=request.request_id,
                metadata=request.metadata,
            )
            response = self.complete(enriched)
            try:
                return schema.model_validate_json(_extract_json(response.text))
            except (ValidationError, ValueError) as exc:
                last_error = exc

        raise SchemaViolation(
            f"model output did not match {schema.__name__} after {retries + 1} attempts: "
            f"{type(last_error).__name__}"
        )


def _schema_instruction(schema: type[BaseModel]) -> str:
    import json

    return (
        "Respond with a single JSON object and nothing else. No prose, no code fence.\n"
        "It must validate against this JSON Schema:\n"
        + json.dumps(schema.model_json_schema(), indent=2)
    )


def _with_instruction(
    context: PromptContext, instruction: str, attempt: int, last_error: Exception | None
) -> PromptContext:
    new = PromptContext(
        instructions=context.instructions,
        trusted_data=list(context.trusted_data),
        untrusted=list(context.untrusted),
    )
    new.trusted_data.append(instruction)
    if attempt > 0 and last_error is not None:
        new.trusted_data.append(
            "Your previous response was rejected because it did not match the schema. "
            "Return only the JSON object."
        )
    return new


def _extract_json(text: str) -> str:
    """Pull a JSON object out of a response that may be wrapped in prose.

    Tolerant of code fences and leading chatter, but does not attempt to repair
    malformed JSON -- a broken structure means the call failed.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("```", 2)[1]
        if stripped.startswith("json"):
            stripped = stripped[4:]
        stripped = stripped.rsplit("```", 1)[0]
    stripped = stripped.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return stripped
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        return stripped[start : end + 1]
    raise ValueError("no JSON object found in model output")


class TimedCall:
    """Small helper so every provider reports latency the same way."""

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc):
        self.elapsed_ms = int((time.perf_counter() - self._start) * 1000)
        return False


__all__ = [
    "LLMError",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "LLMUnavailable",
    "SchemaViolation",
    "TimedCall",
]
