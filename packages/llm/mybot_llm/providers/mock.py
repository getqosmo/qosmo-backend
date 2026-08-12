"""The mock provider.

Not a toy. This is the default provider, and it is what makes `mybot demo`
work with no API key, no network and no cost -- which in turn is what lets the
security tests exercise the *whole* pipeline, including the reasoning layer,
deterministically.

It is intentionally rule-based and boring. It answers structured requests by
constructing a valid object for the requested schema, and it answers chat by
composing a reply from the tool results it was given. It never invents a fact
that was not in its input, which makes it a useful adversarial baseline: if
the grounding tests pass with the mock, the grounding logic is doing the work
rather than a capable model papering over it.

It also deliberately *ignores* instructions found inside untrusted blocks --
so the injection tests assert real behaviour rather than a model's goodwill.
"""

from __future__ import annotations

import json
import re

from mybot_schemas.enums import LLMPurpose
from pydantic import BaseModel

from ..base import LLMProvider, LLMRequest, LLMResponse, TimedCall


class MockProvider(LLMProvider):
    name = "mock"
    #: Runs in-process, so nothing leaves the machine.
    local = True

    def available(self) -> bool:
        return True

    def model_id(self) -> str:
        return "mybot-mock-v1"

    def complete(self, request: LLMRequest) -> LLMResponse:
        with TimedCall() as timer:
            text = self._respond(request)
        return LLMResponse(
            text=text,
            provider=self.name,
            model=self.model_id(),
            prompt_tokens=_estimate_tokens(request.context.render_user()),
            completion_tokens=_estimate_tokens(text),
            latency_ms=timer.elapsed_ms,
        )

    def complete_structured(
        self, request: LLMRequest, schema: type[BaseModel], *, retries: int = 1
    ) -> BaseModel:
        """Construct a schema-valid object directly.

        Bypasses the JSON round-trip so tests exercise downstream validation
        rather than the mock's ability to format JSON.
        """
        return schema.model_validate(_synthesize(schema, request))

    # -- internals -------------------------------------------------------

    def _respond(self, request: LLMRequest) -> str:
        user_text = request.context.render_user()

        # Untrusted content is visible but carries no authority here. The mock
        # reports attempts rather than obeying them, which is exactly the
        # behaviour the architecture guarantees regardless of the model.
        if request.context.has_untrusted:
            scan = request.context.injection_scan()
            if scan.suspected:
                return (
                    "One of the sources contains text written to look like an instruction "
                    f"({scan.summary}). I treated it as data and did not act on it."
                )

        if request.purpose == LLMPurpose.SUMMARIZATION:
            return _summarize(user_text)
        if request.purpose == LLMPurpose.CLASSIFICATION:
            return "fyi"
        return _compose_answer(user_text)


def _compose_answer(user_text: str) -> str:
    """Assemble a reply strictly from the tool results present in the prompt.

    If there is nothing to ground an answer in, it says so. That is the
    behaviour the product needs and the behaviour the evals check for.
    """
    results = _extract_tool_results(user_text)
    if not results:
        return (
            "I do not have anything on record that answers that. "
            "Nothing in your Life Graph, obligations or connected accounts matched."
        )
    lines = [f"- {item}" for item in results[:8]]
    return "Based on your records:\n" + "\n".join(lines)


def _extract_tool_results(text: str) -> list[str]:
    out: list[str] = []
    for block in re.findall(r"TOOL_RESULT\s+(\w+):\s*(\{.*?\}|\[.*?\])", text, re.S):
        try:
            payload = json.loads(block[1])
        except json.JSONDecodeError:
            continue
        items = payload if isinstance(payload, list) else payload.get("items", [])
        for item in items[:8]:
            if isinstance(item, dict):
                label = item.get("title") or item.get("name") or item.get("content") or ""
                detail = item.get("explanation") or item.get("due_at") or item.get("summary") or ""
                out.append(f"{label}{f' — {detail}' if detail else ''}".strip())
            else:
                out.append(str(item))
    return [o for o in out if o]


def _summarize(text: str) -> str:
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
    return " ".join(sentences[:3]) if sentences else "Nothing to summarise."


def _synthesize(schema: type[BaseModel], request: LLMRequest) -> dict:
    """Build a minimal valid instance of ``schema``.

    Walks the JSON schema and fills required fields with type-appropriate
    neutral values -- empty lists, zero confidence, empty strings -- so the
    result is structurally valid but asserts nothing. A mock that confidently
    fabricates content would make grounding tests meaningless.
    """
    json_schema = schema.model_json_schema()
    definitions = json_schema.get("$defs", {})
    return _build_object(json_schema, definitions, request)


def _build_object(node: dict, definitions: dict, request: LLMRequest) -> dict:
    out: dict = {}
    required = set(node.get("required", []))
    for name, prop in (node.get("properties") or {}).items():
        if name not in required:
            continue
        out[name] = _build_value(name, prop, definitions, request)
    return out


def _build_value(name: str, prop: dict, definitions: dict, request: LLMRequest):
    if "$ref" in prop:
        ref = prop["$ref"].split("/")[-1]
        return _build_object(definitions.get(ref, {}), definitions, request)
    if "anyOf" in prop:
        for option in prop["anyOf"]:
            if option.get("type") != "null":
                return _build_value(name, option, definitions, request)
        return None
    if "enum" in prop:
        return prop["enum"][0]

    kind = prop.get("type")
    if kind == "array":
        return []
    if kind == "object":
        return {}
    if kind in ("number", "integer"):
        # Confidence-shaped fields get a low value, not a confident one.
        if "confidence" in name or "score" in name:
            return 0.0
        return 0
    if kind == "boolean":
        return False
    if "confidence" in name:
        return "0.0"
    return ""


def _estimate_tokens(text: str) -> int:
    return max(1, len(text or "") // 4)


__all__ = ["MockProvider"]
