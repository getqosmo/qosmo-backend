"""Cloud and local-runtime providers.

All three speak the same :class:`LLMProvider` interface, so switching a
purpose from a cloud model to an on-device one is configuration, not a code
change. That is the migration path to the MyBot Core: the same call sites,
pointed at a local runtime.

None of these are reachable without an explicit API key. Absent one,
:meth:`available` returns ``False`` and the router falls back to the mock
provider rather than failing a user request.
"""

from __future__ import annotations

import os

import httpx
from mybot_schemas.config import get_settings

from ..base import LLMProvider, LLMRequest, LLMResponse, LLMUnavailable, TimedCall


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    local = False
    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        settings = get_settings()
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model or settings.anthropic_model

    def available(self) -> bool:
        return bool(self._api_key)

    def model_id(self) -> str:
        return self._model

    def complete(self, request: LLMRequest) -> LLMResponse:
        if not self.available():
            raise LLMUnavailable("ANTHROPIC_API_KEY is not set")

        payload = {
            "model": self._model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "system": request.context.render_system(),
            "messages": [{"role": "user", "content": request.context.render_user()}],
        }
        try:
            with TimedCall() as timer, httpx.Client(timeout=60.0) as client:
                response = client.post(
                    self.API_URL,
                    json=payload,
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": self.API_VERSION,
                        "content-type": "application/json",
                    },
                )
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise LLMUnavailable(f"Anthropic request failed: {type(exc).__name__}") from exc

        text = "".join(
            block.get("text", "") for block in body.get("content", []) if block.get("type") == "text"
        )
        usage = body.get("usage", {})
        return LLMResponse(
            text=text,
            provider=self.name,
            model=body.get("model", self._model),
            prompt_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"),
            latency_ms=timer.elapsed_ms,
        )


class OpenAIProvider(LLMProvider):
    name = "openai"
    local = False
    API_URL = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        settings = get_settings()
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._model = model or settings.openai_model

    def available(self) -> bool:
        return bool(self._api_key)

    def model_id(self) -> str:
        return self._model

    def complete(self, request: LLMRequest) -> LLMResponse:
        if not self.available():
            raise LLMUnavailable("OPENAI_API_KEY is not set")
        payload = {
            "model": self._model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [
                {"role": "system", "content": request.context.render_system()},
                {"role": "user", "content": request.context.render_user()},
            ],
        }
        try:
            with TimedCall() as timer, httpx.Client(timeout=60.0) as client:
                response = client.post(
                    self.API_URL,
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise LLMUnavailable(f"OpenAI request failed: {type(exc).__name__}") from exc

        usage = body.get("usage", {})
        return LLMResponse(
            text=body["choices"][0]["message"]["content"],
            provider=self.name,
            model=body.get("model", self._model),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            latency_ms=timer.elapsed_ms,
        )


class LocalProvider(LLMProvider):
    """Ollama-compatible local runtime.

    ``local = True`` is the load-bearing attribute: it is what allows the
    egress guard to permit HIGHLY_SENSITIVE context. On the Core this becomes
    the default for every purpose.
    """

    name = "local"
    local = True

    def __init__(self, base_url: str | None = None, model: str | None = None):
        settings = get_settings()
        self._base_url = (base_url or settings.local_model_base_url).rstrip("/")
        self._model = model or settings.local_model

    def available(self) -> bool:
        try:
            with httpx.Client(timeout=2.0) as client:
                return client.get(f"{self._base_url}/api/tags").status_code == 200
        except httpx.HTTPError:
            return False

    def model_id(self) -> str:
        return self._model

    def complete(self, request: LLMRequest) -> LLMResponse:
        payload = {
            "model": self._model,
            "system": request.context.render_system(),
            "prompt": request.context.render_user(),
            "stream": False,
            "options": {"temperature": request.temperature, "num_predict": request.max_tokens},
        }
        try:
            with TimedCall() as timer, httpx.Client(timeout=120.0) as client:
                response = client.post(f"{self._base_url}/api/generate", json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise LLMUnavailable(f"local model unreachable at {self._base_url}") from exc

        return LLMResponse(
            text=body.get("response", ""),
            provider=self.name,
            model=self._model,
            prompt_tokens=body.get("prompt_eval_count"),
            completion_tokens=body.get("eval_count"),
            latency_ms=timer.elapsed_ms,
        )


__all__ = ["AnthropicProvider", "LocalProvider", "OpenAIProvider"]
