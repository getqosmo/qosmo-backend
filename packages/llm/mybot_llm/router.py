"""Model routing and the guarded call path.

Every model call in MyBot goes through :meth:`ModelRouter.run`, which:

1. picks a provider for the purpose (falling back to mock when the configured
   one is unavailable, rather than failing the user's request),
2. enforces the egress ceiling -- refusing to send over-classified context to a
   remote model,
3. records an :class:`LLMRun` with metadata only.

On that last point: ``LLMRun`` stores the provider, model, purpose, token
counts, latency, status and a hash of the prompt. It does not store the prompt
or the completion. Debuggability is real, but a table full of prompts is a
second copy of the user's life sitting somewhere nobody classified as
sensitive.
"""

from __future__ import annotations

from mybot_schemas.config import get_settings
from mybot_schemas.enums import LLMPurpose
from mybot_schemas.models import LLMRun
from mybot_security.crypto import sha256_hex
from mybot_security.logging import current_request_id, get_logger
from sqlalchemy.orm import Session

from .base import LLMProvider, LLMRequest, LLMResponse, LLMUnavailable, SchemaViolation
from .capabilities import CapabilityRegistry
from .minimizer import assert_egress_allowed
from .providers.cloud import AnthropicProvider, LocalProvider, OpenAIProvider
from .providers.mock import MockProvider

log = get_logger(__name__)

PROVIDER_FACTORIES = {
    "mock": MockProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "local": LocalProvider,
}


class ModelRouter:
    def __init__(
        self,
        *,
        providers: dict[str, LLMProvider] | None = None,
        capabilities: CapabilityRegistry | None = None,
    ):
        self.settings = get_settings()
        self._providers: dict[str, LLMProvider] = providers or {}
        self._fallback = self._providers.get("mock") or MockProvider()
        #: Measured conformance results. Can only narrow routing, never widen
        #: it -- see mybot_llm.capabilities for why that asymmetry matters.
        self.capabilities = capabilities or CapabilityRegistry.load(self.settings.data_dir)

    def provider_for(self, purpose: LLMPurpose) -> LLMProvider:
        """Resolve the provider for a purpose, degrading gracefully.

        An unconfigured cloud provider must not turn into a 500 on the user's
        chat request. It falls back to the mock, and the response is labelled
        so the UI can say the answer came from the offline path.

        In sovereign mode a remote provider is never selected in the first
        place. The egress guard would refuse the call anyway, but a setting
        whose only enforcement is an exception thrown deep in the stack invites
        a future code path that forgets to pass through it. Selection and
        egress both enforce it; neither is load-bearing alone.
        """
        name = self.settings.purpose_provider(purpose.value)
        provider = self._get(name)

        if self.settings.sovereign and provider is not None and not provider.local:
            log.warning(
                "llm.sovereign_blocked_provider", requested=name, purpose=purpose.value
            )
            provider = None

        # A provider measured to fail this purpose is not used for it. Without
        # this, `mybot model-check` would be a document somebody reads once;
        # with it, discovering that a local model fabricates phone numbers
        # actually stops it answering questions about somebody's life.
        if provider is not None and not self.capabilities.permits(name, purpose):
            log.warning(
                "llm.capability_blocked",
                provider=name,
                purpose=purpose.value,
                reasons=self.capabilities.reasons(name, purpose)[:2],
            )
            provider = None

        if provider is not None and provider.available():
            return provider
        if name != "mock":
            log.warning("llm.provider_unavailable", requested=name, fallback="mock")
        return self._fallback

    def _get(self, name: str) -> LLMProvider | None:
        if name in self._providers:
            return self._providers[name]
        factory = PROVIDER_FACTORIES.get(name)
        if factory is None:
            log.warning("llm.unknown_provider", requested=name)
            return None
        provider = factory()
        self._providers[name] = provider
        return provider

    def run(
        self,
        session: Session,
        owner_id: str,
        request: LLMRequest,
        *,
        schema=None,
    ) -> tuple[LLMResponse | object, LLMRun]:
        """Execute a model call with egress control and metadata logging."""
        provider = self.provider_for(request.purpose)

        # `provider_for` degrades to the fallback, and the fallback can itself
        # be a provider that failed this purpose -- so the gate has to be
        # re-checked on the thing actually about to be called. Without this,
        # blocking a provider merely re-routes to another blocked one and
        # enforces nothing.
        #
        # Raising is correct rather than harsh: every caller already handles
        # LLMUnavailable by degrading to its deterministic path, which is the
        # behaviour wanted here. "No model here can be trusted with this" and
        # "no model is configured" deserve the same response.
        if not self.capabilities.permits(provider.name, request.purpose):
            reasons = self.capabilities.reasons(provider.name, request.purpose)
            raise LLMUnavailable(
                f"no model is cleared for {request.purpose.value} on this machine "
                f"({provider.name} failed its check: "
                f"{reasons[0] if reasons else 'a gating probe'})"
            )

        assert_egress_allowed(
            provider_is_local=provider.local,
            payload_classification=request.max_classification,
            ceiling=self.settings.max_external_classification,
            sovereign=self.settings.sovereign,
        )

        run = LLMRun(
            owner_id=owner_id,
            provider=provider.name,
            model=provider.model_id(),
            purpose=request.purpose.value,
            request_id=request.request_id or current_request_id(),
            prompt_hash=sha256_hex(request.context.render_user())[:64],
            max_classification_sent=request.max_classification.value,
            pii_tokenized=request.tokenized,
            contained_untrusted=request.context.has_untrusted,
            # Stamped now, not derived later from the provider name. A ledger
            # whose historical rows change meaning when somebody edits their
            # config is not a ledger.
            left_machine=not provider.local,
            destination=provider.destination(),
        )

        try:
            if schema is not None:
                result = provider.complete_structured(request, schema)
                run.schema_valid = True
                run.status = "ok"
                run.latency_ms = 0
            else:
                result = provider.complete(request)
                run.prompt_tokens = result.prompt_tokens
                run.completion_tokens = result.completion_tokens
                run.latency_ms = result.latency_ms
                run.status = "ok"
        except SchemaViolation as exc:
            run.status = "schema_violation"
            run.schema_valid = False
            run.error = str(exc)[:500]
            session.add(run)
            session.flush()
            raise
        except LLMUnavailable as exc:
            run.status = "unavailable"
            run.error = str(exc)[:500]
            session.add(run)
            session.flush()
            raise
        except Exception as exc:  # noqa: BLE001
            run.status = "error"
            run.error = f"{type(exc).__name__}"
            session.add(run)
            session.flush()
            raise

        session.add(run)
        session.flush()
        log.info(
            "llm.run",
            provider=provider.name,
            model=provider.model_id(),
            purpose=request.purpose.value,
            tokens_in=run.prompt_tokens,
            tokens_out=run.completion_tokens,
            latency_ms=run.latency_ms,
            untrusted=run.contained_untrusted,
            classification=run.max_classification_sent,
        )
        return result, run

    def describe(self) -> dict:
        """Security Center view: which model handles what, and where it runs."""
        out = {}
        for purpose in LLMPurpose:
            provider = self.provider_for(purpose)
            cleared = self.capabilities.permits(provider.name, purpose)
            out[purpose.value] = {
                "provider": provider.name,
                "model": provider.model_id(),
                "local": provider.local,
                "available": provider.available(),
                # False means MyBot will use its deterministic path for this
                # instead of a model it measured as unfit.
                "cleared": cleared,
                "blocked_because": (
                    self.capabilities.reasons(provider.name, purpose) if not cleared else []
                ),
            }
        out["_egress_ceiling"] = self.settings.max_external_classification.value
        out["_pii_tokenization"] = self.settings.pii_tokenization
        out["_sovereign"] = self.settings.sovereign
        out["_measured_capabilities"] = self.capabilities.describe()
        # Stated as a fact the UI can show without interpreting: is there any
        # purpose whose model runs somewhere else?
        out["_fully_local"] = all(
            entry["local"]
            for key, entry in out.items()
            if not key.startswith("_") and isinstance(entry, dict)
        )
        return out


def default_router() -> ModelRouter:
    return ModelRouter(providers={"mock": MockProvider()})


__all__ = ["ModelRouter", "PROVIDER_FACTORIES", "default_router"]
