"""Configuration.

One settings object, read from the environment, validated at import time.
Two rules shape this module:

* No secret has a usable default.  Development conveniences (a generated JWT
  key, a software keystore) are allowed *only* when ``MYBOT_ENV`` is not
  ``production``; in production the process refuses to start rather than run
  with a predictable key.
* Defaults are the safe choice, not the impressive one.  The default LLM
  provider is ``mock`` and the default integration mode is ``mock``, so a
  fresh clone boots with zero credentials and zero outbound calls.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .enums import Classification


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MYBOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    env: str = "development"
    log_level: str = "INFO"
    data_dir: Path = Path("./var")

    database_url: str = "sqlite+pysqlite:///./var/mybot.db"

    jwt_secret: str = ""
    access_token_ttl_seconds: int = 3600
    strong_auth_ttl_seconds: int = 300
    approval_ttl_seconds: int = 900

    vault_keystore: str = "software"
    vault_master_key: str = ""

    llm_default_provider: str = "mock"
    llm_purpose_classification: str | None = None
    llm_purpose_extraction: str | None = None
    llm_purpose_reasoning: str | None = None
    llm_purpose_planning: str | None = None
    llm_purpose_summarization: str | None = None
    llm_purpose_chat: str | None = None
    anthropic_model: str = "claude-sonnet-5"
    openai_model: str = "gpt-4.1-mini"
    local_model_base_url: str = "http://localhost:11434"
    local_model: str = "llama3.1"

    pii_tokenization: bool = True
    max_external_classification: Classification = Classification.PERSONAL

    integrations_mode: str = "mock"

    proactive_enabled: bool = True
    proactive_interval_seconds: int = 300

    cors_origins: str = "http://localhost:3000"

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @field_validator("data_dir")
    @classmethod
    def _ensure_dir(cls, v: Path) -> Path:
        v.mkdir(parents=True, exist_ok=True)
        return v

    def resolved_jwt_secret(self) -> str:
        """Return the token signing key, generating one only in development.

        A generated key is written to ``data_dir`` with owner-only permissions
        so restarts do not invalidate every session, while still never
        shipping a hardcoded default that would make tokens forgeable.
        """
        if self.jwt_secret:
            return self.jwt_secret
        if self.is_production:
            raise RuntimeError(
                "MYBOT_JWT_SECRET must be set in production; refusing to start with "
                "a generated key"
            )
        key_path = self.data_dir / "dev_jwt_secret"
        if key_path.exists():
            return key_path.read_text().strip()
        generated = secrets.token_urlsafe(48)
        key_path.write_text(generated)
        key_path.chmod(0o600)
        return generated

    def purpose_provider(self, purpose: str) -> str:
        override = getattr(self, f"llm_purpose_{purpose}", None)
        return override or self.llm_default_provider

    def documents_dir(self) -> Path:
        p = self.data_dir / "documents"
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook -- lets a test change the environment and re-read it."""
    get_settings.cache_clear()


__all__ = ["Settings", "get_settings", "reset_settings_cache"]
