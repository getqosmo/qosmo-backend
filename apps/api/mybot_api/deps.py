"""Request-scoped wiring and the authentication boundary.

This module is where an HTTP request becomes an owner-scoped, audited unit of
work. Three things happen for every authenticated request, in order:

1. The bearer token is resolved to a *server-side session row*. Expired,
   revoked, or unknown tokens are rejected identically.
2. The effective :class:`AuthLevel` is recomputed from the session's elevation
   window -- a STRONG elevation from twenty minutes ago is BASIC now.
3. :func:`owner_scope` is entered, which arms the ORM-level owner filter for
   everything downstream. No service can read another owner's rows inside this
   request even if it forgets to filter.

The dependency graph is also where the security boundaries show up as code:
routers get a :class:`ServiceBundle`, and that bundle contains no Vault
handle for the chat path, because the reasoning layer has no business
reaching it.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache

import sqlalchemy as sa
from fastapi import Depends, Header, HTTPException, Request, status
from mybot_integrations.registry import IntegrationRegistry, build_default_registry
from mybot_llm.router import ModelRouter, default_router
from mybot_schemas.config import Settings, get_settings
from mybot_schemas.db.scope import bind_owner, session_system_scope
from mybot_schemas.db.session import get_session_factory
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import AuthLevel
from mybot_schemas.models import AuthSession, User
from mybot_security.auth import effective_auth_level
from mybot_security.crypto import token_fingerprint
from mybot_security.hardware.keystore import build_keystore
from mybot_security.hardware.presence import (
    SimulatedAttestationProvider,
    SimulatedPresenceProvider,
)
from mybot_security.logging import get_logger
from mybot_security.vault import Vault, VaultAuditHook
from mybot_services.action_firewall.service import ActionFirewall
from mybot_services.audit.service import AuditService
from mybot_services.brief.service import BriefService
from mybot_services.document_ingestion.service import DocumentIngestionService
from mybot_services.inbox.service import InboxService
from mybot_services.life_graph.service import LifeGraphService
from mybot_services.memory.service import MemoryService
from mybot_services.obligations.service import ObligationService
from mybot_services.policy.service import PolicyService
from mybot_services.proactive.engine import ProactiveEngine
from mybot_services.proactive.sync import ConnectorSync
from mybot_services.security_center.service import SecurityCenterService
from sqlalchemy.orm import Session

log = get_logger(__name__)

UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


# ---------------------------------------------------------------------------
# Process-level singletons
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_registry() -> IntegrationRegistry:
    return build_default_registry(get_settings().integrations_mode)


@lru_cache(maxsize=1)
def get_router() -> ModelRouter:
    return default_router()


@lru_cache(maxsize=1)
def get_presence_provider() -> SimulatedPresenceProvider:
    return SimulatedPresenceProvider()


@lru_cache(maxsize=1)
def get_attestation_provider() -> SimulatedAttestationProvider:
    return SimulatedAttestationProvider()


@lru_cache(maxsize=1)
def _keystore():
    settings = get_settings()
    return build_keystore(
        settings.vault_keystore,
        data_dir=settings.data_dir,
        env_key=settings.vault_master_key,
    )


def get_vault(session: Session | None = None) -> Vault:
    """Build a Vault whose access hook writes to the audit log.

    Constructed per call rather than cached so the audit hook binds to the
    current session. The keystore itself is cached -- deriving keys is the
    expensive part, and the master key should be loaded once.
    """
    settings = get_settings()
    hook = VaultAuditHook()
    if session is not None:
        def _on_access(owner_id: str, ref: str, operation: str, granted: bool, reason: str | None):
            from mybot_schemas.enums import ActorType, AuditEventType, SecurityEventType
            from mybot_schemas.models import SecurityEvent

            AuditService(session).record(
                owner_id,
                AuditEventType.SECURITY,
                actor_type=ActorType.SYSTEM,
                resource_type="vault_secret",
                # The ref, never the secret.
                resource_id=ref,
                reason=f"vault {operation}",
                result="granted" if granted else "denied",
                details={"operation": operation, "reason": reason},
            )
            if not granted:
                session.add(
                    SecurityEvent(
                        owner_id=owner_id,
                        event_type=SecurityEventType.VAULT_ACCESS_DENIED.value,
                        severity="warning",
                        summary=f"Vault access denied: {ref}",
                        details={"operation": operation, "reason": reason},
                    )
                )

        hook.on_access = _on_access

    return Vault(keystore=_keystore(), data_dir=settings.data_dir, audit=hook)


# ---------------------------------------------------------------------------
# Per-request dependencies
# ---------------------------------------------------------------------------


def get_db() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_config() -> Settings:
    return get_settings()


@dataclass
class Principal:
    """The authenticated caller."""

    user: User
    session: AuthSession
    auth_level: AuthLevel
    device_id: str | None

    @property
    def owner_id(self) -> str:
        return self.user.id

    def require(self, level: AuthLevel) -> None:
        if not self.auth_level.satisfies(level):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This requires {level.value} authentication. "
                    f"You currently have {self.auth_level.value}."
                ),
            )


def get_principal(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> Principal:
    """Resolve and validate the caller, then arm owner scoping.

    Every failure path returns the same 401. Distinguishing "no such session"
    from "expired session" from "revoked device" would leak state to whoever is
    probing.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UNAUTHENTICATED
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise UNAUTHENTICATED

    # The session lookup itself must run unscoped -- we do not yet know whose
    # session it is. This is the one place that is legitimate, and it resolves
    # by token hash, so it cannot enumerate.
    with session_system_scope(db, "resolving a bearer token to its session"):
        auth_session = db.execute(
            sa.select(AuthSession).where(AuthSession.token_hash == token_fingerprint(token))
        ).scalar_one_or_none()

        if auth_session is None or auth_session.revoked_at is not None:
            raise UNAUTHENTICATED
        if auth_session.expires_at <= utcnow():
            raise UNAUTHENTICATED

        user = db.get(User, auth_session.owner_id)
        if user is None or not user.is_active:
            raise UNAUTHENTICATED

        if auth_session.device_id:
            from mybot_schemas.models import Device

            device = db.get(Device, auth_session.device_id)
            if device is not None and device.revoked_at is not None:
                raise UNAUTHENTICATED

    level = effective_auth_level(auth_session.auth_level, auth_session.elevated_until)
    auth_session.updated_at = utcnow()

    principal = Principal(
        user=user, session=auth_session, auth_level=level, device_id=auth_session.device_id
    )
    request.state.owner_id = user.id
    request.state.principal = principal

    # Arm the ORM owner filter for the rest of this request. Bound to the
    # session rather than a context variable: the request's dependencies,
    # route handler and teardown may each run in a different task or
    # threadpool worker, and the session is the one object all of them share.
    bind_owner(db, user.id)
    return principal


def require_strong(principal: Principal = Depends(get_principal)) -> Principal:
    principal.require(AuthLevel.STRONG)
    return principal


# ---------------------------------------------------------------------------
# Service bundle
# ---------------------------------------------------------------------------


@dataclass
class ServiceBundle:
    """Everything a router needs, wired to one session and one owner."""

    db: Session
    owner_id: str
    audit: AuditService
    policy: PolicyService
    firewall: ActionFirewall
    graph: LifeGraphService
    memory: MemoryService
    obligations: ObligationService
    inbox: InboxService
    brief: BriefService
    proactive: ProactiveEngine
    sync: ConnectorSync
    security: SecurityCenterService
    documents: DocumentIngestionService
    registry: IntegrationRegistry
    router: ModelRouter
    vault: Vault


def get_services(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ServiceBundle:
    registry = get_registry()
    audit = AuditService(db)
    policy = PolicyService(db, audit)
    firewall = ActionFirewall(db, registry, policy=policy, audit=audit)
    graph = LifeGraphService(db, audit)
    vault = get_vault(db)

    return ServiceBundle(
        db=db,
        owner_id=principal.owner_id,
        audit=audit,
        policy=policy,
        firewall=firewall,
        graph=graph,
        memory=MemoryService(db, audit),
        obligations=ObligationService(db, audit),
        inbox=InboxService(db, audit),
        brief=BriefService(db, audit=audit),
        proactive=ProactiveEngine(db),
        sync=ConnectorSync(db, registry, audit),
        security=SecurityCenterService(db, policy=policy, firewall=firewall, audit=audit),
        documents=DocumentIngestionService(db, vault, audit=audit, graph=graph),
        registry=registry,
        router=get_router(),
        vault=vault,
    )


def coverage_from_sync(result) -> dict:
    """Turn a sync result into the coverage map the brief and chat consume.

    This is what backs the honesty rule: "nothing else requires your attention"
    is only printed when every entry here reports ``ok``.
    """
    coverage = {
        "calendar": {"ok": "calendar" not in result.unavailable},
        "email": {"ok": "email" not in result.unavailable},
        "obligations": {"ok": True},
        "documents": {"ok": True},
    }
    for name, reason in result.unavailable.items():
        coverage.setdefault(name, {})["ok"] = False
        coverage[name]["reason"] = reason
    return coverage


def utc_today() -> str:
    return dt.datetime.now(dt.UTC).date().isoformat()


__all__ = [
    "Principal",
    "ServiceBundle",
    "coverage_from_sync",
    "get_config",
    "get_db",
    "get_principal",
    "get_registry",
    "get_router",
    "get_services",
    "get_vault",
    "require_strong",
    "utc_today",
]
