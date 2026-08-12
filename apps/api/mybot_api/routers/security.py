"""Security Center, permissions, audit and integrations.

Everything that answers "what can MyBot do, who said so, and what has it
done?".

Two endpoints in this file are the direct expression of Rule 2: creating and
revoking permissions. Creation requires ``ActorType.USER`` *and* a STRONG auth
level, both passed explicitly to :meth:`PolicyService.create_rule`, which
refuses anything else. There is no service-to-service call that reaches it
with a non-user actor, and ``tests/security`` asserts that.
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Query, status
from mybot_schemas.enums import ActorType, AuthLevel, IntegrationStatus
from mybot_schemas.models import Integration
from mybot_services.policy.service import PermissionDenied
from mybot_services.security_center.service import LockdownError
from pydantic import BaseModel, Field

from ..deps import Principal, ServiceBundle, get_principal, get_services
from ..serializers import audit_out

router = APIRouter(prefix="/api/v1", tags=["security"])


class PermissionIn(BaseModel):
    action_type: str
    resource: str = "*"
    description: str | None = None
    max_amount: float | None = None
    currency: str | None = None
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_time_window: dict | None = None
    constraints: dict = Field(default_factory=dict)
    requires_confirmation: bool = True
    requires_strong_auth: bool = False
    min_confidence: float = 0.9
    allow_automatic: bool = False
    expires_at: dt.datetime | None = None


class LockIn(BaseModel):
    reason: str = "requested by the owner"


class UnlockIn(BaseModel):
    restore_automations: bool = False


class DeviceIn(BaseModel):
    name: str
    kind: str = "web"
    platform: str = "unknown"


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


@router.get("/security")
def security_overview(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    return services.security.overview(
        principal.owner_id,
        model_routing=services.router.describe(),
        vault=services.vault.describe(),
    )


@router.get("/security/events")
def security_events(
    limit: int = Query(default=50, le=200),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    events = services.security.list_security_events(principal.owner_id, limit=limit)
    return {
        "items": [
            {
                "id": e.id,
                "type": e.event_type,
                "severity": e.severity,
                "summary": e.summary,
                "details": e.details,
                "created_at": e.created_at.isoformat(),
                "acknowledged": e.acknowledged_at is not None,
            }
            for e in events
        ]
    }


# ---------------------------------------------------------------------------
# Permissions  (Rule 2 boundary)
# ---------------------------------------------------------------------------


@router.get("/security/permissions")
def list_permissions(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    overview = services.security.overview(principal.owner_id)
    return {"items": overview["permissions"], "summary": overview["summary"]}


@router.post("/security/permissions", status_code=status.HTTP_201_CREATED)
def create_permission(
    payload: PermissionIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Grant MyBot a capability.

    Requires STRONG authentication. The actor is hard-coded to ``USER``
    because this endpoint is only reachable from an authenticated human
    session -- and ``create_rule`` refuses any other actor regardless.
    """
    principal.require(AuthLevel.STRONG)
    try:
        rule = services.policy.create_rule(
            principal.owner_id,
            action_type=payload.action_type,
            actor_type=ActorType.USER,
            auth_level=principal.auth_level,
            created_by=f"user:{principal.user.email}",
            resource=payload.resource,
            description=payload.description,
            max_amount=payload.max_amount,
            currency=payload.currency,
            allowed_recipients=payload.allowed_recipients,
            allowed_time_window=payload.allowed_time_window,
            constraints=payload.constraints,
            requires_confirmation=payload.requires_confirmation,
            requires_strong_auth=payload.requires_strong_auth,
            min_confidence=payload.min_confidence,
            allow_automatic=payload.allow_automatic,
            expires_at=payload.expires_at,
        )
    except PermissionDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None

    return {
        "id": rule.id,
        "action_type": rule.action_type,
        "resource": rule.resource,
        "max_amount": rule.max_amount,
        "allowed_recipients": rule.allowed_recipients,
        "requires_confirmation": rule.requires_confirmation,
        "requires_strong_auth": rule.requires_strong_auth,
        "allow_automatic": rule.allow_automatic,
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
        "created_at": rule.created_at.isoformat(),
    }


@router.delete("/security/permissions/{rule_id}")
def revoke_permission(
    rule_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Revoke a grant. Intentionally does not require elevation."""
    try:
        services.policy.revoke_rule(
            principal.owner_id,
            rule_id,
            actor_type=ActorType.USER,
            actor_id=f"user:{principal.user.email}",
        )
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None
    except PermissionDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from None
    return {"revoked": True, "id": rule_id}


# ---------------------------------------------------------------------------
# Lockdown
# ---------------------------------------------------------------------------


@router.post("/security/lockdown")
def lock(
    payload: LockIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Engage lockdown. Any valid session may do this -- panic must be cheap."""
    result = services.security.lock(
        principal.owner_id,
        actor_id=f"user:{principal.user.email}",
        reason=payload.reason,
        device_id=principal.device_id,
    )
    return {
        "locked": result.locked,
        "actions_blocked": result.actions_blocked,
        "automations_disabled": result.automations_disabled,
        "sessions_downgraded": result.sessions_downgraded,
        "message": result.message,
    }


@router.post("/security/unlock")
def unlock(
    payload: UnlockIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Release lockdown. Requires STRONG authentication."""
    try:
        result = services.security.unlock(
            principal.owner_id,
            actor_id=f"user:{principal.user.email}",
            auth_level=principal.auth_level,
            restore_automations=payload.restore_automations,
        )
    except LockdownError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from None
    return {"locked": result.locked, "message": result.message}


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@router.post("/security/devices", status_code=status.HTTP_201_CREATED)
def register_device(
    payload: DeviceIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    device = services.security.register_device(
        principal.owner_id,
        name=payload.name,
        kind=payload.kind,
        platform=payload.platform,
        trusted=False,
        actor_id=principal.owner_id,
    )
    return {"id": device.id, "name": device.name, "trusted": device.trusted, "kind": device.kind}


@router.delete("/security/devices/{device_id}")
def revoke_device(
    device_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        services.security.revoke_device(
            principal.owner_id, device_id, actor_id=f"user:{principal.user.email}"
        )
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found") from None
    return {"revoked": True, "id": device_id}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@router.get("/audit")
def audit_log(
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    events = services.audit.list_events(
        principal.owner_id,
        limit=limit,
        offset=offset,
        event_type=event_type,
        resource_id=resource_id,
    )
    return {
        "items": [audit_out(e) for e in events],
        "total": services.audit.count_events(principal.owner_id),
    }


@router.get("/audit/verify")
def verify_audit(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Recompute the hash chain and report whether history is intact."""
    return services.audit.verify_chain(principal.owner_id).as_dict()


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------


@router.get("/integrations")
def list_integrations(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    import sqlalchemy as sa

    rows = list(
        services.db.execute(
            sa.select(Integration).where(Integration.owner_id == principal.owner_id)
        ).scalars()
    )
    return {
        "connected": [
            {
                "id": i.id,
                "provider": i.provider,
                "display_name": i.display_name,
                "status": i.status,
                "scopes": i.scopes,
                "write_enabled": i.write_enabled,
                "last_sync_at": i.last_sync_at.isoformat() if i.last_sync_at else None,
                "last_error": i.last_error,
                "simulated": i.status == IntegrationStatus.MOCK.value,
            }
            for i in rows
        ],
        "available_adapters": services.registry.describe(),
        "mode": services.registry.mode,
    }


@router.post("/integrations/{provider}/connect")
def connect_integration(
    provider: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Begin connecting a real provider.

    Not implemented in V0.1, and it says so rather than pretending. The OAuth
    flow needs client credentials that this build does not have; the adapter
    code exists and the credential model exists, but nothing here fakes a
    successful connection.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "message": (
                f"Connecting {provider} is not available in this release. MyBot is running "
                "with simulated connectors so the full product can be used without "
                "granting access to a real account."
            ),
            "what_exists": (
                "The Google Calendar and Gmail adapters are implemented and the credential "
                "model is in place; the OAuth consent flow is not wired up."
            ),
            "see": "docs/ROADMAP.md",
        },
    )


@router.post("/integrations/sync")
def sync_integrations(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    result = services.sync.sync_all(principal.owner_id)
    scan = services.proactive.scan(principal.owner_id)
    return {"sync": result.as_dict(), "scan": scan.as_dict()}
