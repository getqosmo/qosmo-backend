"""Connecting and disconnecting external accounts.

The consent flow lives in ``mybot_services.oauth``; this is the HTTP surface.

Two things about the shape are deliberate:

**The callback requires an authenticated session.** A bare public callback
cannot tell whose flow it is completing, which is exactly what login-CSRF
exploits — the attacker consents with their own Google account and gets the
victim's browser to the callback. Requiring a session lets the flow check that
the caller is the owner who started it.

**Connecting requires STRONG auth.** Handing MyBot reach into a mailbox is a
bigger decision than most things in the product, and it is the moment somebody
with a stolen tab would want to act.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from mybot_schemas.enums import SecurityEventType
from mybot_services.oauth import PROVIDERS, OAuthError, OAuthStateInvalid
from pydantic import BaseModel, Field

from ..deps import Principal, ServiceBundle, get_principal, get_services, require_strong

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


class ConnectIn(BaseModel):
    provider: str = Field(min_length=1, max_length=64)
    redirect_uri: str = Field(min_length=1, max_length=500)
    #: Write access is a separate, later decision by design.
    include_write: bool = False


class CallbackIn(BaseModel):
    state: str = Field(min_length=1, max_length=200)
    code: str = Field(min_length=1, max_length=2000)


@router.get("/providers")
def providers(
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """What can be connected, and what each would be allowed to see."""
    import sqlalchemy as sa
    from mybot_schemas.models import Integration

    connected = {
        row.provider
        for row in services.db.execute(
            sa.select(Integration).where(
                Integration.owner_id == principal.owner_id,
                Integration.status == "connected",
            )
        ).scalars()
    }
    return {
        "providers": [
            {
                "key": p.key,
                "display_name": p.display_name,
                "read_scopes": list(p.read_scopes),
                "write_scopes": list(p.write_scopes),
                "connected": p.key in connected,
            }
            for p in PROVIDERS.values()
        ],
        "configured": bool(services.oauth.client_id),
        "note": (
            "MyBot connects read-only. Permission to send or change anything is a "
            "separate grant you make later."
        ),
    }


@router.post("/connect")
def connect(
    body: ConnectIn,
    principal: Principal = Depends(require_strong),
    services: ServiceBundle = Depends(get_services),
):
    try:
        return services.oauth.begin(
            principal.owner_id,
            body.provider,
            redirect_uri=body.redirect_uri,
            include_write=body.include_write,
        )
    except OAuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None


@router.post("/callback")
def callback(
    body: CallbackIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        integration = services.oauth.complete(
            principal.owner_id, state=body.state, code=body.code
        )
    except OAuthStateInvalid as exc:
        # Recorded as a security event: a mismatched state is either a stale
        # tab or somebody attempting login-CSRF, and the owner should be able
        # to see that it happened.
        services.security._security_event(
            principal.owner_id,
            SecurityEventType.INTEGRATION_CONNECTED,
            "an account-connection callback did not match a live request",
            severity="warning",
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except OAuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None

    return {
        "provider": integration.provider,
        "display_name": integration.display_name,
        "status": integration.status,
        "scopes": integration.scopes,
        "write_enabled": integration.write_enabled,
    }


@router.delete("/{provider}")
def disconnect(
    provider: str,
    principal: Principal = Depends(require_strong),
    services: ServiceBundle = Depends(get_services),
):
    """Revoke at the provider, then delete locally.

    Returns 404 rather than 200 for something never connected, so a UI cannot
    show "disconnected" for an account that was never there.
    """
    try:
        removed = services.oauth.disconnect(principal.owner_id, provider)
    except OAuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    if not removed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That account is not connected.")
    return {"disconnected": True, "provider": provider}
