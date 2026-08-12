"""Authentication endpoints.

Registration, login, elevation to STRONG, and logout.

Design points that are easy to get wrong and are handled deliberately here:

* Login returns the same error for an unknown email and a wrong password, and
  runs a dummy verification in the unknown-email case so response timing does
  not distinguish them either.
* Elevation is a separate step from login. You log in with a password; you
  elevate with a second factor, and it expires. Nothing grants STRONG at login.
* Sessions are rows. Logging out revokes; revoking a device revokes its
  sessions; lockdown downgrades them all.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from mybot_schemas.config import Settings, get_settings
from mybot_schemas.db.scope import session_owner_scope, session_system_scope
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    AuthLevel,
    Classification,
    SecurityEventType,
)
from mybot_schemas.models import AuthSession, Device, SecurityEvent, User
from mybot_security.auth import (
    generate_totp_secret,
    hash_ip,
    hash_password,
    issue_session_token,
    verify_password,
    verify_totp,
)
from mybot_security.logging import get_logger
from mybot_services.audit.service import AuditService
from mybot_services.security_center.service import SecurityCenterService
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from ..deps import (
    Principal,
    clear_rate_limit,
    enforce_rate_limit,
    get_db,
    get_principal,
    get_vault,
)
from ..websession import clear_session_cookies, issue_session_cookies

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
log = get_logger(__name__)

INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
)

#: Burned when the email is unknown, so the response takes about as long as a
#: real verification and cannot be used to enumerate accounts.
_DUMMY_HASH = hash_password("mybot-timing-equalizer-not-a-real-password")


class RegisterIn(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=256)
    timezone: str = "America/New_York"


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    device_name: str | None = None


class ElevateIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Create the owner account and its security scaffolding."""
    enforce_rate_limit("auth.register", request=request)
    settings = get_settings()
    with session_system_scope(db, "registration creates a new owner before any scope exists"):
        existing = db.execute(
            sa.select(User).where(User.email == payload.email.lower())
        ).scalar_one_or_none()
        if existing is not None:
            # Do not confirm the address exists.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="That account could not be created.",
            )

        user = User(
            email=payload.email.lower(),
            display_name=payload.display_name,
            password_hash=hash_password(payload.password),
            timezone=payload.timezone,
        )
        db.add(user)
        db.flush()

    with session_owner_scope(db, user.id):
        vault = get_vault(db)
        # The second-factor secret goes into the Vault, not a user column.
        totp_secret = generate_totp_secret()
        ref = f"cred:auth:totp:{user.id}"
        vault.put_secret(db, user.id, ref, totp_secret, classification=Classification.SECRET)
        user.strong_auth_ref = ref

        security = SecurityCenterService(db)
        device = security.register_device(
            user.id,
            name=payload.display_name + "'s device",
            kind="web",
            platform=request.headers.get("user-agent", "unknown")[:60],
            trusted=False,
            actor_id=user.id,
        )
        session_row, token = _issue_session(db, user, device, request, settings)

        AuditService(db).record(
            user.id,
            AuditEventType.USER_LOGIN,
            actor_type=ActorType.USER,
            actor_id=user.id,
            resource_type="user",
            resource_id=user.id,
            reason="account created",
            result="registered",
        )

    # The browser gets an httpOnly cookie; the token is still returned for
    # non-browser callers (the CLI, scripts, tests) which have no cookie jar.
    # A browser client should ignore `access_token` entirely and rely on the
    # cookie it cannot read.
    csrf = issue_session_cookies(
        response, token, max_age=settings.access_token_ttl_seconds
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "csrf_token": csrf,
        "expires_at": session_row.expires_at.isoformat(),
        "auth_level": AuthLevel.BASIC.value,
        "user": {"id": user.id, "email": user.email, "display_name": user.display_name},
        # Development affordance: the second-factor secret is shown once so a
        # developer can generate codes. A real deployment provisions a passkey
        # instead and never returns this.
        "development_totp_secret": None if settings.is_production else totp_secret,
    }


@router.post("/login")
def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    # Limited twice: by network, and by the email being tried. The first stops
    # one host walking a password list; the second stops a distributed attempt
    # concentrating on one account.
    enforce_rate_limit("auth.login", request=request)
    enforce_rate_limit("auth.login", request=request, identifier=payload.email)
    settings = get_settings()
    with session_system_scope(db, "login resolves an account before an owner scope exists"):
        user = db.execute(
            sa.select(User).where(User.email == payload.email.lower())
        ).scalar_one_or_none()

        if user is None:
            # Equalise timing, then fail exactly as a wrong password does.
            verify_password(_DUMMY_HASH, payload.password)
            raise INVALID_CREDENTIALS

        if not verify_password(user.password_hash, payload.password):
            with session_owner_scope(db, user.id):
                db.add(
                    SecurityEvent(
                        owner_id=user.id,
                        event_type=SecurityEventType.LOGIN_FAILURE.value,
                        severity="warning",
                        summary="Failed sign-in attempt",
                        details={"ip_hash": hash_ip(_client_ip(request))},
                    )
                )
                db.flush()
            raise INVALID_CREDENTIALS

        if not user.is_active:
            raise INVALID_CREDENTIALS

    # A correct password clears the throttle, so somebody who fat-fingered it
    # twice does not carry a reduced allowance for the next minute.
    clear_rate_limit("auth.login", request=request)
    clear_rate_limit("auth.login", identifier=payload.email)

    with session_owner_scope(db, user.id):
        device = None
        if payload.device_name:
            device = db.execute(
                sa.select(Device).where(
                    Device.owner_id == user.id,
                    Device.name == payload.device_name,
                    Device.revoked_at.is_(None),
                )
            ).scalar_one_or_none()
            if device is None:
                device = SecurityCenterService(db).register_device(
                    user.id, name=payload.device_name, kind="web", actor_id=user.id
                )

        session_row, token = _issue_session(db, user, device, request, settings)
        db.add(
            SecurityEvent(
                owner_id=user.id,
                event_type=SecurityEventType.LOGIN_SUCCESS.value,
                severity="info",
                summary="Signed in",
                details={"device_id": device.id if device else None},
            )
        )
        AuditService(db).record(
            user.id,
            AuditEventType.USER_LOGIN,
            actor_type=ActorType.USER,
            actor_id=user.id,
            resource_type="auth_session",
            resource_id=session_row.id,
            reason="signed in",
            result="success",
        )

    # The browser gets an httpOnly cookie; the token is still returned for
    # non-browser callers (the CLI, scripts, tests) which have no cookie jar.
    # A browser client should ignore `access_token` entirely and rely on the
    # cookie it cannot read.
    csrf = issue_session_cookies(
        response, token, max_age=settings.access_token_ttl_seconds
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "csrf_token": csrf,
        "expires_at": session_row.expires_at.isoformat(),
        "auth_level": AuthLevel.BASIC.value,
        "user": {"id": user.id, "email": user.email, "display_name": user.display_name},
    }


@router.post("/elevate")
def elevate(
    payload: ElevateIn,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    """Prove a second factor to reach STRONG for a limited window.

    Required for approving HIGH-risk actions, creating permissions, and
    unlocking after lockdown. The elevation expires on a timer, so it cannot
    be left standing on an unattended device.
    """
    # The tightest limit in the system. A six-digit code is a million
    # possibilities; unthrottled, that is minutes of guessing.
    enforce_rate_limit("auth.elevate", request=request, owner_id=principal.owner_id)
    settings = get_settings()
    user = principal.user
    if not user.strong_auth_ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No second factor is enrolled for this account.",
        )

    vault = get_vault(db)
    secret = vault.reveal_secret(
        db, user.id, user.strong_auth_ref, purpose="verify second factor for elevation"
    ).decode()

    if not verify_totp(secret, payload.code):
        db.add(
            SecurityEvent(
                owner_id=user.id,
                event_type=SecurityEventType.STRONG_AUTH_FAILURE.value,
                severity="warning",
                summary="Failed second-factor verification",
                details={"session_id": principal.session.id},
            )
        )
        db.flush()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="That code is not valid."
        )

    clear_rate_limit("auth.elevate", owner_id=principal.owner_id)
    principal.session.auth_level = AuthLevel.STRONG.value
    principal.session.elevated_until = utcnow() + dt.timedelta(
        seconds=settings.strong_auth_ttl_seconds
    )
    db.flush()

    db.add(
        SecurityEvent(
            owner_id=user.id,
            event_type=SecurityEventType.STRONG_AUTH_SUCCESS.value,
            severity="info",
            summary="Elevated to strong authentication",
            details={"expires_at": principal.session.elevated_until.isoformat()},
        )
    )
    AuditService(db).record(
        user.id,
        AuditEventType.SECURITY,
        actor_type=ActorType.USER,
        actor_id=user.id,
        resource_type="auth_session",
        resource_id=principal.session.id,
        reason="elevated to strong authentication",
        approval_auth_level=AuthLevel.STRONG.value,
        result="elevated",
    )

    return {
        "auth_level": AuthLevel.STRONG.value,
        "expires_at": principal.session.elevated_until.isoformat(),
        "ttl_seconds": settings.strong_auth_ttl_seconds,
    }


@router.post("/logout")
def logout(
    response: Response,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    """Revoke server-side *and* clear the cookies.

    Server-side revocation is what actually ends the session -- clearing the
    cookie alone would leave a live token that anybody holding a copy could
    keep using. Both, in that order.
    """
    principal.session.revoked_at = utcnow()
    db.flush()
    clear_session_cookies(response)
    return {"ok": True}


@router.get("/me")
def me(principal: Principal = Depends(get_principal)):
    return {
        "id": principal.user.id,
        "email": principal.user.email,
        "display_name": principal.user.display_name,
        "timezone": principal.user.timezone,
        "is_demo": principal.user.is_demo,
        "auth_level": principal.auth_level.value,
        "elevated_until": (
            principal.session.elevated_until.isoformat()
            if principal.session.elevated_until
            else None
        ),
        "device_id": principal.device_id,
    }


# ---------------------------------------------------------------------------


def _issue_session(
    db: Session, user: User, device: Device | None, request: Request, settings: Settings
) -> tuple[AuthSession, str]:
    issued = issue_session_token(settings.access_token_ttl_seconds)
    session_row = AuthSession(
        owner_id=user.id,
        device_id=device.id if device else None,
        token_hash=issued.token_hash,
        auth_level=AuthLevel.BASIC.value,
        expires_at=issued.expires_at,
        ip_hash=hash_ip(_client_ip(request)),
        user_agent=request.headers.get("user-agent", "")[:300] or None,
    )
    db.add(session_row)
    db.flush()
    return session_row, issued.token


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
