"""OAuth 2.0 authorization-code flow with PKCE.

The piece standing between "the Google adapters are code-complete" and
"somebody can actually connect their account". The adapters already take an
injected token provider; this is what produces one.

## What this refuses to do

**No implicit flow, no client-side tokens.** Authorization code with PKCE
(S256) only. The code challenge means an intercepted authorization code is
useless without the verifier, which never leaves this machine.

**No refresh token in the database.** Refresh tokens are the crown jewels of an
OAuth integration — they are long-lived, and one is worth more than any single
access token. They go straight into the Vault as ciphertext under a ref, and
the ``Integration`` row holds only the ref. A database dump yields nothing
usable.

**No token in a log, ever.** Tokens never appear in an audit detail, a log
field, or an error message. The redaction layer would catch most of it; not
putting them there in the first place is better.

**No wildcard redirect.** The redirect URI is compared by exact string against
a configured allowlist. Prefix matching on redirect URIs is how open redirectors
become account takeovers.

**No state reuse.** The state parameter is single-use, expiring, and bound to
the owner who started the flow. It is stored server-side rather than being a
signed blob, because a signed blob that has already been used is
indistinguishable from one that has not.

## Why the state is bound to an owner

The classic attack is login-CSRF: the attacker starts a flow with *their*
Google account, then tricks the victim's browser into hitting the callback, so
the victim's MyBot ends up connected to the attacker's mailbox. Binding the
state record to the owner who began the flow, and refusing a callback whose
authenticated owner does not match, closes it. It is why the callback requires
an authenticated session rather than being a bare public endpoint.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import secrets
from dataclasses import dataclass, field

import httpx
import sqlalchemy as sa
from mybot_schemas.enums import ActorType, AuditEventType, IntegrationStatus
from mybot_schemas.models import CredentialReference, Integration
from mybot_security.crypto import constant_time_equals
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

log = get_logger(__name__)

#: How long an in-flight authorization may sit before its state expires.
#: Long enough for somebody to read a consent screen carefully; short enough
#: that a state record left in a browser history is worthless by the time
#: anyone finds it.
STATE_TTL_SECONDS = 600

#: Refresh a token this long before it actually expires, so a sync in progress
#: does not fail on a token that lapsed mid-request.
REFRESH_SKEW_SECONDS = 120


class OAuthError(RuntimeError):
    """Any failure in the flow. Never carries a token."""


class OAuthStateInvalid(OAuthError):
    """The callback's state did not match a live, owned, unused record.

    Deliberately does not say which of those it was.
    """


@dataclass(frozen=True)
class ProviderConfig:
    """One OAuth provider.

    ``read_scopes`` and ``write_scopes`` are separate because MyBot connects
    read-only and asks again later for write. An assistant that requests send
    permission on day one, before it has earned anything, is asking the user to
    make a decision they have no basis for.
    """

    key: str
    display_name: str
    authorize_url: str
    token_url: str
    revoke_url: str | None
    read_scopes: tuple[str, ...]
    write_scopes: tuple[str, ...] = ()
    #: Extra authorization params. Google needs these to return a refresh token
    #: at all, which is the kind of thing that is obvious only after it fails.
    extra_authorize_params: dict = field(default_factory=dict)


GOOGLE_CALENDAR = ProviderConfig(
    key="google_calendar",
    display_name="Google Calendar",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    revoke_url="https://oauth2.googleapis.com/revoke",
    read_scopes=("https://www.googleapis.com/auth/calendar.readonly",),
    write_scopes=("https://www.googleapis.com/auth/calendar.events",),
    extra_authorize_params={
        # Without `access_type=offline` Google returns no refresh token, and
        # without `prompt=consent` it returns one only on the very first grant
        # — so a re-connect silently produces an integration that dies in an
        # hour.
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
    },
)

GMAIL = ProviderConfig(
    key="gmail",
    display_name="Gmail",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    revoke_url="https://oauth2.googleapis.com/revoke",
    read_scopes=("https://www.googleapis.com/auth/gmail.readonly",),
    write_scopes=(
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/gmail.modify",
    ),
    extra_authorize_params=dict(GOOGLE_CALENDAR.extra_authorize_params),
)

PROVIDERS: dict[str, ProviderConfig] = {
    GOOGLE_CALENDAR.key: GOOGLE_CALENDAR,
    GMAIL.key: GMAIL,
}


@dataclass
class PendingAuthorization:
    """An in-flight consent, held server-side.

    Not a signed cookie: a signed blob that has already been consumed looks
    exactly like one that has not, and single-use is the property that matters.
    """

    state: str
    owner_id: str
    provider: str
    code_verifier: str
    redirect_uri: str
    scopes: tuple[str, ...]
    created_at: dt.datetime
    consumed: bool = False

    def expired(self, now: dt.datetime | None = None) -> bool:
        now = now or dt.datetime.now(dt.UTC)
        return (now - self.created_at).total_seconds() > STATE_TTL_SECONDS


class PendingStore:
    """Where in-flight authorizations live.

    In-process for the single-node Core, which is correct there and would be
    wrong for a multi-node deployment — same shape as the rate limiter. Records
    are dropped once consumed or expired, so this never accumulates.
    """

    def __init__(self):
        self._items: dict[str, PendingAuthorization] = {}

    def put(self, pending: PendingAuthorization) -> None:
        self._prune()
        self._items[pending.state] = pending

    def take(self, state: str) -> PendingAuthorization | None:
        """Fetch and consume in one step, so a replay finds nothing."""
        self._prune()
        pending = self._items.pop(state, None)
        return pending

    def _prune(self) -> None:
        for key, item in list(self._items.items()):
            if item.expired():
                self._items.pop(key, None)

    def __len__(self) -> int:
        return len(self._items)


def _pkce_pair() -> tuple[str, str]:
    """Generate a code verifier and its S256 challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


class OAuthFlow:
    """Runs the consent flow and keeps the resulting tokens safe."""

    def __init__(
        self,
        session: Session,
        vault,
        *,
        audit=None,
        client_id: str = "",
        client_secret: str = "",
        allowed_redirect_uris: tuple[str, ...] = (),
        store: PendingStore | None = None,
        http: httpx.Client | None = None,
    ):
        self.session = session
        self.vault = vault
        self.audit = audit
        self.client_id = client_id
        self.client_secret = client_secret
        self.allowed_redirect_uris = tuple(allowed_redirect_uris)
        self.store = store or PendingStore()
        self._http = http

    # ------------------------------------------------------------------
    # Step 1: send the owner to the provider
    # ------------------------------------------------------------------

    def begin(
        self,
        owner_id: str,
        provider_key: str,
        *,
        redirect_uri: str,
        include_write: bool = False,
    ) -> dict:
        """Build the authorization URL and remember what we are expecting."""
        provider = self._provider(provider_key)
        self._check_configured()
        self._check_redirect(redirect_uri)

        scopes = provider.read_scopes + (provider.write_scopes if include_write else ())
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(32)

        self.store.put(
            PendingAuthorization(
                state=state,
                owner_id=owner_id,
                provider=provider.key,
                code_verifier=verifier,
                redirect_uri=redirect_uri,
                scopes=scopes,
                created_at=dt.datetime.now(dt.UTC),
            )
        )

        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            **provider.extra_authorize_params,
        }
        from urllib.parse import urlencode

        url = f"{provider.authorize_url}?{urlencode(params)}"

        self._audit(
            owner_id,
            AuditEventType.INTEGRATION_CONNECTED,
            result="consent_started",
            details={"provider": provider.key, "scopes": list(scopes), "write": include_write},
        )
        log.info("oauth.begin", provider=provider.key, scopes=len(scopes), write=include_write)

        return {
            "authorization_url": url,
            "provider": provider.key,
            "display_name": provider.display_name,
            # Shown to the owner *before* they leave, so the consent screen is
            # not the first time they learn what is being asked for.
            "scopes": list(scopes),
            "expires_in_seconds": STATE_TTL_SECONDS,
        }

    # ------------------------------------------------------------------
    # Step 2: the provider sends them back
    # ------------------------------------------------------------------

    def complete(self, owner_id: str, *, state: str, code: str) -> Integration:
        """Exchange the code and store the result.

        ``owner_id`` is the *authenticated* caller, and it must match the owner
        who started the flow. That check is what stops an attacker completing
        their own consent inside somebody else's session.
        """
        pending = self.store.take(state or "")
        if pending is None or pending.expired():
            raise OAuthStateInvalid("this sign-in link is no longer valid; start again")
        if pending.consumed:
            raise OAuthStateInvalid("this sign-in link is no longer valid; start again")
        if not constant_time_equals(pending.owner_id, owner_id):
            # The login-CSRF case. Recorded as a security event by the caller.
            log.warning("oauth.state_owner_mismatch", provider=pending.provider)
            raise OAuthStateInvalid("this sign-in link is no longer valid; start again")

        provider = self._provider(pending.provider)
        tokens = self._exchange(
            provider,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": pending.redirect_uri,
                "code_verifier": pending.code_verifier,
            },
        )

        granted = tuple((tokens.get("scope") or " ".join(pending.scopes)).split())
        return self._persist(owner_id, provider, tokens, granted)

    # ------------------------------------------------------------------
    # Using and refreshing
    # ------------------------------------------------------------------

    def access_token(self, owner_id: str, provider_key: str, scopes: tuple[str, ...]) -> str:
        """Return a usable access token, refreshing if needed.

        This is the ``TokenProvider`` the adapters are injected with. Note the
        shape: it hands back one short-lived access token and never the refresh
        token, so a compromised adapter costs at most that token's remaining
        life.
        """
        provider = self._provider(provider_key)
        integration = self._integration(owner_id, provider.key)
        if integration is None or integration.credential_ref is None:
            raise OAuthError(f"{provider.display_name} is not connected")

        missing = [s for s in scopes if s not in (integration.scopes or [])]
        if missing:
            raise OAuthError(
                f"{provider.display_name} is connected without the access this needs "
                f"({', '.join(missing)}). Reconnect to grant it."
            )

        cached = integration.settings.get("access_token_expires_at")
        now = dt.datetime.now(dt.UTC)
        if cached:
            expires = dt.datetime.fromisoformat(cached)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=dt.UTC)
            if expires - dt.timedelta(seconds=REFRESH_SKEW_SECONDS) > now:
                token = self._read_secret(owner_id, f"{integration.credential_ref}/access")
                if token:
                    return token

        return self._refresh(owner_id, provider, integration)

    def _refresh(self, owner_id: str, provider: ProviderConfig, integration: Integration) -> str:
        refresh_token = self._read_secret(owner_id, f"{integration.credential_ref}/refresh")
        if not refresh_token:
            integration.status = IntegrationStatus.ERROR.value
            integration.last_error = "no refresh token stored; reconnect the account"
            self.session.flush()
            raise OAuthError(f"{provider.display_name} needs to be reconnected")

        try:
            tokens = self._exchange(
                provider,
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        except OAuthError:
            # A refresh failure usually means the owner revoked access at the
            # provider. Surface it as a reconnect prompt rather than a generic
            # sync error the user cannot act on.
            integration.status = IntegrationStatus.ERROR.value
            integration.last_error = "access was refused; reconnect the account"
            self.session.flush()
            raise

        self._store_tokens(owner_id, integration, tokens)
        return tokens["access_token"]

    # ------------------------------------------------------------------
    # Disconnecting
    # ------------------------------------------------------------------

    def disconnect(self, owner_id: str, provider_key: str) -> bool:
        """Revoke at the provider, then delete locally.

        Order matters. Deleting the local copy first would leave a live grant
        on Google's side that the owner can no longer see or revoke from here —
        the disconnect would look complete and would not be.
        """
        provider = self._provider(provider_key)
        integration = self._integration(owner_id, provider.key)
        if integration is None:
            return False

        ref = integration.credential_ref
        if ref and provider.revoke_url:
            token = self._read_secret(owner_id, f"{ref}/refresh")
            if token:
                try:
                    self._client().post(provider.revoke_url, data={"token": token})
                except httpx.HTTPError as exc:
                    # Recorded, not fatal: the local credential must still go.
                    log.warning("oauth.revoke_failed", provider=provider.key,
                                error=type(exc).__name__)

        if ref:
            self.vault.delete_secret(self.session, owner_id, f"{ref}/refresh")
            self.vault.delete_secret(self.session, owner_id, f"{ref}/access")
            cred = self.session.execute(
                sa.select(CredentialReference).where(
                    CredentialReference.owner_id == owner_id,
                    CredentialReference.ref == ref,
                )
            ).scalar_one_or_none()
            if cred is not None:
                cred.revoked_at = dt.datetime.now(dt.UTC)

        integration.status = IntegrationStatus.NOT_CONNECTED.value
        integration.credential_ref = None
        integration.scopes = []
        integration.write_enabled = False
        integration.settings = {}
        self.session.flush()

        self._audit(
            owner_id,
            AuditEventType.INTEGRATION_DISCONNECTED,
            result="disconnected",
            details={"provider": provider.key},
        )
        return True

    # ------------------------------------------------------------------

    def _persist(
        self,
        owner_id: str,
        provider: ProviderConfig,
        tokens: dict,
        granted: tuple[str, ...],
    ) -> Integration:
        integration = self._integration(owner_id, provider.key)
        if integration is None:
            integration = Integration(
                owner_id=owner_id,
                provider=provider.key,
                display_name=provider.display_name,
            )
            self.session.add(integration)
            self.session.flush()

        ref = integration.credential_ref or f"oauth/{provider.key}/{integration.id}"
        integration.credential_ref = ref
        integration.status = IntegrationStatus.CONNECTED.value
        integration.scopes = list(granted)
        integration.write_enabled = any(s in granted for s in provider.write_scopes)
        integration.last_error = None

        self._store_tokens(owner_id, integration, tokens)
        self._ensure_credential_reference(owner_id, provider, ref, granted)

        self._audit(
            owner_id,
            AuditEventType.INTEGRATION_CONNECTED,
            result="connected",
            # Scopes, never tokens. This record is meant to answer "what did I
            # agree to?" months later.
            details={"provider": provider.key, "scopes": list(granted),
                     "write_enabled": integration.write_enabled},
        )
        log.info("oauth.connected", provider=provider.key, scopes=len(granted))
        return integration

    def _store_tokens(self, owner_id: str, integration: Integration, tokens: dict) -> None:
        """Refresh token to the Vault; access token to the Vault; expiry to the row.

        The expiry is the only part that goes in an ordinary column, because it
        is not a secret and the refresh path needs to read it cheaply.
        """
        ref = integration.credential_ref
        if tokens.get("refresh_token"):
            # Absent on a refresh response, which is normal -- do not wipe the
            # stored one when the provider simply did not send a new one.
            self.vault.put_secret(
                self.session, owner_id, f"{ref}/refresh", tokens["refresh_token"]
            )
        self.vault.put_secret(self.session, owner_id, f"{ref}/access", tokens["access_token"])

        expires_in = int(tokens.get("expires_in") or 3600)
        settings = dict(integration.settings or {})
        settings["access_token_expires_at"] = (
            dt.datetime.now(dt.UTC) + dt.timedelta(seconds=expires_in)
        ).isoformat()
        integration.settings = settings
        self.session.flush()

    def _ensure_credential_reference(
        self, owner_id: str, provider: ProviderConfig, ref: str, scopes: tuple[str, ...]
    ) -> None:
        """The pointer the Vault checks scopes against at use time.

        Least privilege is enforced twice: here at grant time, and again by
        ``Vault.authorize_request`` on every use — so revoking a scope takes
        effect immediately rather than at the next reconnect.
        """
        cred = self.session.execute(
            sa.select(CredentialReference).where(
                CredentialReference.owner_id == owner_id, CredentialReference.ref == ref
            )
        ).scalar_one_or_none()
        if cred is None:
            cred = CredentialReference(
                owner_id=owner_id,
                ref=ref,
                provider=provider.key,
                purpose=f"{provider.display_name} access",
            )
            self.session.add(cred)
        cred.scopes = list(scopes)
        cred.revoked_at = None
        self.session.flush()

    def _exchange(self, provider: ProviderConfig, *, data: dict) -> dict:
        self._check_configured()
        payload = {**data, "client_id": self.client_id, "client_secret": self.client_secret}
        try:
            response = self._client().post(provider.token_url, data=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            # The provider's error body can echo the code or the client secret,
            # so only the exception type crosses this boundary.
            raise OAuthError(
                f"could not complete sign-in with {provider.display_name} "
                f"({type(exc).__name__})"
            ) from None
        except ValueError as exc:
            raise OAuthError("the provider returned an unreadable response") from exc

        if "access_token" not in body:
            raise OAuthError(f"{provider.display_name} did not return an access token")
        return body

    def _read_secret(self, owner_id: str, ref: str) -> str | None:
        try:
            return self.vault.reveal_secret(
                self.session, owner_id, ref, purpose="oauth token use"
            ).decode("utf-8")
        except Exception:  # noqa: BLE001 - absent or undecryptable, same answer
            return None

    def _integration(self, owner_id: str, provider_key: str) -> Integration | None:
        return self.session.execute(
            sa.select(Integration).where(
                Integration.owner_id == owner_id, Integration.provider == provider_key
            )
        ).scalar_one_or_none()

    def _client(self) -> httpx.Client:
        return self._http or httpx.Client(timeout=20.0)

    @staticmethod
    def _provider(key: str) -> ProviderConfig:
        provider = PROVIDERS.get(key)
        if provider is None:
            raise OAuthError(f"unknown provider: {key}")
        return provider

    def _check_configured(self) -> None:
        if not self.client_id or not self.client_secret:
            raise OAuthError(
                "No OAuth client is configured. Set MYBOT_GOOGLE_CLIENT_ID and "
                "MYBOT_GOOGLE_CLIENT_SECRET, or stay in mock mode."
            )

    def _check_redirect(self, redirect_uri: str) -> None:
        """Exact match against the allowlist.

        Prefix matching on redirect URIs is how open redirectors become account
        takeovers, so there is no normalisation and no trailing-slash
        forgiveness here.
        """
        if redirect_uri not in self.allowed_redirect_uris:
            raise OAuthError("that redirect address is not allowed for this installation")

    def _audit(self, owner_id: str, event_type, *, result: str, details: dict) -> None:
        if self.audit is None:
            return
        self.audit.record(
            owner_id,
            event_type,
            actor_type=ActorType.USER,
            actor_id=owner_id,
            reason="owner managed a connected account",
            result=result,
            details=details,
        )


__all__ = [
    "GMAIL",
    "GOOGLE_CALENDAR",
    "PROVIDERS",
    "REFRESH_SKEW_SECONDS",
    "STATE_TTL_SECONDS",
    "OAuthError",
    "OAuthFlow",
    "OAuthStateInvalid",
    "PendingAuthorization",
    "PendingStore",
    "ProviderConfig",
]
