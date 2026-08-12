"""OAuth consent, token custody, and disconnection.

No Google credentials exist in this build, so the flow is driven against a fake
authorization server. That is the right level anyway: what needs proving is not
that `httpx` can POST, it is that the flow holds its security properties.

The attacks these tests encode:

* **login-CSRF** — the attacker starts a flow with *their* account and tricks
  the victim's browser into the callback, so the victim's MyBot ends up
  connected to the attacker's mailbox;
* **code interception** — an authorization code stolen in transit, useless
  without the PKCE verifier;
* **state replay** — the same callback submitted twice;
* **open redirect** — a redirect_uri the installation never allowed;
* **database theft** — a dump that yields a working refresh token.
"""

from __future__ import annotations

import datetime as dt
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import sqlalchemy as sa
from mybot_schemas.enums import IntegrationStatus
from mybot_schemas.models import CredentialReference, Integration, VaultSecret
from mybot_services.oauth import (
    PROVIDERS,
    OAuthError,
    OAuthFlow,
    OAuthStateInvalid,
    PendingStore,
)

REDIRECT = "http://localhost:3000/integrations/callback"


class FakeGoogle:
    """A stand-in authorization server.

    Records what it was sent so the tests can assert on the *request*, which is
    where the security properties live — PKCE verifier, grant type, the client
    secret never appearing in a URL.
    """

    def __init__(self):
        self.token_requests: list[dict] = []
        self.revocations: list[dict] = []
        self.refresh_token = "refresh-abc123"
        self.access_token = "access-xyz789"
        self.fail_next = False
        self.omit_refresh = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = dict(parse_qs(request.content.decode()))
        flat = {k: v[0] for k, v in body.items()}

        if "revoke" in str(request.url):
            self.revocations.append(flat)
            return httpx.Response(200, json={})

        self.token_requests.append(flat)
        if self.fail_next:
            self.fail_next = False
            return httpx.Response(400, json={"error": "invalid_grant"})

        payload = {
            "access_token": self.access_token,
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/calendar.readonly",
            "token_type": "Bearer",
        }
        if not self.omit_refresh:
            payload["refresh_token"] = self.refresh_token
        return httpx.Response(200, json=payload)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def google():
    return FakeGoogle()


@pytest.fixture
def flow(db, vault, services, google):
    return OAuthFlow(
        db,
        vault,
        audit=services.audit,
        client_id="test-client-id",
        client_secret="test-client-secret",
        allowed_redirect_uris=(REDIRECT,),
        store=PendingStore(),
        http=google.client(),
    )


def _connect(flow, owner_id, provider="google_calendar", **kwargs):
    started = flow.begin(owner_id, provider, redirect_uri=REDIRECT, **kwargs)
    state = parse_qs(urlparse(started["authorization_url"]).query)["state"][0]
    return started, flow.complete(owner_id, state=state, code="auth-code-1")


# ---------------------------------------------------------------------------
# The happy path, and what it does with the tokens
# ---------------------------------------------------------------------------


def test_a_full_connect_stores_scopes_and_marks_connected(db, alice, flow, as_alice):
    started, integration = _connect(flow, alice.id)

    assert integration.status == IntegrationStatus.CONNECTED.value
    assert integration.scopes == ["https://www.googleapis.com/auth/calendar.readonly"]
    assert integration.credential_ref
    # Read-only by default: an assistant that asks for send permission on day
    # one is asking for a decision the owner has no basis for.
    assert integration.write_enabled is False
    assert started["scopes"] == list(PROVIDERS["google_calendar"].read_scopes)


def test_the_authorization_url_carries_pkce_and_state(db, alice, flow, as_alice):
    started = flow.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
    params = parse_qs(urlparse(started["authorization_url"]).query)

    assert params["code_challenge_method"] == ["S256"]
    assert len(params["code_challenge"][0]) >= 40
    assert params["response_type"] == ["code"], "implicit flow must never be used"
    assert params["state"][0]
    # Without these Google returns no refresh token at all, and the integration
    # silently dies an hour after connecting.
    assert params["access_type"] == ["offline"]
    assert params["prompt"] == ["consent"]
    # The secret is never in a URL the browser sees.
    assert "client_secret" not in params


def test_the_code_exchange_sends_the_verifier_not_the_challenge(db, alice, flow, google, as_alice):
    started = flow.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
    query = parse_qs(urlparse(started["authorization_url"]).query)
    challenge = query["code_challenge"][0]

    flow.complete(alice.id, state=query["state"][0], code="auth-code-1")

    sent = google.token_requests[0]
    assert sent["grant_type"] == "authorization_code"
    assert sent["code_verifier"]
    assert sent["code_verifier"] != challenge, "the verifier must not be the challenge"
    assert sent["redirect_uri"] == REDIRECT


def test_write_scopes_are_a_separate_deliberate_grant(db, alice, flow, as_alice):
    started = flow.begin(
        alice.id, "google_calendar", redirect_uri=REDIRECT, include_write=True
    )
    scopes = parse_qs(urlparse(started["authorization_url"]).query)["scope"][0].split()

    assert "https://www.googleapis.com/auth/calendar.events" in scopes


# ---------------------------------------------------------------------------
# Token custody
# ---------------------------------------------------------------------------


def test_no_token_is_stored_in_an_ordinary_column(db, alice, flow, google, as_alice):
    """The database-theft case.

    A dump of every non-Vault table must not yield a working credential.
    """
    _, integration = _connect(flow, alice.id)
    db.flush()

    import json

    row = {c.name: str(getattr(integration, c.name)) for c in integration.__table__.columns}
    blob = json.dumps(row)
    assert google.refresh_token not in blob
    assert google.access_token not in blob

    # And the Vault copy is ciphertext, not the token.
    secrets_ = db.execute(sa.select(VaultSecret)).scalars().all()
    assert secrets_
    for secret in secrets_:
        assert google.refresh_token.encode() not in secret.ciphertext
        assert google.access_token.encode() not in secret.ciphertext


def test_the_refresh_token_never_reaches_an_adapter(db, alice, flow, google, as_alice):
    """`access_token` is the whole surface an adapter gets.

    A compromised adapter costs one short-lived token, not permanent access.
    """
    _connect(flow, alice.id)

    token = flow.access_token(
        alice.id, "google_calendar", ("https://www.googleapis.com/auth/calendar.readonly",)
    )
    assert token == google.access_token
    assert token != google.refresh_token


def test_a_cached_access_token_is_reused_until_it_nearly_expires(
    db, alice, flow, google, as_alice
):
    _connect(flow, alice.id)
    calls_after_connect = len(google.token_requests)

    flow.access_token(
        alice.id, "google_calendar", ("https://www.googleapis.com/auth/calendar.readonly",)
    )
    assert len(google.token_requests) == calls_after_connect, "should not have refreshed"


def test_an_expiring_token_is_refreshed(db, alice, flow, google, as_alice):
    _, integration = _connect(flow, alice.id)
    calls = len(google.token_requests)

    settings = dict(integration.settings)
    settings["access_token_expires_at"] = (
        dt.datetime.now(dt.UTC) + dt.timedelta(seconds=5)
    ).isoformat()
    integration.settings = settings
    db.flush()

    flow.access_token(
        alice.id, "google_calendar", ("https://www.googleapis.com/auth/calendar.readonly",)
    )
    assert len(google.token_requests) == calls + 1
    assert google.token_requests[-1]["grant_type"] == "refresh_token"


def test_a_refresh_response_without_a_new_refresh_token_keeps_the_old_one(
    db, alice, flow, google, vault, as_alice
):
    """Providers usually omit it on refresh. Wiping the stored one because the
    response did not repeat it would break the integration an hour later."""
    _, integration = _connect(flow, alice.id)
    ref = integration.credential_ref

    google.omit_refresh = True
    settings = dict(integration.settings)
    settings["access_token_expires_at"] = dt.datetime.now(dt.UTC).isoformat()
    integration.settings = settings
    db.flush()

    flow.access_token(
        alice.id, "google_calendar", ("https://www.googleapis.com/auth/calendar.readonly",)
    )

    stored = vault.reveal_secret(db, alice.id, f"{ref}/refresh", purpose="test")
    assert stored.decode() == google.refresh_token


def test_a_failed_refresh_asks_for_reconnection(db, alice, flow, google, as_alice):
    """Usually means the owner revoked access at the provider. A generic sync
    error would leave them with nothing to act on."""
    _, integration = _connect(flow, alice.id)
    settings = dict(integration.settings)
    settings["access_token_expires_at"] = dt.datetime.now(dt.UTC).isoformat()
    integration.settings = settings
    db.flush()

    google.fail_next = True
    with pytest.raises(OAuthError):
        flow.access_token(
            alice.id, "google_calendar", ("https://www.googleapis.com/auth/calendar.readonly",)
        )

    assert integration.status == IntegrationStatus.ERROR.value
    assert "reconnect" in (integration.last_error or "")


def test_using_a_scope_that_was_not_granted_is_refused(db, alice, flow, as_alice):
    _connect(flow, alice.id)

    with pytest.raises(OAuthError) as excinfo:
        flow.access_token(
            alice.id, "google_calendar", ("https://www.googleapis.com/auth/calendar.events",)
        )
    assert "Reconnect" in str(excinfo.value)


# ---------------------------------------------------------------------------
# State: CSRF, replay, expiry
# ---------------------------------------------------------------------------


def test_a_callback_for_another_owner_is_refused(db, alice, bob, flow, as_alice):
    """Login-CSRF, the attack this binding exists for.

    The attacker begins consent with their own Google account and gets the
    victim's browser to the callback. Without the owner check, the victim's
    MyBot connects to the attacker's mailbox.
    """
    started = flow.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
    state = parse_qs(urlparse(started["authorization_url"]).query)["state"][0]

    with pytest.raises(OAuthStateInvalid):
        flow.complete(bob.id, state=state, code="auth-code-1")

    assert db.execute(sa.select(Integration)).scalars().all() == []


def test_a_state_cannot_be_replayed(db, alice, flow, as_alice):
    started = flow.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
    state = parse_qs(urlparse(started["authorization_url"]).query)["state"][0]

    flow.complete(alice.id, state=state, code="auth-code-1")
    with pytest.raises(OAuthStateInvalid):
        flow.complete(alice.id, state=state, code="auth-code-1")


def test_an_unknown_or_empty_state_is_refused(db, alice, flow, as_alice):
    for bad in ("", "not-a-real-state", "x" * 64):
        with pytest.raises(OAuthStateInvalid):
            flow.complete(alice.id, state=bad, code="auth-code-1")


def test_an_expired_state_is_refused(db, alice, flow, as_alice, monkeypatch):
    from mybot_services.oauth import flow as flow_mod

    started = flow.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
    state = parse_qs(urlparse(started["authorization_url"]).query)["state"][0]

    monkeypatch.setattr(flow_mod, "STATE_TTL_SECONDS", -1)
    with pytest.raises(OAuthStateInvalid):
        flow.complete(alice.id, state=state, code="auth-code-1")


def test_the_failure_message_does_not_say_which_check_failed(db, alice, bob, flow, as_alice):
    """Distinguishing "expired" from "wrong owner" from "never existed" hands
    an attacker a free oracle."""
    started = flow.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
    state = parse_qs(urlparse(started["authorization_url"]).query)["state"][0]

    messages = set()
    with pytest.raises(OAuthStateInvalid) as e1:
        flow.complete(bob.id, state=state, code="c")
    messages.add(str(e1.value))
    with pytest.raises(OAuthStateInvalid) as e2:
        flow.complete(alice.id, state="never-existed", code="c")
    messages.add(str(e2.value))

    assert len(messages) == 1


def test_consumed_states_do_not_accumulate(db, alice, flow, as_alice):
    for _ in range(5):
        started = flow.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
        state = parse_qs(urlparse(started["authorization_url"]).query)["state"][0]
        flow.complete(alice.id, state=state, code="c")

    assert len(flow.store) == 0


# ---------------------------------------------------------------------------
# Redirect allowlist
# ---------------------------------------------------------------------------


def test_an_unlisted_redirect_is_refused(db, alice, flow, as_alice):
    with pytest.raises(OAuthError):
        flow.begin(alice.id, "google_calendar", redirect_uri="https://evil.example/callback")


def test_the_redirect_allowlist_is_exact_not_prefix(db, alice, flow, as_alice):
    """Prefix matching on redirect URIs is how open redirectors become account
    takeovers."""
    for near_miss in (
        REDIRECT + "/../evil",
        REDIRECT + ".evil.com",
        REDIRECT + "?next=https://evil.example",
        REDIRECT.replace("http://", "https://"),
        REDIRECT + "/",
    ):
        with pytest.raises(OAuthError):
            flow.begin(alice.id, "google_calendar", redirect_uri=near_miss)


# ---------------------------------------------------------------------------
# Configuration and disconnection
# ---------------------------------------------------------------------------


def test_an_unconfigured_client_refuses_rather_than_half_working(db, alice, vault, as_alice):
    bare = OAuthFlow(db, vault, allowed_redirect_uris=(REDIRECT,))

    with pytest.raises(OAuthError) as excinfo:
        bare.begin(alice.id, "google_calendar", redirect_uri=REDIRECT)
    assert "No OAuth client is configured" in str(excinfo.value)


def test_no_oauth_client_ships_by_default():
    """A shipped client id would mean every installation shared one identity at
    the provider."""
    from mybot_schemas.config import get_settings

    settings = get_settings()
    assert settings.google_client_id == ""
    assert settings.google_client_secret == ""


def test_disconnect_revokes_at_the_provider_before_deleting_locally(
    db, alice, flow, google, as_alice
):
    """Order matters. Deleting locally first leaves a live grant at Google the
    owner can no longer see or revoke from here."""
    _, integration = _connect(flow, alice.id)
    ref = integration.credential_ref

    assert flow.disconnect(alice.id, "google_calendar") is True

    assert google.revocations, "the provider was never told"
    assert google.revocations[0]["token"] == google.refresh_token

    assert integration.status == IntegrationStatus.NOT_CONNECTED.value
    assert integration.credential_ref is None
    assert integration.scopes == []
    assert db.execute(
        sa.select(VaultSecret).where(VaultSecret.ref.like(f"{ref}%"))
    ).scalars().all() == []

    cred = db.execute(
        sa.select(CredentialReference).where(CredentialReference.ref == ref)
    ).scalar_one()
    assert cred.revoked_at is not None


def test_disconnect_completes_even_if_the_provider_is_unreachable(db, alice, vault, services, as_alice):
    """The local credential must go regardless. Leaving it because Google was
    down would mean "disconnect" silently did nothing."""

    def explode(request):
        raise httpx.ConnectError("network down")

    google = FakeGoogle()
    connecting = OAuthFlow(
        db, vault, audit=services.audit, client_id="c", client_secret="s",
        allowed_redirect_uris=(REDIRECT,), http=google.client(),
    )
    _, integration = _connect(connecting, alice.id)

    offline = OAuthFlow(
        db, vault, audit=services.audit, client_id="c", client_secret="s",
        allowed_redirect_uris=(REDIRECT,),
        http=httpx.Client(transport=httpx.MockTransport(explode)),
    )
    # Reuse the same store-independent path: disconnect does not need state.
    assert offline.disconnect(alice.id, "google_calendar") is True
    assert integration.credential_ref is None


def test_disconnecting_something_never_connected_is_not_an_error(db, alice, flow, as_alice):
    assert flow.disconnect(alice.id, "gmail") is False


def test_an_unknown_provider_is_refused(db, alice, flow, as_alice):
    with pytest.raises(OAuthError):
        flow.begin(alice.id, "facebook", redirect_uri=REDIRECT)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_connecting_is_audited_with_scopes_and_never_tokens(
    db, alice, flow, google, services, as_alice
):
    """The record has to answer "what did I agree to?" months later, without
    becoming a place a token is written down."""
    _connect(flow, alice.id)

    import json

    events = services.audit.list_events(alice.id, limit=50)
    connected = [e for e in events if e.event_type == "integration.connected"]
    assert connected

    blob = json.dumps([e.details for e in events])
    assert google.refresh_token not in blob
    assert google.access_token not in blob
    assert "calendar.readonly" in blob


def test_one_owner_cannot_reach_anothers_integration(db, alice, bob, flow, as_alice):
    _connect(flow, alice.id)

    with pytest.raises(OAuthError):
        flow.access_token(
            bob.id, "google_calendar", ("https://www.googleapis.com/auth/calendar.readonly",)
        )
    assert flow.disconnect(bob.id, "google_calendar") is False


# ---------------------------------------------------------------------------
# The HTTP surface
# ---------------------------------------------------------------------------


def test_connecting_requires_strong_auth(api, registered, elevate):
    """Handing MyBot reach into a mailbox is exactly what somebody with a
    stolen tab would want to do."""
    account = registered()

    weak = api.post(
        "/api/v1/integrations/connect",
        json={"provider": "google_calendar", "redirect_uri": REDIRECT},
        headers=account["headers"],
    )
    assert weak.status_code in (401, 403)

    elevate(account)
    strong = api.post(
        "/api/v1/integrations/connect",
        json={"provider": "google_calendar", "redirect_uri": REDIRECT},
        headers=account["headers"],
    )
    # No client is configured in tests, so it refuses -- but for the right
    # reason, having passed the auth check.
    assert strong.status_code == 400
    assert "No OAuth client is configured" in strong.json()["detail"]


def test_disconnecting_requires_strong_auth(api, registered):
    account = registered()
    response = api.delete("/api/v1/integrations/google_calendar", headers=account["headers"])
    assert response.status_code in (401, 403)


def test_the_callback_requires_a_session(api):
    """A bare public callback cannot tell whose flow it is completing, which is
    what login-CSRF exploits."""
    response = api.post(
        "/api/v1/integrations/callback", json={"state": "x", "code": "y"}
    )
    assert response.status_code in (401, 403)


def test_providers_lists_scopes_before_anybody_leaves(api, registered):
    """The consent screen should not be the first time somebody learns what is
    being asked for."""
    account = registered()
    body = api.get("/api/v1/integrations/providers", headers=account["headers"]).json()

    keys = {p["key"] for p in body["providers"]}
    assert keys == {"google_calendar", "gmail"}
    calendar = next(p for p in body["providers"] if p["key"] == "google_calendar")
    assert calendar["read_scopes"] == ["https://www.googleapis.com/auth/calendar.readonly"]
    assert calendar["connected"] is False
    assert body["configured"] is False


def test_a_bad_callback_is_recorded_as_a_security_event(api, registered):
    account = registered()
    response = api.post(
        "/api/v1/integrations/callback",
        json={"state": "forged-state", "code": "whatever"},
        headers=account["headers"],
    )
    assert response.status_code == 400

    events = api.get("/api/v1/security/events", headers=account["headers"]).json()
    summaries = " ".join(e["summary"] for e in events["items"])
    assert "callback" in summaries


def test_disconnecting_something_never_connected_is_404(api, registered, elevate):
    account = registered()
    elevate(account)
    response = api.delete("/api/v1/integrations/gmail", headers=account["headers"])
    assert response.status_code == 404
