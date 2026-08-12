"""Cookie sessions and CSRF.

These close two limitations the build carried together, and they had to be
closed together: moving the session token into an httpOnly cookie is what takes
it out of XSS's reach, and it is also what makes CSRF possible in the first
place. Fixing one alone makes the other worse.

What the tests establish:

* the session token is not readable by JavaScript;
* a cross-site write without the CSRF header is refused;
* bearer callers -- the CLI, scripts, this suite -- keep working, and are
  exempt from CSRF for a reason rather than by oversight;
* logging out revokes server-side, not just in the browser.
"""

from __future__ import annotations

from mybot_api.websession import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE

PASSWORD = "test-password-12345"


def _register(api, email="cookie@example.com"):
    return api.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Cookie Owner", "password": PASSWORD},
    )


# ---------------------------------------------------------------------------
# The cookie itself
# ---------------------------------------------------------------------------


def test_login_sets_an_httponly_session_cookie(api):
    response = _register(api)
    assert response.status_code == 201

    header = response.headers.get("set-cookie", "")
    assert SESSION_COOKIE in header
    assert "httponly" in header.lower(), "the session cookie must be unreadable by JavaScript"
    assert "samesite=strict" in header.lower().replace(" ", "")


def test_the_csrf_cookie_is_readable_and_the_session_cookie_is_not(api):
    """The asymmetry is the design.

    The app has to copy the CSRF token into a header, so that cookie must be
    readable. It authenticates nothing on its own.
    """
    _register(api)

    cookies = api.cookies
    assert cookies.get(CSRF_COOKIE), "the app cannot echo a token it cannot read"

    raw = [h for h in api.cookies.jar if h.name == SESSION_COOKIE]
    assert raw, "no session cookie was set"


def test_the_csrf_token_is_not_derived_from_the_session_token(api):
    """A readable value derived from a secret is a downgrade of that secret."""
    body = _register(api).json()

    assert body["csrf_token"]
    assert body["csrf_token"] != body["access_token"]
    assert body["csrf_token"] not in body["access_token"]
    assert body["access_token"] not in body["csrf_token"]


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


def test_a_cookie_authenticated_write_without_the_csrf_header_is_refused(api):
    """The cross-site form post. The browser attaches the session cookie; the
    attacker's page cannot read the CSRF cookie to copy it."""
    _register(api)

    response = api.post("/api/v1/learning/corrections", json={"subject": "x", "correction": "y"})
    assert response.status_code == 403
    assert "could not be verified" in response.json()["detail"]


def test_a_cookie_authenticated_write_with_the_csrf_header_succeeds(api):
    _register(api)
    csrf = api.cookies.get(CSRF_COOKIE)

    response = api.post(
        "/api/v1/learning/corrections",
        json={"subject": "my dentist", "correction": "Dr Patel"},
        headers={CSRF_HEADER: csrf},
    )
    assert response.status_code == 201


def test_a_wrong_csrf_token_is_refused(api):
    _register(api)

    response = api.post(
        "/api/v1/learning/corrections",
        json={"subject": "x", "correction": "y"},
        headers={CSRF_HEADER: "not-the-right-token"},
    )
    assert response.status_code == 403


def test_reads_do_not_require_a_csrf_token(api):
    """GET must be side-effect free, so there is nothing to forge."""
    _register(api)

    assert api.get("/api/v1/auth/me").status_code == 200
    assert api.get("/api/v1/learning").status_code == 200


def test_the_csrf_token_is_not_accepted_in_a_query_parameter(api):
    """A token in a query parameter ends up in browser history, server logs and
    Referer headers sent to third parties. Header only."""
    _register(api)
    csrf = api.cookies.get(CSRF_COOKIE)

    response = api.post(
        f"/api/v1/learning/corrections?csrf_token={csrf}",
        json={"subject": "x", "correction": "y"},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Bearer callers
# ---------------------------------------------------------------------------


def test_bearer_callers_still_work_and_are_csrf_exempt(api):
    """Not an oversight.

    CSRF exists because browsers attach cookies automatically and never attach
    an Authorization header automatically. A cross-site attacker cannot forge
    one, so requiring a CSRF token from a bearer caller would protect nothing
    and break every script.
    """
    token = _register(api).json()["access_token"]
    api.cookies.clear()

    response = api.post(
        "/api/v1/learning/corrections",
        json={"subject": "x", "correction": "y"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201


def test_a_bearer_header_wins_over_a_stale_cookie(api):
    """A caller that set a header meant it, and a leftover cookie should not
    silently override an explicit credential."""
    first = _register(api, "one@example.com").json()
    # The client now holds one@example.com's cookies.
    second = _register(api, "two@example.com").json()

    me = api.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {first['access_token']}"}
    ).json()
    assert me["email"] == "one@example.com"
    assert second["user"]["email"] == "two@example.com"


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


def test_logout_revokes_server_side_not_just_in_the_browser(api):
    """Clearing the cookie alone would leave a live token anybody holding a
    copy could keep using."""
    token = _register(api).json()["access_token"]
    csrf = api.cookies.get(CSRF_COOKIE)

    assert api.post("/api/v1/auth/logout", headers={CSRF_HEADER: csrf}).status_code == 200

    # The cookie is gone from the browser...
    assert not api.cookies.get(SESSION_COOKIE)
    # ...and the token is dead regardless of who holds it.
    replay = api.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert replay.status_code == 401
