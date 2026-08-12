"""Cookie sessions and CSRF protection.

Closes two limitations this build had been carrying together, because closing
either one alone makes the other worse:

* the session token lived in ``sessionStorage``, readable by any XSS;
* there were no CSRF tokens, which was *safe* precisely because auth was
  bearer-only — a cross-site form post carries no ``Authorization`` header.

Moving the token into an httpOnly cookie takes it out of JavaScript's reach and
hands the browser the job of attaching it, which is exactly what makes CSRF
possible. So the two changes are one change.

## The shape

**Session cookie: httpOnly, SameSite=Strict, Secure outside development.**
httpOnly means XSS cannot read it. SameSite=Strict means the browser will not
attach it to a request originating from another site at all, which is the
primary CSRF defence and is enforced by the browser rather than by us.

**CSRF token: a second, readable cookie, echoed in a header.** The classic
double-submit. An attacker's page can cause a request to be *sent* with the
session cookie, but same-origin policy stops it *reading* the CSRF cookie to
copy into the header. Belt and braces on top of SameSite, because SameSite is a
browser behaviour and browsers vary.

The CSRF token is deliberately **not** derived from the session token. A
readable value derived from a secret is a downgrade of that secret.

**Bearer tokens still work.** The CLI, scripts and tests are not browsers and
have no cookie jar or CSRF concept. Crucially, a bearer request is exempt from
the CSRF check — and that is safe rather than a hole, because the whole reason
CSRF exists is that browsers attach cookies automatically and never attach an
``Authorization`` header automatically. A cross-site attacker cannot forge one.

## The mistake this avoids

The tempting shortcut is to accept the CSRF token from a form field *or* a
header *or* a query parameter, "for convenience". A token accepted in a query
parameter ends up in browser history, in server logs, and in ``Referer``
headers sent to third parties. Header only.
"""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, Response, status
from mybot_schemas.config import get_settings
from mybot_security.crypto import constant_time_equals

#: Holds the session token. Unreadable by JavaScript.
SESSION_COOKIE = "mybot_session"
#: Holds the CSRF token. Deliberately readable, so the app can echo it.
CSRF_COOKIE = "mybot_csrf"
CSRF_HEADER = "X-MyBot-CSRF"

#: Methods that change something. GET/HEAD/OPTIONS are exempt because they must
#: be side-effect free -- if a GET in this API ever mutates, that is the bug.
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def issue_session_cookies(response: Response, token: str, *, max_age: int) -> str:
    """Attach the session and CSRF cookies. Returns the CSRF token.

    The caller echoes the CSRF token in the response body so a fresh client can
    use it immediately without waiting for a round trip to read its own cookie.
    """
    settings = get_settings()
    secure = settings.is_production

    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
    )
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=max_age,
        # Readable on purpose: the app has to copy it into a header. This
        # cookie authenticates nothing on its own.
        httponly=False,
        samesite="strict",
        secure=secure,
        path="/",
    )
    return csrf


def clear_session_cookies(response: Response) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/")


def token_from_request(request: Request, authorization: str | None) -> tuple[str | None, str]:
    """Find the session token and say how it arrived.

    Returns ``(token, source)`` where source is ``bearer``, ``cookie`` or
    ``none``. The source matters: only cookie-authenticated requests need a
    CSRF check.

    Bearer wins when both are present. A caller that went to the trouble of
    setting a header meant it, and it keeps a stale cookie from silently
    overriding an explicit credential.
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if token:
            return token, "bearer"

    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        return cookie, "cookie"
    return None, "none"


def enforce_csrf(request: Request, source: str) -> None:
    """Require a matching CSRF token on cookie-authenticated writes.

    Exempt for bearer callers: a cross-site attacker cannot make a browser
    attach an ``Authorization`` header, which is the entire premise of CSRF.
    Exempt for safe methods, which must not change anything anyway.
    """
    if source != "cookie":
        return
    if request.method.upper() not in UNSAFE_METHODS:
        return

    sent = request.headers.get(CSRF_HEADER, "")
    expected = request.cookies.get(CSRF_COOKIE, "")
    if not sent or not expected or not constant_time_equals(sent, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This request could not be verified. Reload the page and try again.",
        )


__all__ = [
    "CSRF_COOKIE",
    "CSRF_HEADER",
    "SESSION_COOKIE",
    "UNSAFE_METHODS",
    "clear_session_cookies",
    "enforce_csrf",
    "issue_session_cookies",
    "token_from_request",
]
