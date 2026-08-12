"""Google Calendar and Gmail adapters.

**Status, stated plainly:** the request shapes below target the real Google
APIs and the code paths are complete, but they have *not* been executed
against live Google endpoints in this build -- no OAuth credentials exist
here. They are wired, not verified. ``MYBOT_INTEGRATIONS_MODE`` defaults to
``mock`` for exactly that reason, and connecting a real account is an explicit
opt-in.

Security decisions worth noting:

* Access tokens are never held by this module. It asks the Vault for a
  short-lived grant and exchanges it at the boundary, so a compromised adapter
  yields at most one token's remaining lifetime rather than a refresh token.
* Scopes are least-privilege and split read/write. Read access is granted at
  connect time; write access is a separate, later grant the owner must make
  deliberately.
* Everything fetched is returned as data destined for ``UntrustedContent``.
  Nothing here interprets a message body.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable

import httpx
from mybot_schemas.enums import ExecutionOutcome

from ..base import (
    ActionNotSupported,
    CalendarConnector,
    CalendarEventData,
    EmailConnector,
    EmailMessageData,
    ExecutionContext,
    ExecutionResult,
    IntegrationAdapter,
    IntegrationUnavailable,
)

CALENDAR_API = "https://www.googleapis.com/calendar/v3"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1"

#: Read-only to begin with. Write scopes are requested separately, only when
#: the owner enables write access for the integration.
CALENDAR_READ_SCOPES = ("https://www.googleapis.com/auth/calendar.readonly",)
CALENDAR_WRITE_SCOPES = ("https://www.googleapis.com/auth/calendar.events",)
GMAIL_READ_SCOPES = ("https://www.googleapis.com/auth/gmail.readonly",)
GMAIL_WRITE_SCOPES = (
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.modify",
)

#: Supplied by the API layer; returns a live access token for (owner, scopes)
#: or raises. Injected rather than imported so this package never depends on
#: the Vault directly.
TokenProvider = Callable[[str, tuple[str, ...]], str]


class _GoogleBase:
    def __init__(self, token_provider: TokenProvider | None, timeout: float = 15.0):
        self._token_provider = token_provider
        self._timeout = timeout

    def _token(self, owner_id: str, scopes: tuple[str, ...]) -> str:
        if self._token_provider is None:
            raise IntegrationUnavailable(
                "Google is not connected. Connect an account in Settings → Integrations, "
                "or run in mock mode."
            )
        return self._token_provider(owner_id, scopes)

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            timeout=self._timeout,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )


class GoogleCalendarConnector(_GoogleBase, CalendarConnector):
    provider = "google_calendar"
    is_mock = False

    def list_events(
        self, owner_id: str, since: dt.datetime, until: dt.datetime
    ) -> list[CalendarEventData]:
        token = self._token(owner_id, CALENDAR_READ_SCOPES)
        params = {
            "timeMin": since.astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
            "timeMax": until.astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
            "singleEvents": "true",
            "orderBy": "startTime",
            "maxResults": "250",
        }
        try:
            with self._client(token) as client:
                resp = client.get(f"{CALENDAR_API}/calendars/primary/events", params=params)
                resp.raise_for_status()
                payload = resp.json()
        except httpx.HTTPError as exc:
            raise IntegrationUnavailable(f"Google Calendar unreachable: {type(exc).__name__}") from exc

        events: list[CalendarEventData] = []
        for item in payload.get("items", []):
            start = _parse_google_time(item.get("start", {}))
            end = _parse_google_time(item.get("end", {}))
            if start is None or end is None:
                continue
            events.append(
                CalendarEventData(
                    external_id=item["id"],
                    title=item.get("summary") or "(no title)",
                    start_at=start,
                    end_at=end,
                    calendar_id="primary",
                    description=item.get("description"),
                    location=item.get("location"),
                    attendees=tuple(
                        a.get("email", "") for a in item.get("attendees", []) if a.get("email")
                    ),
                    organizer=(item.get("organizer") or {}).get("email"),
                    all_day="date" in item.get("start", {}),
                    status=item.get("status", "confirmed"),
                )
            )
        return events


class GoogleCalendarAdapter(_GoogleBase, IntegrationAdapter):
    provider = "google_calendar"
    display_name = "Google Calendar"
    supported_actions = frozenset({"calendar.reschedule", "calendar.create", "calendar.cancel"})
    is_mock = False

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        if not self.supports(ctx.action_type):
            raise ActionNotSupported(f"{self.provider} cannot execute {ctx.action_type}")
        token = self._token(ctx.owner_id, CALENDAR_WRITE_SCOPES)
        params = ctx.params
        calendar_id = params.get("calendar_id", "primary")

        try:
            with self._client(token) as client:
                if ctx.action_type == "calendar.reschedule":
                    resp = client.patch(
                        f"{CALENDAR_API}/calendars/{calendar_id}/events/{params['event_id']}",
                        json={
                            "start": {"dateTime": params["new_start"]},
                            "end": {"dateTime": params["new_end"]},
                        },
                    )
                elif ctx.action_type == "calendar.create":
                    resp = client.post(
                        f"{CALENDAR_API}/calendars/{calendar_id}/events",
                        json={
                            "summary": params["title"],
                            "start": {"dateTime": params["start"]},
                            "end": {"dateTime": params["end"]},
                            "location": params.get("location"),
                            "description": params.get("description"),
                        },
                    )
                else:  # calendar.cancel
                    resp = client.delete(
                        f"{CALENDAR_API}/calendars/{calendar_id}/events/{params['event_id']}",
                        params={"sendUpdates": "all" if params.get("notify_attendees") else "none"},
                    )
        except httpx.TimeoutException as exc:
            # A timeout is genuinely ambiguous: the change may or may not have
            # landed. Reporting failure here would be a lie, and retrying
            # could double-book. UNKNOWN is the honest answer.
            return ExecutionResult(
                outcome=ExecutionOutcome.UNKNOWN,
                message=(
                    "Google did not respond in time. MyBot cannot tell whether the change "
                    "was applied and will not retry automatically."
                ),
                error=f"timeout: {exc!s}"[:200],
            )
        except httpx.HTTPError as exc:
            return ExecutionResult(
                outcome=ExecutionOutcome.FAILED,
                message="Google Calendar could not be reached.",
                error=f"{type(exc).__name__}",
            )

        if resp.status_code in (200, 201, 204):
            body = resp.json() if resp.content and resp.status_code != 204 else {}
            return ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message="Google Calendar confirmed the change.",
                external_ref=body.get("id") or params.get("event_id"),
                data={"htmlLink": body.get("htmlLink")} if body else {},
                occurred_at=dt.datetime.now(dt.UTC),
            )
        if resp.status_code in (408, 429, 500, 502, 503, 504):
            return ExecutionResult(
                outcome=ExecutionOutcome.UNKNOWN,
                message=f"Google returned {resp.status_code}; the outcome is unclear.",
                error=f"http_{resp.status_code}",
            )
        return ExecutionResult(
            outcome=ExecutionOutcome.FAILED,
            message=f"Google rejected the change (HTTP {resp.status_code}).",
            error=f"http_{resp.status_code}",
        )


class GmailConnector(_GoogleBase, EmailConnector):
    provider = "gmail"
    is_mock = False

    def list_messages(
        self, owner_id: str, since: dt.datetime, limit: int = 100
    ) -> list[EmailMessageData]:
        token = self._token(owner_id, GMAIL_READ_SCOPES)
        query = f"after:{int(since.timestamp())}"
        try:
            with self._client(token) as client:
                listing = client.get(
                    f"{GMAIL_API}/users/me/messages",
                    params={"q": query, "maxResults": str(min(limit, 100))},
                )
                listing.raise_for_status()
                ids = [m["id"] for m in listing.json().get("messages", [])]

                messages: list[EmailMessageData] = []
                for message_id in ids:
                    detail = client.get(
                        f"{GMAIL_API}/users/me/messages/{message_id}",
                        params={"format": "metadata", "metadataHeaders": ["From", "To", "Subject", "Date"]},
                    )
                    if detail.status_code != 200:
                        continue
                    messages.append(_gmail_to_data(detail.json()))
        except httpx.HTTPError as exc:
            raise IntegrationUnavailable(f"Gmail unreachable: {type(exc).__name__}") from exc
        return messages


class GmailAdapter(_GoogleBase, IntegrationAdapter):
    provider = "gmail"
    display_name = "Gmail"
    supported_actions = frozenset({"email.draft", "email.send", "email.label"})
    is_mock = False

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        if not self.supports(ctx.action_type):
            raise ActionNotSupported(f"{self.provider} cannot execute {ctx.action_type}")
        token = self._token(ctx.owner_id, GMAIL_WRITE_SCOPES)
        try:
            with self._client(token) as client:
                if ctx.action_type == "email.label":
                    resp = client.post(
                        f"{GMAIL_API}/users/me/messages/{ctx.params['message_id']}/modify",
                        json={"addLabelIds": [ctx.params["label"]]},
                    )
                else:
                    raw = _build_raw_message(ctx.params)
                    endpoint = (
                        f"{GMAIL_API}/users/me/drafts"
                        if ctx.action_type == "email.draft"
                        else f"{GMAIL_API}/users/me/messages/send"
                    )
                    body = (
                        {"message": {"raw": raw}}
                        if ctx.action_type == "email.draft"
                        else {"raw": raw}
                    )
                    resp = client.post(endpoint, json=body)
        except httpx.TimeoutException:
            return ExecutionResult(
                outcome=ExecutionOutcome.UNKNOWN,
                message="Gmail did not respond in time; MyBot cannot confirm whether it sent.",
                error="timeout",
            )
        except httpx.HTTPError as exc:
            return ExecutionResult(
                outcome=ExecutionOutcome.FAILED,
                message="Gmail could not be reached.",
                error=type(exc).__name__,
            )

        if resp.status_code in (200, 201):
            payload = resp.json()
            return ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message="Gmail confirmed the operation.",
                external_ref=payload.get("id"),
                occurred_at=dt.datetime.now(dt.UTC),
            )
        if resp.status_code in (408, 429, 500, 502, 503, 504):
            return ExecutionResult(
                outcome=ExecutionOutcome.UNKNOWN,
                message=f"Gmail returned {resp.status_code}; the outcome is unclear.",
                error=f"http_{resp.status_code}",
            )
        return ExecutionResult(
            outcome=ExecutionOutcome.FAILED,
            message=f"Gmail rejected the request (HTTP {resp.status_code}).",
            error=f"http_{resp.status_code}",
        )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _parse_google_time(node: dict) -> dt.datetime | None:
    raw = node.get("dateTime") or node.get("date")
    if not raw:
        return None
    if len(raw) == 10:  # all-day event
        return dt.datetime.fromisoformat(raw).replace(tzinfo=dt.UTC)
    return dt.datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(dt.UTC)


def _gmail_to_data(payload: dict) -> EmailMessageData:
    headers = {h["name"].lower(): h["value"] for h in payload.get("payload", {}).get("headers", [])}
    received = dt.datetime.fromtimestamp(int(payload.get("internalDate", "0")) / 1000, dt.UTC)
    from_raw = headers.get("from", "")
    name, address = _split_address(from_raw)
    return EmailMessageData(
        external_id=payload["id"],
        thread_id=payload.get("threadId"),
        from_address=address,
        from_name=name,
        to_addresses=tuple(a.strip() for a in headers.get("to", "").split(",") if a.strip()),
        subject=headers.get("subject", ""),
        snippet=payload.get("snippet", ""),
        # Metadata-only fetch: the body is deliberately not pulled here. It is
        # requested separately, and only when something needs to analyse it.
        body="",
        received_at=received,
        labels=tuple(payload.get("labelIds", [])),
        is_read="UNREAD" not in payload.get("labelIds", []),
    )


def _split_address(raw: str) -> tuple[str | None, str]:
    raw = raw.strip()
    if "<" in raw and ">" in raw:
        name = raw.split("<", 1)[0].strip().strip('"')
        address = raw.split("<", 1)[1].split(">", 1)[0].strip()
        return (name or None), address
    return None, raw


def _build_raw_message(params: dict) -> str:
    import base64
    from email.message import EmailMessage

    message = EmailMessage()
    message["To"] = ", ".join(params.get("to", []))
    if params.get("cc"):
        message["Cc"] = ", ".join(params["cc"])
    message["Subject"] = params.get("subject", "")
    if params.get("in_reply_to"):
        message["In-Reply-To"] = params["in_reply_to"]
        message["References"] = params["in_reply_to"]
    message.set_content(params.get("body", ""))
    return base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")


__all__ = [
    "CALENDAR_READ_SCOPES",
    "CALENDAR_WRITE_SCOPES",
    "GMAIL_READ_SCOPES",
    "GMAIL_WRITE_SCOPES",
    "GmailAdapter",
    "GmailConnector",
    "GoogleCalendarAdapter",
    "GoogleCalendarConnector",
    "TokenProvider",
]
