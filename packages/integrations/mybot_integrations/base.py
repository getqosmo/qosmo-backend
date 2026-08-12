"""Connector contracts.

Two separate concerns, deliberately not merged:

* **Readers** (:class:`CalendarConnector`, :class:`EmailConnector`) pull data
  in. Everything they return is untrusted by construction.
* **Executors** (:class:`IntegrationAdapter`) push changes out. They are only
  ever invoked by the Action Firewall, never directly by the orchestrator and
  never by a tool the model can call.

An adapter that is asked to execute an action it does not support raises
rather than guessing, and any ambiguous response becomes
``ExecutionOutcome.UNKNOWN`` rather than being optimistically read as success.
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from mybot_schemas.enums import ExecutionOutcome


class IntegrationError(RuntimeError):
    pass


class IntegrationUnavailable(IntegrationError):
    """The service could not be reached, or credentials are missing.

    Distinct from a failure: the caller must report "I could not check" rather
    than "there is nothing there".
    """


class ActionNotSupported(IntegrationError):
    pass


@dataclass(frozen=True)
class ExecutionContext:
    """Everything an adapter is given.

    Note what is absent: no session, no vault, no owner credentials in the
    clear. An adapter that needs a credential receives an
    ``AuthorizedRequest`` grant, which it exchanges at the Vault boundary.
    """

    owner_id: str
    action_type: str
    params: dict
    idempotency_key: str
    proposal_id: str
    request_id: str | None = None
    #: Opaque capability from the Vault; never key material.
    grant: object | None = None
    dry_run: bool = False


@dataclass(frozen=True)
class ExecutionResult:
    outcome: ExecutionOutcome
    #: Human-readable, shown to the user. Never a raw provider error blob.
    message: str = ""
    #: Provider-side identifier, so the effect can be found again.
    external_ref: str | None = None
    data: dict = field(default_factory=dict)
    error: str | None = None
    occurred_at: dt.datetime | None = None


@dataclass(frozen=True)
class CalendarEventData:
    external_id: str
    title: str
    start_at: dt.datetime
    end_at: dt.datetime
    calendar_id: str = "primary"
    description: str | None = None
    location: str | None = None
    attendees: tuple[str, ...] = ()
    organizer: str | None = None
    all_day: bool = False
    status: str = "confirmed"
    importance: str = "normal"


@dataclass(frozen=True)
class EmailMessageData:
    external_id: str
    from_address: str
    subject: str
    received_at: dt.datetime
    body: str = ""
    snippet: str = ""
    from_name: str | None = None
    to_addresses: tuple[str, ...] = ()
    thread_id: str | None = None
    labels: tuple[str, ...] = ()
    is_read: bool = False


class IntegrationAdapter(ABC):
    """Executes approved actions against one external service."""

    #: Stable provider key, matching ``Integration.provider``.
    provider: str = "unset"
    #: Human label for the Security Center.
    display_name: str = "Unset"
    #: Action types this adapter can execute.
    supported_actions: frozenset[str] = frozenset()
    #: Whether this is a simulation. Surfaced in the UI so a demo is never
    #: mistaken for the real thing.
    is_mock: bool = True

    def supports(self, action_type: str) -> bool:
        return action_type in self.supported_actions

    @abstractmethod
    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        """Perform the action. Must be idempotent on ``ctx.idempotency_key``."""

    def health(self) -> dict:
        return {"provider": self.provider, "mock": self.is_mock, "ok": True}


class CalendarConnector(ABC):
    provider: str = "unset"
    is_mock: bool = True

    @abstractmethod
    def list_events(
        self, owner_id: str, since: dt.datetime, until: dt.datetime
    ) -> list[CalendarEventData]:
        ...


class EmailConnector(ABC):
    provider: str = "unset"
    is_mock: bool = True

    @abstractmethod
    def list_messages(self, owner_id: str, since: dt.datetime, limit: int = 100) -> list[EmailMessageData]:
        ...


__all__ = [
    "ActionNotSupported",
    "CalendarConnector",
    "CalendarEventData",
    "EmailConnector",
    "EmailMessageData",
    "ExecutionContext",
    "ExecutionResult",
    "IntegrationAdapter",
    "IntegrationError",
    "IntegrationUnavailable",
]
