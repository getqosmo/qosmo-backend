"""Mock connectors.

MyBot must be fully usable with no Google credentials, no API keys and no
network. That is not only a developer convenience -- it is how the security
properties get exercised end to end in tests and in `mybot demo` without
anyone's real mailbox being involved.

Mocks here are honest:

* Every adapter reports ``is_mock = True``, and that flag reaches the Security
  Center and the UI. A simulated confirmation is labelled as simulated.
* They simulate the *awkward* cases too -- an ambiguous response that must
  become ``UNKNOWN``, a provider that rejects a duplicate -- because those are
  the paths where real money gets moved twice.
* Idempotency is enforced, so the firewall's replay protection is genuinely
  tested rather than assumed.
"""

from __future__ import annotations

import datetime as dt

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
)


class _IdempotentAdapter(IntegrationAdapter):
    """Shared replay protection.

    Keyed on the idempotency key, so a second execution of the same proposal
    returns the first result rather than repeating the effect.
    """

    def __init__(self):
        self._seen: dict[str, ExecutionResult] = {}

    def _replay(self, ctx: ExecutionContext) -> ExecutionResult | None:
        return self._seen.get(f"{ctx.owner_id}:{ctx.idempotency_key}")

    def _remember(self, ctx: ExecutionContext, result: ExecutionResult) -> ExecutionResult:
        self._seen[f"{ctx.owner_id}:{ctx.idempotency_key}"] = result
        return result


class MockCalendarAdapter(_IdempotentAdapter):
    provider = "mock_calendar"
    display_name = "Calendar (simulated)"
    supported_actions = frozenset({"calendar.reschedule", "calendar.create", "calendar.cancel"})
    is_mock = True

    def __init__(self, store: MockCalendarConnector | None = None):
        super().__init__()
        self.store = store

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        if not self.supports(ctx.action_type):
            raise ActionNotSupported(f"{self.provider} cannot execute {ctx.action_type}")
        replayed = self._replay(ctx)
        if replayed is not None:
            return replayed
        if ctx.dry_run:
            return ExecutionResult(
                outcome=ExecutionOutcome.ACCEPTED,
                message="Dry run: no change was made.",
            )

        now = dt.datetime.now(dt.UTC)
        params = ctx.params
        if ctx.action_type == "calendar.reschedule":
            result = ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message=(
                    f"Simulated: event {params['event_id']} moved to "
                    f"{params['new_start']}."
                ),
                external_ref=params["event_id"],
                data={"new_start": params["new_start"], "new_end": params["new_end"]},
                occurred_at=now,
            )
            if self.store is not None:
                self.store.apply_reschedule(
                    ctx.owner_id, params["event_id"], params["new_start"], params["new_end"]
                )
        elif ctx.action_type == "calendar.create":
            new_id = f"mockevt-{ctx.idempotency_key[:12]}"
            result = ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message=f"Simulated: created “{params['title']}”.",
                external_ref=new_id,
                data={"event_id": new_id},
                occurred_at=now,
            )
        else:  # calendar.cancel
            result = ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message=f"Simulated: cancelled event {params['event_id']}.",
                external_ref=params["event_id"],
                occurred_at=now,
            )
        return self._remember(ctx, result)


class MockEmailAdapter(_IdempotentAdapter):
    provider = "mock_email"
    display_name = "Email (simulated)"
    supported_actions = frozenset({"email.send", "email.draft", "email.label"})
    is_mock = True

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        if not self.supports(ctx.action_type):
            raise ActionNotSupported(f"{self.provider} cannot execute {ctx.action_type}")
        replayed = self._replay(ctx)
        if replayed is not None:
            return replayed

        now = dt.datetime.now(dt.UTC)
        if ctx.action_type == "email.draft":
            ref = f"mockdraft-{ctx.idempotency_key[:12]}"
            result = ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message="Simulated: draft saved. Nothing was sent.",
                external_ref=ref,
                data={"draft_id": ref},
                occurred_at=now,
            )
        elif ctx.action_type == "email.label":
            result = ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message=f"Simulated: labelled as {ctx.params['label']}.",
                external_ref=ctx.params["message_id"],
                occurred_at=now,
            )
        else:  # email.send
            ref = f"mockmsg-{ctx.idempotency_key[:12]}"
            result = ExecutionResult(
                outcome=ExecutionOutcome.CONFIRMED,
                message=f"Simulated: sent to {', '.join(ctx.params['to'])}.",
                external_ref=ref,
                data={"message_id": ref},
                occurred_at=now,
            )
        return self._remember(ctx, result)


class UnavailablePaymentsAdapter(IntegrationAdapter):
    """Payments are deliberately not implemented.

    The action types exist in the registry, the policy engine enforces real
    limits on them, and the approval UI renders them properly -- but nothing
    can actually move money in V0.1. This adapter makes that explicit rather
    than leaving a plausible-looking stub that might one day be wired up by
    accident.

    It returns FAILED, never CONFIRMED, so no code path can report success for
    a payment that did not happen.
    """

    provider = "payments"
    display_name = "Payments (not implemented)"
    supported_actions = frozenset(
        {"payment.pay_bill", "utilities.pay", "payment.transfer", "subscription.cancel"}
    )
    is_mock = True

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        return ExecutionResult(
            outcome=ExecutionOutcome.FAILED,
            message=(
                "MyBot cannot move money in this release. The request was recorded "
                "and authorized, but no payment provider is connected."
            ),
            error="payments_not_implemented",
            occurred_at=dt.datetime.now(dt.UTC),
        )


class FlakyAdapter(IntegrationAdapter):
    """Test fixture that returns an ambiguous result.

    Exists so the "never claim success you did not observe" behaviour has a
    real code path exercising it: the firewall must land on ``UNKNOWN`` and
    surface it for investigation rather than retrying.
    """

    provider = "flaky_test"
    display_name = "Unreliable service (test fixture)"
    supported_actions = frozenset({"calendar.create"})
    is_mock = True

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        return ExecutionResult(
            outcome=ExecutionOutcome.UNKNOWN,
            message=(
                "The service accepted the request but did not confirm it. "
                "MyBot will not retry automatically."
            ),
            error="ambiguous_response",
            occurred_at=dt.datetime.now(dt.UTC),
        )


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


class MockCalendarConnector(CalendarConnector):
    """In-memory calendar seeded by the demo fixture."""

    provider = "mock_calendar"
    is_mock = True

    def __init__(self):
        self._events: dict[str, list[CalendarEventData]] = {}

    def seed(self, owner_id: str, events: list[CalendarEventData]) -> None:
        self._events[owner_id] = list(events)

    def list_events(
        self, owner_id: str, since: dt.datetime, until: dt.datetime
    ) -> list[CalendarEventData]:
        return [
            e for e in self._events.get(owner_id, []) if e.start_at < until and e.end_at > since
        ]

    def apply_reschedule(self, owner_id: str, event_id: str, new_start: str, new_end: str) -> None:
        events = self._events.get(owner_id, [])
        for index, event in enumerate(events):
            if event.external_id == event_id:
                events[index] = CalendarEventData(
                    external_id=event.external_id,
                    title=event.title,
                    start_at=dt.datetime.fromisoformat(new_start),
                    end_at=dt.datetime.fromisoformat(new_end),
                    calendar_id=event.calendar_id,
                    description=event.description,
                    location=event.location,
                    attendees=event.attendees,
                    organizer=event.organizer,
                    all_day=event.all_day,
                    status=event.status,
                    importance=event.importance,
                )
                return


class MockEmailConnector(EmailConnector):
    """In-memory mailbox seeded by the demo fixture."""

    provider = "mock_email"
    is_mock = True

    def __init__(self):
        self._messages: dict[str, list[EmailMessageData]] = {}

    def seed(self, owner_id: str, messages: list[EmailMessageData]) -> None:
        self._messages[owner_id] = list(messages)

    def list_messages(
        self, owner_id: str, since: dt.datetime, limit: int = 100
    ) -> list[EmailMessageData]:
        msgs = [m for m in self._messages.get(owner_id, []) if m.received_at >= since]
        return sorted(msgs, key=lambda m: m.received_at, reverse=True)[:limit]


__all__ = [
    "FlakyAdapter",
    "MockCalendarAdapter",
    "MockCalendarConnector",
    "MockEmailAdapter",
    "MockEmailConnector",
    "UnavailablePaymentsAdapter",
]
