"""Adapter registry.

The Action Firewall asks this registry for the adapter that can execute a
given action type. There is intentionally no fallback: if nothing is
registered, the action fails with a clear reason rather than silently doing
nothing and reporting success.

Mock and live adapters are never mixed for the same provider. The mode is set
once from configuration, so a half-connected account cannot end up executing
calendar writes against the real calendar while reading from a fixture.
"""

from __future__ import annotations

from .adapters.mock import (
    MockCalendarAdapter,
    MockCalendarConnector,
    MockEmailAdapter,
    MockEmailConnector,
    UnavailablePaymentsAdapter,
)
from .base import CalendarConnector, EmailConnector, IntegrationAdapter


class IntegrationRegistry:
    def __init__(self, *, mode: str = "mock"):
        self.mode = mode
        self._adapters: list[IntegrationAdapter] = []
        self._calendar: CalendarConnector | None = None
        self._email: EmailConnector | None = None

    # -- registration ----------------------------------------------------

    def register_adapter(self, adapter: IntegrationAdapter) -> None:
        self._adapters.append(adapter)

    def set_calendar_connector(self, connector: CalendarConnector) -> None:
        self._calendar = connector

    def set_email_connector(self, connector: EmailConnector) -> None:
        self._email = connector

    # -- lookup ----------------------------------------------------------

    def adapter_for(self, action_type: str) -> IntegrationAdapter | None:
        for adapter in self._adapters:
            if adapter.supports(action_type):
                return adapter
        return None

    def calendar(self) -> CalendarConnector | None:
        return self._calendar

    def email(self) -> EmailConnector | None:
        return self._email

    def adapters(self) -> list[IntegrationAdapter]:
        return list(self._adapters)

    def describe(self) -> list[dict]:
        return [
            {
                "provider": a.provider,
                "display_name": a.display_name,
                "mock": a.is_mock,
                "actions": sorted(a.supported_actions),
            }
            for a in self._adapters
        ]


def build_default_registry(mode: str = "mock") -> IntegrationRegistry:
    """Assemble the registry for the configured mode.

    ``live`` requires credentials and a token provider, which the API layer
    supplies during integration connect. Until then the registry stays in mock
    mode -- the product works, and nothing pretends to be connected.
    """
    registry = IntegrationRegistry(mode=mode)

    calendar_store = MockCalendarConnector()
    email_store = MockEmailConnector()
    registry.set_calendar_connector(calendar_store)
    registry.set_email_connector(email_store)
    registry.register_adapter(MockCalendarAdapter(store=calendar_store))
    registry.register_adapter(MockEmailAdapter())
    # Registered so the failure is explicit and audited rather than a missing
    # adapter that looks like a configuration mistake.
    registry.register_adapter(UnavailablePaymentsAdapter())
    return registry


__all__ = ["IntegrationRegistry", "build_default_registry"]
