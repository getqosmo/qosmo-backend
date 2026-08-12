"""The action registry: the deterministic contract for everything MyBot can do
to the outside world.

This module is the single source of truth for:

* which action types exist at all,
* the parameter schema each one requires,
* the *floor* risk level for each one,
* whether an action mutates something outside MyBot,
* whether an action is reversible.

Two properties matter more than anything else here:

1. **A model cannot add an entry to this registry, and cannot change one.**
   An action type that is not registered simply cannot be executed -- the
   Action Firewall rejects it before the policy engine is even consulted.

2. **Risk is a floor, never a ceiling.**  Permission rules and runtime signals
   (untrusted provenance, low confidence, lockdown) may only ever *raise* the
   requirements attached to an action.  ``PolicyEngine`` enforces this
   monotonicity, so no amount of clever prompting can talk a $10,000 transfer
   down into the LOW bucket.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel, Field, field_validator

from .enums import RiskLevel

# ---------------------------------------------------------------------------
# Parameter schemas
# ---------------------------------------------------------------------------
# Every action type binds to a Pydantic model.  The firewall validates the
# proposed parameters against it and rejects anything malformed, extra or
# missing.  "Reject anything with extra fields" is deliberate: it stops a model
# from smuggling an unexpected key past a permissive adapter.


class ActionParams(BaseModel):
    model_config = {"extra": "forbid"}


class CalendarRescheduleParams(ActionParams):
    event_id: str
    new_start: str = Field(description="ISO-8601 datetime, timezone-aware")
    new_end: str = Field(description="ISO-8601 datetime, timezone-aware")
    calendar_id: str = "primary"

    @field_validator("new_start", "new_end")
    @classmethod
    def _iso(cls, v: str) -> str:
        from datetime import datetime

        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return v


class CalendarCreateParams(ActionParams):
    title: str
    start: str
    end: str
    calendar_id: str = "primary"
    location: str | None = None
    description: str | None = None


class CalendarCancelParams(ActionParams):
    event_id: str
    calendar_id: str = "primary"
    notify_attendees: bool = False


class EmailDraftParams(ActionParams):
    to: list[str]
    subject: str
    body: str
    in_reply_to: str | None = None


class EmailSendParams(ActionParams):
    to: list[str]
    subject: str
    body: str
    cc: list[str] = Field(default_factory=list)
    in_reply_to: str | None = None


class EmailLabelParams(ActionParams):
    message_id: str
    label: str


class DocumentOrganizeParams(ActionParams):
    document_id: str
    folder: str


class TaskCreateParams(ActionParams):
    title: str
    due_date: str | None = None
    notes: str | None = None


class ObligationCreateParams(ActionParams):
    title: str
    due_date: str
    kind: str = "generic"
    notes: str | None = None


class MemoryWriteParams(ActionParams):
    kind: str
    content: str
    subject: str | None = None


class SubscriptionCancelParams(ActionParams):
    subscription_entity_id: str
    provider: str
    effective_date: str | None = None


class PaymentParams(ActionParams):
    payee: str
    amount: float = Field(gt=0)
    currency: str = "USD"
    account_ref: str = Field(description="Vault credential reference, never a raw account number")
    memo: str | None = None
    invoice_id: str | None = None


class TransferParams(ActionParams):
    destination_ref: str
    amount: float = Field(gt=0)
    currency: str = "USD"
    memo: str | None = None


class SecuritySettingParams(ActionParams):
    setting: str
    value: str


class DeviceTrustParams(ActionParams):
    device_id: str
    device_name: str


class VaultExportParams(ActionParams):
    scope: str = "all"


class GovernmentSubmitParams(ActionParams):
    agency: str
    form_id: str
    payload_ref: str


class DataDeleteParams(ActionParams):
    resource_type: str
    resource_id: str


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionSpec:
    """Immutable description of one action type."""

    action_type: str
    #: Floor risk. Runtime signals may raise it; nothing may lower it.
    risk: RiskLevel
    params_model: type[ActionParams]
    #: Human sentence used in approval UI. Kept here so the copy shown to the
    #: user is never model-generated.
    display: str
    #: True when executing this touches a system outside MyBot.  Lockdown
    #: blocks exactly this set.
    external_mutation: bool
    #: Can this be undone by MyBot itself, without a human calling someone?
    reversible: bool
    #: Integration this routes to. ``None`` means internal-only.
    integration: str | None = None
    #: Auth level required *at minimum* on top of whatever risk implies.
    min_auth: str | None = None
    #: Free-form tags used by permission rules for coarse matching.
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def money(self) -> bool:
        return "money" in self.tags


def _spec(*args, **kwargs) -> ActionSpec:
    return ActionSpec(*args, **kwargs)


#: The registry.  Adding to this is a code change, reviewed like any other.
ACTION_REGISTRY: dict[str, ActionSpec] = {
    # -- LOW ---------------------------------------------------------------
    # Internal, reversible, no external side effect.  These may run without a
    # human in the loop when a permission rule allows it.
    s.action_type: s
    for s in [
        _spec(
            "document.organize",
            RiskLevel.LOW,
            DocumentOrganizeParams,
            "File a document",
            external_mutation=False,
            reversible=True,
            tags=("documents",),
        ),
        _spec(
            "task.create",
            RiskLevel.LOW,
            TaskCreateParams,
            "Create an internal task",
            external_mutation=False,
            reversible=True,
            tags=("tasks",),
        ),
        _spec(
            "obligation.create",
            RiskLevel.LOW,
            ObligationCreateParams,
            "Track a new obligation",
            external_mutation=False,
            reversible=True,
            tags=("obligations",),
        ),
        _spec(
            "memory.write",
            RiskLevel.LOW,
            MemoryWriteParams,
            "Remember something",
            external_mutation=False,
            reversible=True,
            tags=("memory",),
        ),
        _spec(
            "email.label",
            RiskLevel.LOW,
            EmailLabelParams,
            "Label an email",
            external_mutation=True,
            reversible=True,
            integration="gmail",
            tags=("email",),
        ),
        _spec(
            "email.draft",
            RiskLevel.LOW,
            EmailDraftParams,
            "Prepare a draft reply",
            external_mutation=False,
            reversible=True,
            integration="gmail",
            tags=("email",),
        ),
        # -- MEDIUM --------------------------------------------------------
        # Leaves the house.  Visible to other people.  Approval required in
        # V0.1 regardless of what any rule says.
        _spec(
            "calendar.reschedule",
            RiskLevel.MEDIUM,
            CalendarRescheduleParams,
            "Move an appointment",
            external_mutation=True,
            reversible=True,
            integration="google_calendar",
            tags=("calendar",),
        ),
        _spec(
            "calendar.create",
            RiskLevel.MEDIUM,
            CalendarCreateParams,
            "Add a calendar event",
            external_mutation=True,
            reversible=True,
            integration="google_calendar",
            tags=("calendar",),
        ),
        _spec(
            "calendar.cancel",
            RiskLevel.MEDIUM,
            CalendarCancelParams,
            "Cancel an appointment",
            external_mutation=True,
            reversible=False,
            integration="google_calendar",
            tags=("calendar",),
        ),
        _spec(
            "email.send",
            RiskLevel.MEDIUM,
            EmailSendParams,
            "Send an email",
            external_mutation=True,
            reversible=False,
            integration="gmail",
            tags=("email", "communication"),
        ),
        # -- HIGH ----------------------------------------------------------
        _spec(
            "subscription.cancel",
            RiskLevel.HIGH,
            SubscriptionCancelParams,
            "Cancel a subscription",
            external_mutation=True,
            reversible=False,
            integration="service_provider",
            tags=("money", "subscriptions"),
        ),
        _spec(
            "payment.pay_bill",
            RiskLevel.HIGH,
            PaymentParams,
            "Pay a bill",
            external_mutation=True,
            reversible=False,
            integration="payments",
            min_auth="STRONG",
            tags=("money", "payments"),
        ),
        _spec(
            "utilities.pay",
            RiskLevel.HIGH,
            PaymentParams,
            "Pay a utility bill",
            external_mutation=True,
            reversible=False,
            integration="payments",
            min_auth="STRONG",
            tags=("money", "payments", "utilities"),
        ),
        _spec(
            "government.submit",
            RiskLevel.HIGH,
            GovernmentSubmitParams,
            "Submit a government form",
            external_mutation=True,
            reversible=False,
            integration="government",
            min_auth="STRONG",
            tags=("government", "identity"),
        ),
        _spec(
            "data.delete",
            RiskLevel.HIGH,
            DataDeleteParams,
            "Delete stored information",
            external_mutation=False,
            reversible=False,
            tags=("data",),
        ),
        # -- CRITICAL ------------------------------------------------------
        # Compromise here is unrecoverable.  Physical presence or strong auth,
        # never automatic, never derived from untrusted content.
        _spec(
            "payment.transfer",
            RiskLevel.CRITICAL,
            TransferParams,
            "Transfer money",
            external_mutation=True,
            reversible=False,
            integration="payments",
            min_auth="PHYSICAL",
            tags=("money", "payments", "transfer"),
        ),
        _spec(
            "security.change_setting",
            RiskLevel.CRITICAL,
            SecuritySettingParams,
            "Change a security setting",
            external_mutation=False,
            reversible=False,
            min_auth="STRONG",
            tags=("security",),
        ),
        _spec(
            "security.trust_device",
            RiskLevel.CRITICAL,
            DeviceTrustParams,
            "Trust a new device",
            external_mutation=False,
            reversible=True,
            min_auth="PHYSICAL",
            tags=("security", "devices"),
        ),
        _spec(
            "vault.export",
            RiskLevel.CRITICAL,
            VaultExportParams,
            "Export the Vault",
            external_mutation=False,
            reversible=False,
            min_auth="PHYSICAL",
            tags=("security", "vault"),
        ),
    ]
}


#: Action types that an agent (LLM) is permitted to *propose* at all.
#: Everything else must originate from a human interaction in the UI.  This is
#: an architectural barrier, not a prompt instruction: the firewall checks the
#: actor type against this set.
AGENT_PROPOSABLE: frozenset[str] = frozenset(
    {
        "document.organize",
        "task.create",
        "obligation.create",
        "memory.write",
        "email.label",
        "email.draft",
        "calendar.reschedule",
        "calendar.create",
        "calendar.cancel",
        "email.send",
    }
)

#: Nothing derived from untrusted external content may propose these, at any
#: confidence, ever.  A malicious email cannot reach money.
UNTRUSTED_FORBIDDEN: frozenset[str] = frozenset(
    a for a, s in ACTION_REGISTRY.items() if s.risk.at_least(RiskLevel.HIGH)
)


class UnknownActionType(ValueError):
    """Raised when an action type is not in the registry.

    Deliberately fatal: an unregistered action has no risk class, so there is
    no safe default other than refusal.
    """


def get_spec(action_type: str) -> ActionSpec:
    try:
        return ACTION_REGISTRY[action_type]
    except KeyError as exc:  # pragma: no cover - trivial
        raise UnknownActionType(f"unregistered action type: {action_type!r}") from exc


def validate_params(action_type: str, params: dict) -> ActionParams:
    """Validate raw parameters against the registered schema.

    Raises ``pydantic.ValidationError`` on anything malformed.  Callers must
    not catch-and-continue: a proposal that fails validation is rejected.
    """
    spec = get_spec(action_type)
    return spec.params_model.model_validate(params)


def external_mutation_types() -> frozenset[str]:
    return frozenset(a for a, s in ACTION_REGISTRY.items() if s.external_mutation)


__all__ = [
    "ACTION_REGISTRY",
    "AGENT_PROPOSABLE",
    "ActionParams",
    "ActionSpec",
    "UNTRUSTED_FORBIDDEN",
    "UnknownActionType",
    "external_mutation_types",
    "get_spec",
    "validate_params",
]
