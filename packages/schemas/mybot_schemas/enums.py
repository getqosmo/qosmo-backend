"""Canonical vocabulary for MyBot.

Everything downstream -- the policy engine, the action firewall, the audit log,
the UI -- agrees on the values in this module.  These are deliberately plain
string enums so they survive JSON round-trips, database storage and export
without a translation layer.

Nothing in this module may be modified at runtime by a model.  Risk levels in
particular are *data*, not something an LLM negotiates over; see
``mybot_schemas.actions`` for the registry that binds action types to risk.
"""

from __future__ import annotations

from enum import StrEnum


class Classification(StrEnum):
    """Sensitivity of a piece of data.

    Drives redaction in logs, what may be sent to an external model, and which
    auth level is needed to read a field back out.
    """

    PUBLIC = "PUBLIC"
    NORMAL = "NORMAL"
    PERSONAL = "PERSONAL"
    SENSITIVE = "SENSITIVE"
    HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"
    SECRET = "SECRET"

    @property
    def rank(self) -> int:
        return _CLASSIFICATION_ORDER.index(self)

    def at_least(self, other: Classification) -> bool:
        return self.rank >= other.rank

    @classmethod
    def max_of(cls, values) -> Classification:
        best = cls.PUBLIC
        for v in values:
            v = cls(v)
            if v.rank > best.rank:
                best = v
        return best


_CLASSIFICATION_ORDER = [
    Classification.PUBLIC,
    Classification.NORMAL,
    Classification.PERSONAL,
    Classification.SENSITIVE,
    Classification.HIGHLY_SENSITIVE,
    Classification.SECRET,
]


class RiskLevel(StrEnum):
    """How much damage an action can do if it is wrong or malicious."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RISK_ORDER.index(self)

    def at_least(self, other: RiskLevel) -> bool:
        return self.rank >= other.rank

    @classmethod
    def max_of(cls, values) -> RiskLevel:
        best = cls.LOW
        for v in values:
            v = cls(v)
            if v.rank > best.rank:
                best = v
        return best


_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


class AuthLevel(StrEnum):
    """Strength of the proof we have that the human is present and consenting.

    ``BASIC``    - a valid session (password / passkey at login time).
    ``STRONG``   - a fresh second factor within the elevation window.
    ``PHYSICAL`` - proof of physical presence at the MyBot Core (button press,
                   attested device).  Simulated in development.
    """

    NONE = "NONE"
    BASIC = "BASIC"
    STRONG = "STRONG"
    PHYSICAL = "PHYSICAL"

    @property
    def rank(self) -> int:
        return _AUTH_ORDER.index(self)

    def satisfies(self, required: AuthLevel) -> bool:
        return self.rank >= required.rank


_AUTH_ORDER = [AuthLevel.NONE, AuthLevel.BASIC, AuthLevel.STRONG, AuthLevel.PHYSICAL]


class ActorType(StrEnum):
    """Who or what originated a request.

    The distinction matters: an ``AGENT`` actor may *propose* but never
    *authorize*.  This is Rule 1 and Rule 3 expressed in the type system.
    """

    USER = "USER"
    AGENT = "AGENT"
    SYSTEM = "SYSTEM"
    INTEGRATION = "INTEGRATION"
    AUTOMATION = "AUTOMATION"


class ActionStatus(StrEnum):
    """Lifecycle of an action proposal.

    There is no ``done``.  ``CONFIRMED`` may only be set when an integration
    adapter returned an affirmative result; anything ambiguous lands in
    ``UNKNOWN`` and is surfaced for investigation rather than retried.
    """

    DRAFT = "draft"
    PREPARED = "prepared"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    BLOCKED = "blocked"
    SUBMITTED = "submitted"
    PROCESSING = "processing"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


TERMINAL_ACTION_STATUSES = frozenset(
    {
        ActionStatus.REJECTED,
        ActionStatus.EXPIRED,
        ActionStatus.CONFIRMED,
        ActionStatus.FAILED,
        ActionStatus.CANCELLED,
    }
)

#: Statuses from which an approval may still be granted.
APPROVABLE_ACTION_STATUSES = frozenset({ActionStatus.PENDING_APPROVAL, ActionStatus.PREPARED})


class PolicyOutcome(StrEnum):
    """Result of a deterministic policy evaluation."""

    ALLOW = "allow"
    ALLOW_WITH_APPROVAL = "allow_with_approval"
    DENY = "deny"


class EntityType(StrEnum):
    """Life Graph node types.

    New types are added here; no schema migration is needed because entity
    payloads live in structured JSON attributes validated per type.
    """

    PERSON = "Person"
    ORGANIZATION = "Organization"
    PROJECT = "Project"
    ACCOUNT = "Account"
    VEHICLE = "Vehicle"
    PROPERTY = "Property"
    DOCUMENT = "Document"
    SUBSCRIPTION = "Subscription"
    BILL = "Bill"
    APPOINTMENT = "Appointment"
    TASK = "Task"
    DEADLINE = "Deadline"
    SERVICE_PROVIDER = "ServiceProvider"
    PURCHASE = "Purchase"
    TRIP = "Trip"
    PREFERENCE = "Preference"
    RULE = "Rule"
    CREDENTIAL_REFERENCE = "CredentialReference"
    EXTERNAL_ACCOUNT = "ExternalAccount"
    PLACE = "Place"
    EVENT = "Event"
    MESSAGE = "Message"


class RelationType(StrEnum):
    """Life Graph edge types."""

    OWNS = "OWNS"
    WORKS_WITH = "WORKS_WITH"
    PAYS = "PAYS"
    MANAGES = "MANAGES"
    RELATED_TO = "RELATED_TO"
    DEPENDS_ON = "DEPENDS_ON"
    RENEWS_ON = "RENEWS_ON"
    EXPIRES_ON = "EXPIRES_ON"
    BELONGS_TO = "BELONGS_TO"
    SCHEDULED_FOR = "SCHEDULED_FOR"
    AUTHORIZED_FOR = "AUTHORIZED_FOR"
    ISSUED_BY = "ISSUED_BY"
    MEMBER_OF = "MEMBER_OF"
    LOCATED_AT = "LOCATED_AT"
    DOCUMENTS = "DOCUMENTS"


class SourceKind(StrEnum):
    """Where a fact came from.  Provenance is a first-class field, not a note.

    ``trust`` below is what separates a user's own statement from the body of an
    email a stranger sent them.
    """

    USER_STATEMENT = "user_statement"
    USER_CORRECTION = "user_correction"
    DOCUMENT = "document"
    EMAIL = "email"
    CALENDAR = "calendar"
    EXTERNAL_API = "external_api"
    INFERENCE = "inference"
    SEED = "seed"
    SYSTEM = "system"

    @property
    def is_trusted(self) -> bool:
        """True when content from this source may be treated as instructions.

        Anything reachable by a third party is untrusted, forever.
        """
        return self in _TRUSTED_SOURCES


_TRUSTED_SOURCES = frozenset(
    {
        SourceKind.USER_STATEMENT,
        SourceKind.USER_CORRECTION,
        SourceKind.SYSTEM,
        SourceKind.SEED,
    }
)


class InboxCategory(StrEnum):
    URGENT = "urgent"
    DECISION = "decision"
    APPROVAL = "approval"
    MONEY = "money"
    WORK = "work"
    HOME = "home"
    FAMILY = "family"
    TRAVEL = "travel"
    FYI = "fyi"
    HANDLED = "handled"


class Urgency(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class InboxItemState(StrEnum):
    OPEN = "open"
    SNOOZED = "snoozed"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class ObligationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    CANCELLED = "cancelled"
    OVERDUE = "overdue"


class Recurrence(StrEnum):
    NONE = "none"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


class MemoryKind(StrEnum):
    """Not every sentence deserves to be remembered forever.

    ``WORKING`` is scratch context for one exchange.  ``CONVERSATION`` is chat
    history subject to retention limits.  Only ``FACT``/``PREFERENCE``/``RULE``
    are durable memory the user can inspect, edit and delete.
    """

    WORKING = "working"
    CONVERSATION = "conversation"
    FACT = "fact"
    PREFERENCE = "preference"
    RULE = "rule"
    INSTRUCTION = "instruction"


class IntegrationStatus(StrEnum):
    NOT_CONNECTED = "not_connected"
    MOCK = "mock"
    CONNECTED = "connected"
    ERROR = "error"
    REVOKED = "revoked"


class LLMPurpose(StrEnum):
    """Model routing dimension.  Different jobs, different models, different
    amounts of context allowed to leave the machine."""

    CLASSIFICATION = "classification"
    EXTRACTION = "extraction"
    REASONING = "reasoning"
    PLANNING = "planning"
    SUMMARIZATION = "summarization"
    CHAT = "chat"


class SecurityEventType(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    STRONG_AUTH_SUCCESS = "strong_auth_success"
    STRONG_AUTH_FAILURE = "strong_auth_failure"
    LOCKDOWN_ENGAGED = "lockdown_engaged"
    LOCKDOWN_RELEASED = "lockdown_released"
    POLICY_DENIED = "policy_denied"
    PERMISSION_CREATED = "permission_created"
    PERMISSION_REVOKED = "permission_revoked"
    PROMPT_INJECTION_SUSPECTED = "prompt_injection_suspected"
    CROSS_OWNER_ACCESS_ATTEMPT = "cross_owner_access_attempt"
    APPROVAL_REPLAY_ATTEMPT = "approval_replay_attempt"
    UNSAFE_MODEL_OUTPUT = "unsafe_model_output"
    DEVICE_REGISTERED = "device_registered"
    INTEGRATION_CONNECTED = "integration_connected"
    INTEGRATION_REVOKED = "integration_revoked"
    VAULT_ACCESS_DENIED = "vault_access_denied"
    DATA_EXPORTED = "data_exported"
    DATA_DELETED = "data_deleted"


class AuditEventType(StrEnum):
    ACTION_PROPOSED = "action.proposed"
    ACTION_POLICY_EVALUATED = "action.policy_evaluated"
    ACTION_APPROVED = "action.approved"
    ACTION_REJECTED = "action.rejected"
    ACTION_EXECUTED = "action.executed"
    ACTION_RESULT = "action.result"
    ACTION_BLOCKED = "action.blocked"
    ACTION_EXPIRED = "action.expired"
    ENTITY_CREATED = "entity.created"
    ENTITY_UPDATED = "entity.updated"
    ENTITY_ARCHIVED = "entity.archived"
    ENTITY_DELETED = "entity.deleted"
    MEMORY_WRITTEN = "memory.written"
    MEMORY_SUPERSEDED = "memory.superseded"
    MEMORY_DELETED = "memory.deleted"
    OBLIGATION_CREATED = "obligation.created"
    OBLIGATION_UPDATED = "obligation.updated"
    INBOX_ITEM_CREATED = "inbox.item_created"
    INBOX_ITEM_RESOLVED = "inbox.item_resolved"
    DOCUMENT_INGESTED = "document.ingested"
    BRIEF_GENERATED = "brief.generated"
    LLM_CALLED = "llm.called"
    SECURITY = "security"
    INTEGRATION_SYNCED = "integration.synced"
    #: Connecting an account is the moment an owner hands MyBot reach into
    #: something outside the machine, so it is audited as its own event rather
    #: than folded into a generic settings change.
    INTEGRATION_CONNECTED = "integration.connected"
    INTEGRATION_DISCONNECTED = "integration.disconnected"
    USER_LOGIN = "user.login"
    DATA_EXPORTED = "data.exported"
    DATA_DELETED = "data.deleted"


class ApprovalMethod(StrEnum):
    NOT_REQUIRED = "not_required"
    IN_APP = "in_app"
    STRONG_AUTH = "strong_auth"
    PHYSICAL_PRESENCE = "physical_presence"


class ExecutionOutcome(StrEnum):
    """What an integration adapter actually reported back.

    ``UNKNOWN`` is a real, first-class outcome.  Never collapse it into success
    or failure and never retry it automatically -- that is how money moves
    twice.
    """

    CONFIRMED = "confirmed"
    ACCEPTED = "accepted"
    FAILED = "failed"
    UNKNOWN = "unknown"


class TrustLevel(StrEnum):
    """Trust attached to content flowing through the reasoning layer."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


__all__ = [
    "ActionStatus",
    "ActorType",
    "ApprovalMethod",
    "AuditEventType",
    "AuthLevel",
    "Classification",
    "EntityType",
    "ExecutionOutcome",
    "InboxCategory",
    "InboxItemState",
    "IntegrationStatus",
    "LLMPurpose",
    "MemoryKind",
    "ObligationStatus",
    "PolicyOutcome",
    "Recurrence",
    "RelationType",
    "RiskLevel",
    "SecurityEventType",
    "SourceKind",
    "TrustLevel",
    "Urgency",
    "APPROVABLE_ACTION_STATUSES",
    "TERMINAL_ACTION_STATUSES",
]
