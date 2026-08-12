"""The MyBot data model.

Layout follows the trust boundaries rather than the feature list:

* **Identity & devices** -- who is asking, and from what.
* **Life Graph** -- entities, relationships, facts. The structured truth.
* **Memory** -- durable, editable, attributable recollection.
* **Obligations & Inbox** -- what needs attention and why.
* **Actions** -- proposals, approvals, executions. Never merged into one row;
  the proposal is what a model produced, the approval is what a human did, and
  keeping them separate is what makes Rule 3 checkable.
* **Security** -- permissions, audit chain, security events, lockdown state.
* **Connectors** -- synced external data, always carrying a trust flag.
* **Model calls** -- metadata only. Prompts containing personal data are not
  persisted.

Every personal table inherits :class:`OwnedMixin`; that is what binds it to the
ORM-level owner filter.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db.base import (
    Base,
    Classified,
    OwnedMixin,
    Provenanced,
    SoftDeletable,
    Timestamped,
    UUIDPk,
)
from .db.types import JSONDict, UTCDateTime, UUIDStr, new_uuid, utcnow
from .enums import (
    ActionStatus,
    ActorType,
    ApprovalMethod,
    AuthLevel,
    Classification,
    InboxCategory,
    InboxItemState,
    IntegrationStatus,
    MemoryKind,
    ObligationStatus,
    Recurrence,
    RiskLevel,
    TrustLevel,
    Urgency,
)

# ===========================================================================
# Identity
# ===========================================================================


class User(Base, UUIDPk, Timestamped):
    """The owner.  One human, one MyBot.

    Not ``OwnedMixin`` -- this *is* the owner record.  Everything else points
    here, and ``ON DELETE CASCADE`` on those foreign keys is what makes the
    "delete my data" promise mechanically true for personal content.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(sa.String(320), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    #: Argon2id hash. Never a plaintext or reversibly-encrypted password.
    password_hash: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    #: Shared secret for the simulated second factor, stored via the Vault as a
    #: reference rather than inline.
    strong_auth_ref: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    timezone: Mapped[str] = mapped_column(sa.String(64), default="America/New_York", nullable=False)
    locale: Mapped[str] = mapped_column(sa.String(16), default="en-US", nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    is_demo: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    settings: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)


class Device(Base, UUIDPk, OwnedMixin, Timestamped):
    """A phone, laptop or Core the owner has approved.

    Trust is per-device so a stolen laptop can be revoked without touching the
    account, and so ``PHYSICAL`` auth can be tied to the Core specifically.
    """

    __tablename__ = "devices"

    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    platform: Mapped[str] = mapped_column(sa.String(64), default="unknown", nullable=False)
    #: web | mobile | desktop | core
    kind: Mapped[str] = mapped_column(sa.String(32), default="web", nullable=False)
    trusted: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    #: Set only for hardware that produced a valid attestation. Software mock
    #: in development; the field exists now so the Core rollout is not a
    #: migration.
    attestation: Mapped[dict | None] = mapped_column(JSONDict, nullable=True)
    can_provide_physical_presence: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, nullable=False
    )
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuthSession(Base, UUIDPk, OwnedMixin, Timestamped):
    """A live session.

    Stored server-side so lockdown and device revocation can kill sessions;
    a purely stateless JWT could not be revoked at all.
    """

    __tablename__ = "auth_sessions"

    device_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    #: Hash of the token, never the token. A database dump must not yield
    #: usable session credentials.
    token_hash: Mapped[str] = mapped_column(sa.String(128), unique=True, nullable=False, index=True)
    auth_level: Mapped[str] = mapped_column(
        sa.String(16), default=AuthLevel.BASIC.value, nullable=False
    )
    #: When the current elevation lapses back to BASIC.
    elevated_until: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expires_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    ip_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(sa.String(300), nullable=True)


# ===========================================================================
# Life Graph
# ===========================================================================


class Entity(Base, UUIDPk, OwnedMixin, Timestamped, Classified, Provenanced, SoftDeletable):
    """A node in the Life Graph.

    Typed by ``entity_type`` with the type-specific payload in ``attributes``.
    That split is what lets a new entity type ship without a migration while
    keeping the queryable, security-relevant columns (owner, type, name,
    classification, provenance) as real columns.
    """

    __tablename__ = "entities"
    __table_args__ = (
        sa.Index("ix_entities_owner_type", "owner_id", "entity_type"),
        sa.Index("ix_entities_owner_name", "owner_id", "name"),
    )

    entity_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    #: Case-folded, punctuation-stripped name used for entity resolution
    #: ("PSE&G" / "PSEG" / "Public Service Electric & Gas").
    normalized_name: Mapped[str] = mapped_column(sa.String(300), nullable=False, index=True)
    summary: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    attributes: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    #: Alternate spellings collected during resolution; kept so a merge can be
    #: explained and undone.
    aliases: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    #: Set when this entity was merged into another. Never hard-deleted, so
    #: references from old facts still resolve.
    merged_into_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )

    facts: Mapped[list[Fact]] = relationship(
        back_populates="entity", cascade="all, delete-orphan", lazy="selectin"
    )


class Relationship(Base, UUIDPk, OwnedMixin, Timestamped, Provenanced):
    """A directed, typed edge in the Life Graph."""

    __tablename__ = "relationships"
    __table_args__ = (
        sa.UniqueConstraint(
            "owner_id", "from_id", "to_id", "relation_type", name="uq_relationship_triple"
        ),
        sa.Index("ix_rel_owner_from", "owner_id", "from_id"),
        sa.Index("ix_rel_owner_to", "owner_id", "to_id"),
    )

    from_id: Mapped[str] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    to_id: Mapped[str] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    relation_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    valid_from: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    valid_to: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Fact(Base, UUIDPk, OwnedMixin, Timestamped, Classified, Provenanced):
    """One attributed assertion about an entity.

    Facts are never overwritten.  A correction writes a new row and points the
    old one at it via ``superseded_by_id``.  That is what makes "you told me
    October 18, the notice said October 14" answerable months later, and it is
    the mechanism behind the user-correction requirement.
    """

    __tablename__ = "facts"
    __table_args__ = (sa.Index("ix_facts_owner_entity_key", "owner_id", "entity_id", "key"),)

    entity_id: Mapped[str] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    key: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    value: Mapped[dict] = mapped_column(JSONDict, nullable=False)
    #: Free-text quote from the source, e.g. "passport page 1". Shown in the
    #: "Why?" explanation.
    evidence: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    observed_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    superseded_by_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("facts.id", ondelete="SET NULL"), nullable=True
    )
    superseded_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    entity: Mapped[Entity] = relationship(back_populates="facts")

    @property
    def is_current(self) -> bool:
        return self.superseded_by_id is None


# ===========================================================================
# Memory
# ===========================================================================


class Memory(Base, UUIDPk, OwnedMixin, Timestamped, Classified, Provenanced, SoftDeletable):
    """Durable, user-visible memory.

    Distinct from ``Fact`` (which hangs off an entity) and from chat history
    (which is transient).  Everything here is editable and deletable by the
    owner by design -- memory the user cannot correct is a liability.
    """

    __tablename__ = "memories"
    __table_args__ = (sa.Index("ix_memories_owner_kind", "owner_id", "kind"),)

    kind: Mapped[str] = mapped_column(sa.String(32), default=MemoryKind.FACT.value, nullable=False)
    content: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Short searchable label, e.g. "appointment preference".
    subject: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    #: Optional link into the Life Graph.
    entity_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )
    tags: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    #: Structured payload for machine-usable preferences, e.g.
    #: {"appointment_time_of_day": "afternoon"}.
    structured: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    superseded_by_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("memories.id", ondelete="SET NULL"), nullable=True
    )
    last_used_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Source(Base, UUIDPk, OwnedMixin, Timestamped, Classified):
    """A citable origin.

    Every conclusion MyBot shows can be traced to one of these, which is what
    makes the "Why?" affordance honest rather than a generated rationalisation.
    """

    __tablename__ = "sources"

    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    label: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    #: e.g. gmail message id, document id, calendar event id
    external_ref: Mapped[str | None] = mapped_column(sa.String(300), nullable=True, index=True)
    excerpt: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: Whether content from this source may ever be treated as instructions.
    trust: Mapped[str] = mapped_column(
        sa.String(16), default=TrustLevel.UNTRUSTED.value, nullable=False
    )
    occurred_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    attributes: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)


# ===========================================================================
# Documents
# ===========================================================================


class Document(Base, UUIDPk, OwnedMixin, Timestamped, Classified, SoftDeletable):
    """An ingested file and what was extracted from it."""

    __tablename__ = "documents"

    filename: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    mime_type: Mapped[str] = mapped_column(sa.String(120), default="application/octet-stream")
    byte_size: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    #: Path relative to the owner's document root. Contents live encrypted on
    #: disk, not in the database.
    storage_path: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    #: passport | vehicle_registration | insurance_declaration | utility_bill | ...
    document_type: Mapped[str | None] = mapped_column(sa.String(64), nullable=True, index=True)
    issuer: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    folder: Mapped[str] = mapped_column(sa.String(200), default="Inbox", nullable=False)
    #: Extracted text is untrusted content: a PDF can carry an injection just
    #: as well as an email can.
    extracted_text: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    extraction_status: Mapped[str] = mapped_column(sa.String(32), default="pending", nullable=False)
    extraction_error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: [{field, value, confidence, evidence}] -- never bare values.
    extracted_fields: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    entity_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )


# ===========================================================================
# Obligations
# ===========================================================================


class Obligation(Base, UUIDPk, OwnedMixin, Timestamped, Provenanced, SoftDeletable):
    """Something the owner is on the hook for.

    Broader than a todo: an obligation has a consequence if missed, a source
    that established it, and often an action that would discharge it.
    """

    __tablename__ = "obligations"
    __table_args__ = (
        sa.Index("ix_obligations_owner_due", "owner_id", "due_at"),
        sa.Index("ix_obligations_owner_status", "owner_id", "status"),
    )

    title: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: registration_renewal | bill | tax | appointment | subscription_renewal | ...
    kind: Mapped[str] = mapped_column(sa.String(64), default="generic", nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(32), default=ObligationStatus.OPEN.value, nullable=False
    )
    due_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    recurrence: Mapped[str] = mapped_column(
        sa.String(32), default=Recurrence.NONE.value, nullable=False
    )
    amount: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    currency: Mapped[str | None] = mapped_column(sa.String(8), nullable=True)
    #: What happens if this is missed. Used for priority scoring and shown to
    #: the user rather than an invented urgency adjective.
    consequence: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    entity_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )
    source_ids: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    recommended_action_type: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    #: Obligations that must be discharged before this one can be.
    depends_on_ids: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    remind_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


# ===========================================================================
# Life Inbox
# ===========================================================================


class InboxItem(Base, UUIDPk, OwnedMixin, Timestamped):
    """A card on the Life Inbox: one thing that may need the owner.

    Produced by the deterministic proactive engine, not by a model deciding
    what feels important.  ``dedupe_key`` is what stops the same registration
    deadline generating a new card on every scheduler tick.
    """

    __tablename__ = "inbox_items"
    __table_args__ = (
        sa.UniqueConstraint("owner_id", "dedupe_key", name="uq_inbox_dedupe"),
        sa.Index("ix_inbox_owner_state", "owner_id", "state"),
    )

    dedupe_key: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    category: Mapped[str] = mapped_column(
        sa.String(32), default=InboxCategory.FYI.value, nullable=False
    )
    urgency: Mapped[str] = mapped_column(
        sa.String(16), default=Urgency.LOW.value, nullable=False
    )
    #: Deterministic 0-100 score. Ranking is code, not vibes; see
    #: ``mybot_services.inbox.priority``.
    priority_score: Mapped[float] = mapped_column(sa.Float, default=0.0, nullable=False)
    state: Mapped[str] = mapped_column(
        sa.String(16), default=InboxItemState.OPEN.value, nullable=False
    )

    title: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    #: Plain-language reason this card exists, templated from real data.
    explanation: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: The "Why?" answer: the specific evidence behind the claim.
    reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    confidence: Mapped[float] = mapped_column(sa.Float, default=1.0, nullable=False)

    #: Which deterministic rule produced this.
    rule_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_ids: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    evidence: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)

    obligation_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("obligations.id", ondelete="CASCADE"), nullable=True
    )
    entity_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )
    action_proposal_id: Mapped[str | None] = mapped_column(
        UUIDStr, sa.ForeignKey("action_proposals.id", ondelete="SET NULL"), nullable=True
    )
    #: [{label, action_type, params}] offered to the user. Selecting one
    #: creates a proposal; it never executes directly from the card.
    possible_actions: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    recommended_action: Mapped[str | None] = mapped_column(sa.String(300), nullable=True)

    due_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    snoozed_until: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class DailyBrief(Base, UUIDPk, OwnedMixin, Timestamped):
    """A generated morning brief, kept so it can be re-read and audited.

    ``facts`` holds the structured data every sentence was rendered from --
    the brief is a view over it, never a free-form generation.
    """

    __tablename__ = "daily_briefs"
    __table_args__ = (sa.UniqueConstraint("owner_id", "brief_date", name="uq_brief_day"),)

    brief_date: Mapped[str] = mapped_column(sa.String(10), nullable=False)
    greeting: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    needs_you: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    handled: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    schedule: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    facts: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    #: Systems consulted, and whether each answered. Drives the honest
    #: "nothing else requires your attention" vs. "calendar unavailable".
    coverage: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)


# ===========================================================================
# Actions
# ===========================================================================


class ActionProposal(Base, UUIDPk, OwnedMixin, Timestamped):
    """A request to change something.

    Created by anything -- a model, a rule, the user clicking a button -- and
    authorized by nothing.  Authorization lives in ``ActionApproval`` and the
    policy decision recorded here.
    """

    __tablename__ = "action_proposals"
    __table_args__ = (
        sa.UniqueConstraint("owner_id", "idempotency_key", name="uq_action_idempotency"),
        sa.Index("ix_actions_owner_status", "owner_id", "status"),
    )

    action_type: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    params: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(32), default=ActionStatus.DRAFT.value, nullable=False
    )

    #: Risk as decided by the registry and raised (never lowered) by policy.
    risk: Mapped[str] = mapped_column(sa.String(16), default=RiskLevel.LOW.value, nullable=False)
    #: The floor from the registry, kept separately so tampering is visible.
    base_risk: Mapped[str] = mapped_column(
        sa.String(16), default=RiskLevel.LOW.value, nullable=False
    )

    requested_by_type: Mapped[str] = mapped_column(
        sa.String(16), default=ActorType.AGENT.value, nullable=False
    )
    requested_by_id: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    #: Which subsystem asked, e.g. "Calendar Assistant". Shown in approval UI.
    requested_by_label: Mapped[str] = mapped_column(
        sa.String(120), default="MyBot", nullable=False
    )

    #: Why, in the words of whatever produced it -- displayed to the user.
    reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: Evidence that justified the proposal.
    source_ids: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    evidence: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    assumptions: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(sa.Float, default=1.0, nullable=False)

    #: Taint tracking.  True when any input to this proposal came from content
    #: a third party controls.  The policy engine treats these far more
    #: harshly, which is the architectural half of prompt-injection defence.
    derived_from_untrusted: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, nullable=False
    )
    untrusted_source_ids: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)

    requires_approval: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    required_auth_level: Mapped[str] = mapped_column(
        sa.String(16), default=AuthLevel.BASIC.value, nullable=False
    )
    policy_outcome: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    policy_rule_id: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    policy_reasons: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)

    #: Prevents the same external effect happening twice, including across
    #: retries and duplicate submissions.
    idempotency_key: Mapped[str] = mapped_column(sa.String(120), default=new_uuid, nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    #: Populated only by an adapter, only after execution.
    execution_outcome: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    execution_result: Mapped[dict | None] = mapped_column(JSONDict, nullable=True)
    execution_error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    executed_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    llm_run_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    request_id: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)

    approvals: Mapped[list[ActionApproval]] = relationship(
        back_populates="proposal", cascade="all, delete-orphan", lazy="selectin"
    )


class ActionApproval(Base, UUIDPk, OwnedMixin, Timestamped):
    """A human decision about a proposal.

    Separate table on purpose: it records *who* consented, *how strongly* they
    proved it, and *when it stops counting*.  Single-use, so a captured
    approval cannot be replayed against a second proposal.
    """

    __tablename__ = "action_approvals"

    proposal_id: Mapped[str] = mapped_column(
        UUIDStr, sa.ForeignKey("action_proposals.id", ondelete="CASCADE"), nullable=False
    )
    decision: Mapped[str] = mapped_column(sa.String(16), nullable=False)  # approve | reject
    method: Mapped[str] = mapped_column(
        sa.String(32), default=ApprovalMethod.IN_APP.value, nullable=False
    )
    auth_level: Mapped[str] = mapped_column(
        sa.String(16), default=AuthLevel.BASIC.value, nullable=False
    )
    approver_user_id: Mapped[str] = mapped_column(UUIDStr, nullable=False)
    device_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    session_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    note: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: Binds the approval to the exact parameters shown to the user. If the
    #: proposal changes after approval, the hash no longer matches and the
    #: approval is void -- no bait-and-switch between consent and execution.
    params_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, nullable=False)
    consumed_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    invalidated_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    invalidated_reason: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)

    proposal: Mapped[ActionProposal] = relationship(back_populates="approvals")


# ===========================================================================
# Security
# ===========================================================================


class PermissionRule(Base, UUIDPk, OwnedMixin, Timestamped):
    """A grant, expressed as data the policy engine evaluates deterministically.

    Rules can only ever be created through the Security Center by an
    authenticated human.  There is no code path by which a model writes one --
    that is Rule 2, and ``tests/security`` proves it.
    """

    __tablename__ = "permission_rules"
    __table_args__ = (sa.Index("ix_perm_owner_action", "owner_id", "action_type"),)

    action_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Glob against the action's resource, e.g. "calendar:primary", "*".
    resource: Mapped[str] = mapped_column(sa.String(200), default="*", nullable=False)
    description: Mapped[str | None] = mapped_column(sa.String(300), nullable=True)

    max_amount: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    currency: Mapped[str | None] = mapped_column(sa.String(8), nullable=True)
    allowed_recipients: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    #: {"days": ["mon",...], "start": "08:00", "end": "20:00", "tz": "..."}
    allowed_time_window: Mapped[dict | None] = mapped_column(JSONDict, nullable=True)
    #: Rule-specific caps, e.g. {"max_shift_days": 7}
    constraints: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)

    requires_confirmation: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    requires_strong_auth: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    #: Refuse to auto-run on a shaky inference even when otherwise permitted.
    min_confidence: Mapped[float] = mapped_column(sa.Float, default=0.9, nullable=False)
    #: Explicitly allow automatic execution. Absent this, everything waits.
    allow_automatic: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    enabled: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    created_auth_level: Mapped[str] = mapped_column(
        sa.String(16), default=AuthLevel.STRONG.value, nullable=False
    )
    revoked_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuditEvent(Base, UUIDPk, OwnedMixin):
    """Append-only, hash-chained record of anything that mattered.

    Not ``Timestamped`` -- an audit row has no ``updated_at`` because it is
    never updated.  ORM-level guards plus database triggers reject UPDATE and
    DELETE; see ``migrations/`` for the triggers.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        sa.Index("ix_audit_owner_seq", "owner_id", "sequence"),
        sa.UniqueConstraint("owner_id", "sequence", name="uq_audit_owner_sequence"),
    )

    #: Per-owner monotonic counter. A gap is itself evidence of tampering.
    sequence: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    timestamp: Mapped[dt.datetime] = mapped_column(
        UTCDateTime, default=utcnow, nullable=False, index=True
    )

    actor_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    event_type: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)

    request_id: Mapped[str | None] = mapped_column(sa.String(64), nullable=True, index=True)
    reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    model_used: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    policy_rule: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    approval_method: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    approval_auth_level: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    integration: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    result: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    #: Already redacted by ``mybot_security.redaction`` before it lands here.
    details: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)

    previous_event_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)


class SecurityEvent(Base, UUIDPk, OwnedMixin, Timestamped):
    """Security-relevant occurrences surfaced in the Security Center.

    Kept separate from the audit chain so that noisy signals (failed logins,
    suspected injection) can be queried and expired on their own schedule
    without touching the chain.
    """

    __tablename__ = "security_events"

    event_type: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(sa.String(16), default="info", nullable=False)
    summary: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    details: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    device_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    request_id: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    acknowledged_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class SecurityState(Base, UUIDPk, OwnedMixin, Timestamped):
    """Lockdown and global posture, one row per owner."""

    __tablename__ = "security_states"
    __table_args__ = (sa.UniqueConstraint("owner_id", name="uq_security_state_owner"),)

    locked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    locked_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    locked_reason: Mapped[str | None] = mapped_column(sa.String(300), nullable=True)
    locked_by: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    automations_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    #: Bumped on unlock; any approval issued before this is void.
    approval_epoch: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)


class CredentialReference(Base, UUIDPk, OwnedMixin, Timestamped, Classified):
    """A pointer to a secret, never the secret.

    Application code passes these around.  Only the Vault can turn one into
    key material, and it prefers to perform the operation on the caller's
    behalf rather than hand anything back.
    """

    __tablename__ = "credential_references"
    __table_args__ = (sa.UniqueConstraint("owner_id", "ref", name="uq_credref_ref"),)

    #: Stable opaque handle, e.g. "cred:google:calendar:refresh".
    ref: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    purpose: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    #: OAuth scopes or equivalent. Least privilege is checked against this.
    scopes: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class VaultSecret(Base, UUIDPk, OwnedMixin, Timestamped):
    """Ciphertext at rest.

    AES-256-GCM.  The key never lives here; it comes from a
    :class:`SecureKeyStore`, which on the future Core is hardware-backed.
    ``aad`` binds each blob to its owner and ref so a row cannot be moved
    between users or repurposed.
    """

    __tablename__ = "vault_secrets"
    __table_args__ = (sa.UniqueConstraint("owner_id", "ref", name="uq_vault_ref"),)

    ref: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    #: Which master key version encrypted this, so rotation is incremental.
    key_version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    nonce: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(sa.LargeBinary, nullable=False)
    aad: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    classification: Mapped[str] = mapped_column(
        sa.String(20), default=Classification.SECRET.value, nullable=False
    )
    rotated_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class PiiToken(Base, UUIDPk, OwnedMixin, Timestamped):
    """Local mapping between a real identifier and its placeholder.

    Lives only on the owner's machine.  An external model sees ``PERSON_001``;
    the mapping that makes it meaningful never leaves.
    """

    __tablename__ = "pii_tokens"
    __table_args__ = (
        sa.UniqueConstraint("owner_id", "token", name="uq_pii_token"),
        sa.UniqueConstraint("owner_id", "value_hash", name="uq_pii_value"),
    )

    token: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Category: person | address | account | email | phone | org
    category: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    #: Keyed hash for lookup without storing a searchable plaintext index.
    value_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Encrypted via the Vault; this column holds the vault ref.
    value_ref: Mapped[str] = mapped_column(sa.String(200), nullable=False)


# ===========================================================================
# Integrations & connectors
# ===========================================================================


class Integration(Base, UUIDPk, OwnedMixin, Timestamped):
    """A connected (or mocked) external service."""

    __tablename__ = "integrations"
    __table_args__ = (sa.UniqueConstraint("owner_id", "provider", name="uq_integration_provider"),)

    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(32), default=IntegrationStatus.NOT_CONNECTED.value, nullable=False
    )
    #: Exactly the scopes granted -- shown verbatim in the Security Center so
    #: "what can MyBot do?" is answerable in seconds.
    scopes: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    credential_ref: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    account_label: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    last_sync_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    last_error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: Read-only until the owner explicitly grants write access per provider.
    write_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    settings: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)


class CalendarEvent(Base, UUIDPk, OwnedMixin, Timestamped):
    """Synced calendar event.

    Descriptions and attendee-supplied text are untrusted content -- a meeting
    invite is an attacker-controlled channel like any other.
    """

    __tablename__ = "calendar_events"
    __table_args__ = (
        sa.UniqueConstraint("owner_id", "provider", "external_id", name="uq_calevent_external"),
        sa.Index("ix_calevent_owner_start", "owner_id", "start_at"),
    )

    provider: Mapped[str] = mapped_column(sa.String(64), default="mock_calendar", nullable=False)
    external_id: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    calendar_id: Mapped[str] = mapped_column(sa.String(200), default="primary", nullable=False)
    title: Mapped[str] = mapped_column(sa.String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    location: Mapped[str | None] = mapped_column(sa.String(300), nullable=True)
    start_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, nullable=False)
    end_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, nullable=False)
    all_day: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    attendees: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    organizer: Mapped[str | None] = mapped_column(sa.String(300), nullable=True)
    status: Mapped[str] = mapped_column(sa.String(32), default="confirmed", nullable=False)
    importance: Mapped[str] = mapped_column(sa.String(16), default="normal", nullable=False)
    cancelled: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)


class EmailMessage(Base, UUIDPk, OwnedMixin, Timestamped):
    """Synced email.

    ``body`` is the canonical example of hostile input.  Nothing reads this
    field without going through the untrusted-content wrapper.
    """

    __tablename__ = "email_messages"
    __table_args__ = (
        sa.UniqueConstraint("owner_id", "provider", "external_id", name="uq_email_external"),
        sa.Index("ix_email_owner_received", "owner_id", "received_at"),
    )

    provider: Mapped[str] = mapped_column(sa.String(64), default="mock_email", nullable=False)
    external_id: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    thread_id: Mapped[str | None] = mapped_column(sa.String(200), nullable=True, index=True)
    from_address: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    from_name: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    to_addresses: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    subject: Mapped[str] = mapped_column(sa.String(500), default="", nullable=False)
    snippet: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    body: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    received_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, nullable=False)
    labels: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    is_read: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    #: Deterministic-then-model classification: actionable | important |
    #: waiting | fyi | deadline | marketing | transactional | spam_like
    classification_label: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    classification_confidence: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    requires_reply: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    replied_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    #: Set when the body contains patterns that look like an attempt to give
    #: the agent instructions. Recorded, never obeyed.
    injection_suspected: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    extracted: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)


class AutomationRule(Base, UUIDPk, OwnedMixin, Timestamped):
    """A standing instruction, e.g. "remind me before subscriptions renew".

    Automations are disabled wholesale by lockdown, and any automation whose
    action is above LOW still produces a proposal rather than an execution.
    """

    __tablename__ = "automation_rules"

    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    trigger_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    trigger_config: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    action_type: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    action_params: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    run_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    created_by: Mapped[str] = mapped_column(sa.String(200), default="user", nullable=False)


class Notification(Base, UUIDPk, OwnedMixin, Timestamped):
    """Something worth pushing to the owner's device."""

    __tablename__ = "notifications"
    __table_args__ = (
        sa.UniqueConstraint("owner_id", "dedupe_key", name="uq_notification_dedupe"),
    )

    #: Stable identifier for the underlying thing, so the same renewal noticed
    #: by both an automation and a proactive rule produces one ping rather than
    #: two. Nullable, because a genuinely one-off notification has nothing to
    #: deduplicate against.
    dedupe_key: Mapped[str | None] = mapped_column(sa.String(300), nullable=True)

    title: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    body: Mapped[str] = mapped_column(sa.Text, nullable=False)
    channel: Mapped[str] = mapped_column(sa.String(32), default="in_app", nullable=False)
    urgency: Mapped[str] = mapped_column(sa.String(16), default=Urgency.LOW.value, nullable=False)
    inbox_item_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    action_proposal_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    read_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    delivered_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class LLMRun(Base, UUIDPk, OwnedMixin, Timestamped):
    """Metadata about one model call.

    Note what is *absent*: the prompt and the completion.  Debuggability is
    real, but persisting a full prompt means persisting a second copy of the
    user's life in a table nobody thinks of as sensitive.  Hashes and shapes
    are enough to diagnose almost everything; when a body is genuinely needed
    it must be explicitly sanitized first.
    """

    __tablename__ = "llm_runs"

    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    model: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    purpose: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    request_id: Mapped[str | None] = mapped_column(sa.String(64), nullable=True, index=True)
    prompt_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    status: Mapped[str] = mapped_column(sa.String(32), default="ok", nullable=False)
    error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    #: Highest classification present in the outbound payload, after
    #: minimisation and tokenisation.
    max_classification_sent: Mapped[str] = mapped_column(
        sa.String(20), default=Classification.NORMAL.value, nullable=False
    )
    pii_tokenized: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    #: Whether untrusted content was in the context window for this call.
    contained_untrusted: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    schema_valid: Mapped[bool | None] = mapped_column(sa.Boolean, nullable=True)

    #: Did this call physically leave the machine?
    #:
    #: Recorded at the time of the call rather than derived later from the
    #: provider name, because the answer must not change when somebody edits
    #: their configuration. A ledger whose historical rows re-interpret
    #: themselves is not a ledger.
    #:
    #: **NULL means unknown**, not "no". Rows written before the ledger existed
    #: genuinely have no answer, and backfilling them with ``False`` would make
    #: the ledger claim nothing left during a period it has no record of. "We
    #: have no record" and "nothing happened" are different sentences, and a
    #: privacy ledger that conflates them is worth nothing.
    left_machine: Mapped[bool | None] = mapped_column(sa.Boolean, default=False, nullable=True)
    #: Where it went, as a hostname. Null when nothing left, or unknown.
    destination: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)


class ChatMessage(Base, UUIDPk, OwnedMixin, Timestamped):
    """Conversation history.

    Retained separately from durable memory and subject to its own retention
    policy -- talking to MyBot should not silently create permanent records.
    """

    __tablename__ = "chat_messages"
    __table_args__ = (sa.Index("ix_chat_owner_conv", "owner_id", "conversation_id"),)

    conversation_id: Mapped[str] = mapped_column(UUIDStr, nullable=False)
    role: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    content: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Tool calls made and the ids of records that grounded the answer.
    tool_calls: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    citations: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)
    llm_run_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    action_proposal_ids: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)


class LearnedPreference(Base, UUIDPk, OwnedMixin, Timestamped):
    """Something MyBot worked out about this owner by watching them.

    This table is the closest thing MyBot has to an individual identity. The
    model weights are rented and interchangeable; *this* is what makes one
    installation different from every other one, and it is why a backup is
    worth having.

    Four properties are load-bearing:

    **Evidence, not vibes.** Every row carries how many times it was observed,
    when it was first and last seen, and the ids of the records that support
    it. A preference with three observations is presented differently from one
    with thirty. Nothing here is a model's opinion about the user.

    **Inspectable and reversible.** The owner can read every row in plain
    language, correct it, or delete it. A system that learns things about you
    that you cannot see or change is surveillance, not assistance.

    **Never authority.** A learned preference can shape what MyBot *suggests*
    and how it phrases things. It can never grant a permission, raise a risk
    ceiling, or approve an action -- that is Rule 2 applied to learning, and it
    is enforced in :mod:`mybot_services.learning`, not just documented here.
    An attacker who successfully poisons this table gets to change MyBot's
    manners, not its authority.

    **Portable across models.** Nothing here references a provider or a model
    id. Swap the brain and the individual survives.
    """

    __tablename__ = "learned_preferences"
    __table_args__ = (
        # One row per (kind, subject). Repeated observation increments evidence
        # rather than accumulating near-duplicate rows that would each look
        # weakly supported.
        sa.UniqueConstraint("owner_id", "kind", "subject", name="uq_learned_subject"),
        sa.Index("ix_learned_owner_kind", "owner_id", "kind"),
    )

    #: See ``mybot_services.learning.LEARNABLE`` -- a fixed vocabulary, not
    #: free text, so the set of things MyBot can conclude about someone is
    #: reviewable in one place.
    kind: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: What the preference is *about*: an action type, a category, an entity.
    subject: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    #: The learned value. Shape depends on ``kind`` and is validated on write.
    value: Mapped[dict] = mapped_column(JSONDict, default=dict, nullable=False)

    #: How many independent observations support this.
    evidence_count: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    #: Observations that contradicted it. Kept rather than subtracted, because
    #: "you did this 9 times out of 10" and "you did this 9 times" are
    #: different claims and only one of them is honest.
    contradiction_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    confidence: Mapped[float] = mapped_column(sa.Float, default=0.0, nullable=False)

    first_observed_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, nullable=False)
    last_observed_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, nullable=False)
    #: Ids of the records that support this, capped. Lets the owner ask "why do
    #: you think that?" and get specific records back rather than a shrug.
    evidence_refs: Mapped[list] = mapped_column(JSONDict, default=list, nullable=False)

    #: Plain-language sentence shown to the owner. Written by the deterministic
    #: learner, not by a model, so it cannot drift from what the row says.
    explanation: Mapped[str] = mapped_column(sa.Text, nullable=False)

    #: The owner switched this off. Kept rather than deleted so the same
    #: observation does not immediately re-learn it -- being overruled is
    #: itself a durable thing to know.
    muted: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    #: The owner stated this directly instead of it being inferred. Confirmed
    #: preferences outrank inferred ones and are never decayed away.
    confirmed_by_owner: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    #: Set when learning is derived from content that came from outside the
    #: owner. Such rows are quarantined: never applied, only shown. This is the
    #: taint rule from the injection defence, applied to learning.
    derived_from_untrusted: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, nullable=False
    )


#: Every model that holds personal data. Used by export, deletion and the
#: owner-isolation test that walks the registry.
OWNED_MODELS: tuple[type, ...] = tuple(
    m
    for m in Base.registry._class_registry.values()
    if isinstance(m, type) and issubclass(m, OwnedMixin)
)


__all__ = [
    "ActionApproval",
    "ActionProposal",
    "AuditEvent",
    "AuthSession",
    "AutomationRule",
    "Base",
    "CalendarEvent",
    "ChatMessage",
    "CredentialReference",
    "DailyBrief",
    "Device",
    "Document",
    "EmailMessage",
    "Entity",
    "Fact",
    "InboxItem",
    "Integration",
    "LLMRun",
    "LearnedPreference",
    "Memory",
    "Notification",
    "OWNED_MODELS",
    "Obligation",
    "PermissionRule",
    "PiiToken",
    "Relationship",
    "SecurityEvent",
    "SecurityState",
    "Source",
    "User",
    "VaultSecret",
]
