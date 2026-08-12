"""The Action Firewall.

Every change MyBot makes to anything -- internal or external -- goes through
this module. There is no second path. Integrations are not reachable from the
orchestrator, from an agent tool, or from a router; the only code that calls
``adapter.execute`` is :meth:`ActionFirewall._execute`, below.

The pipeline, in order:

    proposal
      -> schema validation        (registry-defined, extra fields rejected)
      -> risk classification      (registry floor, never model-supplied)
      -> policy evaluation        (deterministic, fail-closed)
      -> authentication check     (level proven, freshness enforced)
      -> human approval           (single-use, expiring, params-bound)
      -> integration adapter      (idempotent)
      -> outcome recording        (never "done" unless observed)
      -> audit event              (hash-chained)

Several properties are worth calling out because they are easy to lose:

* **Policy is re-evaluated at approval time**, not just at proposal time. A
  permission revoked in the intervening minutes takes effect immediately, and
  a lockdown engaged after a proposal was raised blocks it.
* **Approvals are bound to the exact parameters shown to the user.** The hash
  is recorded at approval and re-checked before execution, so nothing can be
  edited between consent and effect.
* **Approvals are single-use and expire.** Replay is refused and recorded as a
  security event.
* **Outcome honesty.** ``CONFIRMED`` is set only when an adapter affirmatively
  says so. Ambiguity becomes ``UNKNOWN``, which is surfaced to the user and
  never automatically retried.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import sqlalchemy as sa
from mybot_integrations.base import (
    ActionNotSupported,
    ExecutionContext,
    ExecutionResult,
    IntegrationError,
    IntegrationUnavailable,
)
from mybot_integrations.registry import IntegrationRegistry
from mybot_schemas.actions import get_spec, validate_params
from mybot_schemas.config import get_settings
from mybot_schemas.db.types import new_uuid, utcnow
from mybot_schemas.enums import (
    APPROVABLE_ACTION_STATUSES,
    ActionStatus,
    ActorType,
    ApprovalMethod,
    AuditEventType,
    AuthLevel,
    ExecutionOutcome,
    PolicyOutcome,
    RiskLevel,
    SecurityEventType,
)
from mybot_schemas.models import ActionApproval, ActionProposal, SecurityEvent
from mybot_security.crypto import canonical_json, sha256_hex
from mybot_security.logging import current_request_id, get_logger
from pydantic import ValidationError
from sqlalchemy.orm import Session

from ..audit.service import AuditService
from ..policy.engine import PolicyRequest
from ..policy.service import PolicyService

log = get_logger(__name__)


class ActionRejected(PermissionError):
    """The firewall refused. Carries a user-facing explanation."""

    def __init__(self, message: str, *, reasons: list[str] | None = None):
        super().__init__(message)
        self.reasons = reasons or []


@dataclass
class ProposalRequest:
    """What a caller submits. Note what it cannot set.

    There is no field for risk level, no field for "requires approval" and no
    field for auth level. Those are computed. A caller -- including the
    reasoning layer -- can describe *what* it wants and *why*, and nothing
    else.
    """

    owner_id: str
    action_type: str
    params: dict
    actor_type: ActorType
    actor_id: str | None = None
    actor_label: str = "MyBot"
    reason: str | None = None
    resource: str = "*"
    confidence: float = 1.0
    source_ids: list[str] | None = None
    evidence: list[dict] | None = None
    assumptions: list[str] | None = None
    derived_from_untrusted: bool = False
    untrusted_source_ids: list[str] | None = None
    context: dict | None = None
    idempotency_key: str | None = None
    llm_run_id: str | None = None
    #: Populated by the API layer from the caller's session.
    presented_auth_level: AuthLevel = AuthLevel.NONE


def params_fingerprint(action_type: str, params: dict) -> str:
    """Hash binding an approval to exactly what the user saw."""
    return sha256_hex(f"{action_type}|{canonical_json(params)}")


class ActionFirewall:
    def __init__(
        self,
        session: Session,
        registry: IntegrationRegistry,
        *,
        policy: PolicyService | None = None,
        audit: AuditService | None = None,
    ):
        self.session = session
        self.registry = registry
        self.audit = audit or AuditService(session)
        self.policy = policy or PolicyService(session, self.audit)
        self.settings = get_settings()

    # ------------------------------------------------------------------
    # Proposal
    # ------------------------------------------------------------------

    def propose(self, request: ProposalRequest) -> ActionProposal:
        """Validate, classify, evaluate and persist a proposal.

        Always returns a row. A denied action is stored with status
        ``BLOCKED`` and its reasons attached -- refusals are part of the record
        the user can inspect, not silent drops.
        """
        owner_id = request.owner_id

        # Schema validation happens before anything else touches the params.
        try:
            validated = validate_params(request.action_type, request.params)
            params = validated.model_dump(mode="json")
        except ValidationError as exc:
            proposal = self._persist_blocked(
                request,
                reasons=[
                    "parameters failed schema validation",
                    *[f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]],
                ],
                risk=RiskLevel.CRITICAL,
            )
            # `from None`: the validation error names fields and values, and
            # this exception reaches the client. The detail is already in the
            # blocked proposal and the audit record.
            raise ActionRejected(
                "This action was rejected because required information was missing or malformed.",
                reasons=proposal.policy_reasons,
            ) from None
        except Exception as exc:  # unregistered action type
            proposal = self._persist_blocked(
                request, reasons=[str(exc)], risk=RiskLevel.CRITICAL
            )
            raise ActionRejected(str(exc), reasons=[str(exc)]) from exc

        decision = self.policy.evaluate(
            PolicyRequest(
                owner_id=owner_id,
                action_type=request.action_type,
                params=params,
                actor_type=request.actor_type,
                resource=request.resource,
                confidence=request.confidence,
                derived_from_untrusted=request.derived_from_untrusted,
                untrusted_source_ids=tuple(request.untrusted_source_ids or ()),
                presented_auth_level=request.presented_auth_level,
                context=request.context or {},
            )
        )

        spec = get_spec(request.action_type)
        now = utcnow()
        proposal = ActionProposal(
            id=new_uuid(),
            owner_id=owner_id,
            action_type=request.action_type,
            params=params,
            risk=decision.risk.value,
            base_risk=decision.base_risk.value,
            requested_by_type=request.actor_type.value,
            requested_by_id=request.actor_id,
            requested_by_label=request.actor_label,
            reason=request.reason,
            source_ids=request.source_ids or [],
            evidence=request.evidence or [],
            assumptions=request.assumptions or [],
            confidence=request.confidence,
            derived_from_untrusted=request.derived_from_untrusted,
            untrusted_source_ids=request.untrusted_source_ids or [],
            requires_approval=decision.requires_approval,
            required_auth_level=decision.required_auth_level.value,
            policy_outcome=decision.outcome.value,
            policy_rule_id=decision.matched_rule_id,
            policy_reasons=decision.reasons + decision.violations,
            idempotency_key=request.idempotency_key or new_uuid(),
            expires_at=now + dt.timedelta(seconds=self.settings.approval_ttl_seconds * 4),
            llm_run_id=request.llm_run_id,
            request_id=current_request_id(),
            status=ActionStatus.DRAFT.value,
        )

        if decision.outcome == PolicyOutcome.DENY:
            proposal.status = ActionStatus.BLOCKED.value
        elif decision.requires_approval:
            proposal.status = ActionStatus.PENDING_APPROVAL.value
        else:
            proposal.status = ActionStatus.APPROVED.value

        self.session.add(proposal)
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.ACTION_PROPOSED,
            actor_type=request.actor_type,
            actor_id=request.actor_id,
            resource_type="action_proposal",
            resource_id=proposal.id,
            reason=request.reason,
            policy_rule=decision.matched_rule_id,
            integration=spec.integration,
            result=proposal.status,
            details={
                "action_type": request.action_type,
                "risk": decision.risk.value,
                "base_risk": decision.base_risk.value,
                "policy_outcome": decision.outcome.value,
                "policy_reasons": decision.reasons,
                "violations": decision.violations,
                "derived_from_untrusted": request.derived_from_untrusted,
                "confidence": request.confidence,
                "params": params,
            },
        )

        if decision.outcome == PolicyOutcome.DENY:
            self._security_event(
                owner_id,
                SecurityEventType.POLICY_DENIED,
                f"Action refused: {request.action_type}",
                severity="warning" if not request.derived_from_untrusted else "critical",
                details={
                    "proposal_id": proposal.id,
                    "reasons": decision.reasons,
                    "derived_from_untrusted": request.derived_from_untrusted,
                },
            )
            raise ActionRejected(
                decision.reasons[0] if decision.reasons else "This action is not permitted.",
                reasons=decision.reasons + decision.violations,
            )

        # Automatic execution is only reachable for LOW-risk actions that a
        # rule explicitly permits; the policy engine already enforced that.
        if not decision.requires_approval:
            self._execute(proposal, approval=None)

        return proposal

    # ------------------------------------------------------------------
    # Approval
    # ------------------------------------------------------------------

    def approve(
        self,
        owner_id: str,
        proposal_id: str,
        *,
        approver_user_id: str,
        auth_level: AuthLevel,
        session_id: str | None = None,
        device_id: str | None = None,
        note: str | None = None,
        physical_presence: bool = False,
    ) -> ActionProposal:
        """Approve and execute, if every check still passes."""
        proposal = self._load(owner_id, proposal_id)
        now = utcnow()

        if proposal.status not in {s.value for s in APPROVABLE_ACTION_STATUSES}:
            raise ActionRejected(
                f"This action can no longer be approved (status: {proposal.status})."
            )
        if proposal.expires_at is not None and proposal.expires_at <= now:
            proposal.status = ActionStatus.EXPIRED.value
            self.session.flush()
            self._audit_action(proposal, AuditEventType.ACTION_EXPIRED, result="expired")
            raise ActionRejected("This action expired before it was approved.")

        # Re-evaluate. Permissions may have been revoked, lockdown may have
        # been engaged, or the clock may have moved outside an allowed window.
        decision = self.policy.evaluate(
            PolicyRequest(
                owner_id=owner_id,
                action_type=proposal.action_type,
                params=proposal.params,
                actor_type=ActorType(proposal.requested_by_type),
                confidence=proposal.confidence,
                derived_from_untrusted=proposal.derived_from_untrusted,
                untrusted_source_ids=tuple(proposal.untrusted_source_ids or ()),
                presented_auth_level=auth_level,
            )
        )
        if decision.outcome == PolicyOutcome.DENY:
            proposal.status = ActionStatus.BLOCKED.value
            proposal.policy_reasons = decision.reasons + decision.violations
            self.session.flush()
            self._audit_action(
                proposal,
                AuditEventType.ACTION_BLOCKED,
                result="blocked_at_approval",
                details={"reasons": decision.reasons},
            )
            raise ActionRejected(
                "Conditions changed since this was proposed and it is no longer permitted.",
                reasons=decision.reasons + decision.violations,
            )

        required = AuthLevel(decision.required_auth_level)
        effective = AuthLevel.PHYSICAL if physical_presence else auth_level
        if not effective.satisfies(required):
            raise ActionRejected(
                f"This action requires {required.value} authentication "
                f"(you have {effective.value}).",
                reasons=[f"required_auth_level={required.value}"],
            )

        approval = ActionApproval(
            id=new_uuid(),
            owner_id=owner_id,
            proposal_id=proposal.id,
            decision="approve",
            method=(
                ApprovalMethod.PHYSICAL_PRESENCE.value
                if physical_presence
                else ApprovalMethod.STRONG_AUTH.value
                if effective.satisfies(AuthLevel.STRONG)
                else ApprovalMethod.IN_APP.value
            ),
            auth_level=effective.value,
            approver_user_id=approver_user_id,
            device_id=device_id,
            session_id=session_id,
            note=note,
            params_hash=params_fingerprint(proposal.action_type, proposal.params),
            expires_at=now + dt.timedelta(seconds=self.settings.approval_ttl_seconds),
        )
        self.session.add(approval)
        proposal.status = ActionStatus.APPROVED.value
        proposal.requires_approval = False
        self.session.flush()

        self._audit_action(
            proposal,
            AuditEventType.ACTION_APPROVED,
            actor_type=ActorType.USER,
            actor_id=approver_user_id,
            approval_method=approval.method,
            approval_auth_level=approval.auth_level,
            result="approved",
            details={"approval_id": approval.id, "note": note},
        )
        return self._execute(proposal, approval=approval)

    def reject(
        self,
        owner_id: str,
        proposal_id: str,
        *,
        approver_user_id: str,
        auth_level: AuthLevel = AuthLevel.BASIC,
        note: str | None = None,
    ) -> ActionProposal:
        """Reject a proposal. Deliberately requires no elevated auth."""
        proposal = self._load(owner_id, proposal_id)
        if proposal.status in {
            ActionStatus.CONFIRMED.value,
            ActionStatus.SUBMITTED.value,
            ActionStatus.PROCESSING.value,
        }:
            raise ActionRejected("This action has already been carried out.")

        self.session.add(
            ActionApproval(
                owner_id=owner_id,
                proposal_id=proposal.id,
                decision="reject",
                method=ApprovalMethod.IN_APP.value,
                auth_level=auth_level.value,
                approver_user_id=approver_user_id,
                note=note,
                params_hash=params_fingerprint(proposal.action_type, proposal.params),
                expires_at=utcnow(),
                consumed_at=utcnow(),
            )
        )
        proposal.status = ActionStatus.REJECTED.value
        self.session.flush()
        self._audit_action(
            proposal,
            AuditEventType.ACTION_REJECTED,
            actor_type=ActorType.USER,
            actor_id=approver_user_id,
            result="rejected",
            details={"note": note},
        )
        return proposal

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _execute(
        self, proposal: ActionProposal, *, approval: ActionApproval | None
    ) -> ActionProposal:
        owner_id = proposal.owner_id
        spec = get_spec(proposal.action_type)
        now = utcnow()

        # Last-moment lockdown check. Between approval and execution is a
        # small window, but "lock everything now" has to mean now.
        state = self.policy.get_security_state(owner_id)
        if state.locked and spec.external_mutation:
            proposal.status = ActionStatus.BLOCKED.value
            self.session.flush()
            self._audit_action(proposal, AuditEventType.ACTION_BLOCKED, result="lockdown")
            raise ActionRejected("MyBot is locked down; external actions are blocked.")

        if approval is not None:
            if approval.consumed_at is not None:
                self._security_event(
                    owner_id,
                    SecurityEventType.APPROVAL_REPLAY_ATTEMPT,
                    "An approval was presented twice",
                    severity="critical",
                    details={"approval_id": approval.id, "proposal_id": proposal.id},
                )
                raise ActionRejected("This approval has already been used.")
            if approval.expires_at <= now:
                raise ActionRejected("This approval expired before the action ran.")
            if approval.invalidated_at is not None:
                raise ActionRejected(
                    f"This approval is no longer valid: {approval.invalidated_reason}"
                )
            # Consent was given for specific parameters. If they differ now,
            # the consent does not cover what is about to happen.
            if approval.params_hash != params_fingerprint(proposal.action_type, proposal.params):
                self._security_event(
                    owner_id,
                    SecurityEventType.UNSAFE_MODEL_OUTPUT,
                    "Action parameters changed after approval",
                    severity="critical",
                    details={"proposal_id": proposal.id},
                )
                raise ActionRejected(
                    "The details of this action changed after you approved it. "
                    "It was not carried out."
                )
            approval.consumed_at = now

        # Internal actions have no adapter and no external effect; they are
        # marked confirmed only after the caller applies them.
        adapter = self.registry.adapter_for(proposal.action_type)
        if adapter is None:
            if not spec.external_mutation:
                proposal.status = ActionStatus.CONFIRMED.value
                proposal.execution_outcome = ExecutionOutcome.CONFIRMED.value
                proposal.executed_at = now
                proposal.execution_result = {"internal": True}
                self.session.flush()
                self._audit_action(
                    proposal, AuditEventType.ACTION_RESULT, result="confirmed",
                    details={"internal": True},
                )
                return proposal
            proposal.status = ActionStatus.FAILED.value
            proposal.execution_outcome = ExecutionOutcome.FAILED.value
            proposal.execution_error = "no integration is connected for this action"
            self.session.flush()
            self._audit_action(
                proposal, AuditEventType.ACTION_RESULT, result="failed",
                details={"error": "no_adapter"},
            )
            return proposal

        proposal.status = ActionStatus.SUBMITTED.value
        self.session.flush()
        self._audit_action(
            proposal,
            AuditEventType.ACTION_EXECUTED,
            integration=adapter.provider,
            result="submitted",
            approval_method=approval.method if approval else ApprovalMethod.NOT_REQUIRED.value,
            approval_auth_level=approval.auth_level if approval else None,
        )

        ctx = ExecutionContext(
            owner_id=owner_id,
            action_type=proposal.action_type,
            params=proposal.params,
            idempotency_key=proposal.idempotency_key,
            proposal_id=proposal.id,
            request_id=proposal.request_id,
        )

        try:
            result = adapter.execute(ctx)
        except IntegrationUnavailable as exc:
            result = ExecutionResult(
                outcome=ExecutionOutcome.FAILED,
                message="That service is not connected.",
                error=str(exc)[:300],
            )
        except ActionNotSupported as exc:
            result = ExecutionResult(
                outcome=ExecutionOutcome.FAILED,
                message="This action is not supported by the connected service.",
                error=str(exc)[:300],
            )
        except IntegrationError as exc:
            result = ExecutionResult(
                outcome=ExecutionOutcome.UNKNOWN,
                message="The service returned something MyBot could not interpret.",
                error=str(exc)[:300],
            )
        except Exception as exc:  # noqa: BLE001
            # An unexpected exception is ambiguous: the request may have been
            # sent. Never assume it failed cleanly.
            log.exception("action.adapter_crash", action_type=proposal.action_type)
            result = ExecutionResult(
                outcome=ExecutionOutcome.UNKNOWN,
                message="Something went wrong and MyBot cannot tell whether the action took effect.",
                error=f"{type(exc).__name__}",
            )

        proposal.execution_outcome = result.outcome.value
        proposal.execution_result = {
            "message": result.message,
            "external_ref": result.external_ref,
            "data": result.data,
            "simulated": adapter.is_mock,
        }
        proposal.execution_error = result.error
        proposal.executed_at = now
        proposal.status = _status_for(result.outcome)
        self.session.flush()

        self._audit_action(
            proposal,
            AuditEventType.ACTION_RESULT,
            integration=adapter.provider,
            result=result.outcome.value,
            details={
                "message": result.message,
                "external_ref": result.external_ref,
                "error": result.error,
                "simulated": adapter.is_mock,
            },
        )

        if result.outcome == ExecutionOutcome.UNKNOWN:
            self._security_event(
                owner_id,
                SecurityEventType.UNSAFE_MODEL_OUTPUT,
                f"Action outcome unknown: {proposal.action_type}",
                severity="warning",
                details={
                    "proposal_id": proposal.id,
                    "note": "not retried automatically; requires investigation",
                },
            )
        return proposal

    # ------------------------------------------------------------------
    # Lockdown support
    # ------------------------------------------------------------------

    def invalidate_pending(self, owner_id: str, reason: str) -> int:
        """Void outstanding approvals and pending actions.

        Called by lockdown. Anything already approved but not yet executed is
        stopped, because "lock it down" has to include work in flight.
        """
        now = utcnow()
        approvals = list(
            self.session.execute(
                sa.select(ActionApproval).where(
                    ActionApproval.owner_id == owner_id,
                    ActionApproval.decision == "approve",
                    ActionApproval.consumed_at.is_(None),
                    ActionApproval.invalidated_at.is_(None),
                )
            ).scalars()
        )
        for approval in approvals:
            approval.invalidated_at = now
            approval.invalidated_reason = reason

        proposals = list(
            self.session.execute(
                sa.select(ActionProposal).where(
                    ActionProposal.owner_id == owner_id,
                    ActionProposal.status.in_(
                        [
                            ActionStatus.PENDING_APPROVAL.value,
                            ActionStatus.APPROVED.value,
                            ActionStatus.PREPARED.value,
                        ]
                    ),
                )
            ).scalars()
        )
        for proposal in proposals:
            proposal.status = ActionStatus.BLOCKED.value
            proposal.policy_reasons = list(proposal.policy_reasons or []) + [reason]
        self.session.flush()

        if proposals or approvals:
            self.audit.record(
                owner_id,
                AuditEventType.ACTION_BLOCKED,
                actor_type=ActorType.SYSTEM,
                reason=reason,
                result="invalidated",
                details={"proposals": len(proposals), "approvals": len(approvals)},
            )
        return len(proposals)

    def expire_stale(self, owner_id: str) -> int:
        """Mark proposals that sat unanswered past their expiry."""
        now = utcnow()
        stale = list(
            self.session.execute(
                sa.select(ActionProposal).where(
                    ActionProposal.owner_id == owner_id,
                    ActionProposal.status == ActionStatus.PENDING_APPROVAL.value,
                    ActionProposal.expires_at.is_not(None),
                    ActionProposal.expires_at <= now,
                )
            ).scalars()
        )
        for proposal in stale:
            proposal.status = ActionStatus.EXPIRED.value
            self._audit_action(proposal, AuditEventType.ACTION_EXPIRED, result="expired")
        self.session.flush()
        return len(stale)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_proposals(
        self, owner_id: str, *, status: str | None = None, limit: int = 50
    ) -> list[ActionProposal]:
        stmt = sa.select(ActionProposal).where(ActionProposal.owner_id == owner_id)
        if status:
            stmt = stmt.where(ActionProposal.status == status)
        return list(
            self.session.execute(
                stmt.order_by(ActionProposal.created_at.desc()).limit(limit)
            ).scalars()
        )

    def get(self, owner_id: str, proposal_id: str) -> ActionProposal:
        return self._load(owner_id, proposal_id)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load(self, owner_id: str, proposal_id: str) -> ActionProposal:
        proposal = self.session.execute(
            sa.select(ActionProposal).where(
                ActionProposal.owner_id == owner_id, ActionProposal.id == proposal_id
            )
        ).scalar_one_or_none()
        if proposal is None:
            # Same error whether it does not exist or belongs to someone else.
            raise LookupError("action not found")
        return proposal

    def _persist_blocked(
        self, request: ProposalRequest, *, reasons: list[str], risk: RiskLevel
    ) -> ActionProposal:
        proposal = ActionProposal(
            id=new_uuid(),
            owner_id=request.owner_id,
            action_type=request.action_type,
            params={},
            status=ActionStatus.BLOCKED.value,
            risk=risk.value,
            base_risk=risk.value,
            requested_by_type=request.actor_type.value,
            requested_by_id=request.actor_id,
            requested_by_label=request.actor_label,
            reason=request.reason,
            confidence=request.confidence,
            derived_from_untrusted=request.derived_from_untrusted,
            untrusted_source_ids=request.untrusted_source_ids or [],
            requires_approval=True,
            required_auth_level=AuthLevel.PHYSICAL.value,
            policy_outcome=PolicyOutcome.DENY.value,
            policy_reasons=reasons,
            idempotency_key=request.idempotency_key or new_uuid(),
            request_id=current_request_id(),
        )
        self.session.add(proposal)
        self.session.flush()
        self.audit.record(
            request.owner_id,
            AuditEventType.ACTION_BLOCKED,
            actor_type=request.actor_type,
            actor_id=request.actor_id,
            resource_type="action_proposal",
            resource_id=proposal.id,
            result="blocked",
            details={"action_type": request.action_type, "reasons": reasons},
        )
        return proposal

    def _audit_action(
        self,
        proposal: ActionProposal,
        event_type: AuditEventType,
        *,
        actor_type: ActorType | None = None,
        actor_id: str | None = None,
        integration: str | None = None,
        result: str | None = None,
        approval_method: str | None = None,
        approval_auth_level: str | None = None,
        details: dict | None = None,
    ) -> None:
        self.audit.record(
            proposal.owner_id,
            event_type,
            actor_type=actor_type or ActorType(proposal.requested_by_type),
            actor_id=actor_id or proposal.requested_by_id,
            resource_type="action_proposal",
            resource_id=proposal.id,
            reason=proposal.reason,
            policy_rule=proposal.policy_rule_id,
            integration=integration or get_spec(proposal.action_type).integration,
            approval_method=approval_method,
            approval_auth_level=approval_auth_level,
            result=result,
            request_id=proposal.request_id,
            details={"action_type": proposal.action_type, **(details or {})},
        )

    def _security_event(
        self,
        owner_id: str,
        event_type: SecurityEventType,
        summary: str,
        *,
        severity: str = "info",
        details: dict | None = None,
    ) -> None:
        self.session.add(
            SecurityEvent(
                owner_id=owner_id,
                event_type=event_type.value,
                severity=severity,
                summary=summary,
                details=details or {},
                request_id=current_request_id(),
            )
        )
        self.session.flush()


def _status_for(outcome: ExecutionOutcome) -> str:
    return {
        ExecutionOutcome.CONFIRMED: ActionStatus.CONFIRMED.value,
        ExecutionOutcome.ACCEPTED: ActionStatus.PROCESSING.value,
        ExecutionOutcome.FAILED: ActionStatus.FAILED.value,
        ExecutionOutcome.UNKNOWN: ActionStatus.UNKNOWN.value,
    }[outcome]


__all__ = ["ActionFirewall", "ActionRejected", "ProposalRequest", "params_fingerprint"]
