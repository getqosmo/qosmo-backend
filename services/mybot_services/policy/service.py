"""Permission storage and the database-backed face of the policy engine.

Rule 2 lives here: **the AI can never modify its own permissions.**

That is enforced structurally rather than by instruction. :meth:`create_rule`
requires an ``ActorType`` and refuses anything that is not ``USER``, and it
requires a proven :class:`AuthLevel` of STRONG or better. There is no other
write path to ``permission_rules`` in the codebase, no service that wraps this
one with a system actor, and no agent tool that reaches it. A model asking for
more access can only produce text explaining why; the grant happens in the
Security Center, by a human, over a separate authenticated channel.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from mybot_schemas.actions import ACTION_REGISTRY, UnknownActionType, get_spec
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    AuthLevel,
    RiskLevel,
    SecurityEventType,
)
from mybot_schemas.models import PermissionRule, SecurityState
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

from ..audit.service import AuditService
from .engine import PolicyDecision, PolicyEngine, PolicyRequest, RuleView

log = get_logger(__name__)

#: Creating or revoking a permission is itself a security-critical operation.
PERMISSION_WRITE_AUTH = AuthLevel.STRONG


class PermissionDenied(PermissionError):
    pass


class PolicyService:
    def __init__(self, session: Session, audit: AuditService | None = None):
        self.session = session
        self.audit = audit or AuditService(session)
        self.engine = PolicyEngine()

    # -- security state --------------------------------------------------

    def get_security_state(self, owner_id: str) -> SecurityState:
        state = self.session.execute(
            sa.select(SecurityState).where(SecurityState.owner_id == owner_id)
        ).scalar_one_or_none()
        if state is None:
            state = SecurityState(owner_id=owner_id)
            self.session.add(state)
            self.session.flush()
        return state

    def is_locked(self, owner_id: str) -> bool:
        return bool(self.get_security_state(owner_id).locked)

    # -- rules -----------------------------------------------------------

    def list_rules(self, owner_id: str, *, include_revoked: bool = False) -> list[PermissionRule]:
        stmt = sa.select(PermissionRule).where(PermissionRule.owner_id == owner_id)
        if not include_revoked:
            stmt = stmt.where(PermissionRule.revoked_at.is_(None))
        return list(self.session.execute(stmt.order_by(PermissionRule.created_at.desc())).scalars())

    def rule_views(self, owner_id: str) -> list[RuleView]:
        return [_to_view(r) for r in self.list_rules(owner_id)]

    def create_rule(
        self,
        owner_id: str,
        *,
        action_type: str,
        actor_type: ActorType,
        auth_level: AuthLevel,
        created_by: str,
        resource: str = "*",
        description: str | None = None,
        max_amount: float | None = None,
        currency: str | None = None,
        allowed_recipients: list[str] | None = None,
        allowed_time_window: dict | None = None,
        constraints: dict | None = None,
        requires_confirmation: bool = True,
        requires_strong_auth: bool = False,
        min_confidence: float = 0.9,
        allow_automatic: bool = False,
        expires_at: dt.datetime | None = None,
    ) -> PermissionRule:
        """Grant a capability. Humans only.

        The two guards at the top of this method are the entire mechanism
        behind Rule 2, and ``tests/security/test_rule_two_permissions.py``
        asserts they cannot be routed around.
        """
        if actor_type != ActorType.USER:
            self._security_event(
                owner_id,
                SecurityEventType.PERMISSION_CREATED,
                "blocked: non-human actor attempted to create a permission rule",
                severity="critical",
                details={"actor_type": str(actor_type), "action_type": action_type},
            )
            raise PermissionDenied(
                "permission rules may only be created by an authenticated human through "
                "the Security Center; the reasoning layer cannot grant itself access"
            )
        if not auth_level.satisfies(PERMISSION_WRITE_AUTH):
            raise PermissionDenied(
                f"creating a permission rule requires {PERMISSION_WRITE_AUTH.value} "
                f"authentication (presented: {auth_level.value})"
            )
        if action_type not in ACTION_REGISTRY and action_type != "*":
            raise UnknownActionType(
                f"cannot grant permission for unregistered action type {action_type!r}"
            )

        # A rule cannot pre-authorize something the release does not allow to
        # run automatically anyway; say so rather than storing a misleading grant.
        if allow_automatic and action_type in ACTION_REGISTRY:
            spec = get_spec(action_type)
            if spec.risk.at_least(RiskLevel.MEDIUM):
                allow_automatic = False
                description = (
                    (description or "")
                    + " [automatic execution not available for MEDIUM+ risk in V0.1]"
                ).strip()

        rule = PermissionRule(
            owner_id=owner_id,
            action_type=action_type,
            resource=resource,
            description=description,
            max_amount=max_amount,
            currency=currency,
            allowed_recipients=allowed_recipients or [],
            allowed_time_window=allowed_time_window,
            constraints=constraints or {},
            requires_confirmation=requires_confirmation,
            requires_strong_auth=requires_strong_auth,
            min_confidence=min_confidence,
            allow_automatic=allow_automatic,
            created_by=created_by,
            created_auth_level=auth_level.value,
            expires_at=expires_at,
        )
        self.session.add(rule)
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.SECURITY,
            actor_type=ActorType.USER,
            actor_id=created_by,
            resource_type="permission_rule",
            resource_id=rule.id,
            reason=f"permission granted for {action_type}",
            approval_auth_level=auth_level.value,
            result="created",
            details={
                "action_type": action_type,
                "resource": resource,
                "max_amount": max_amount,
                "allowed_recipients": allowed_recipients or [],
                "allow_automatic": allow_automatic,
                "requires_strong_auth": requires_strong_auth,
            },
        )
        self._security_event(
            owner_id,
            SecurityEventType.PERMISSION_CREATED,
            f"Permission granted: {action_type}",
            details={"rule_id": rule.id, "action_type": action_type},
        )
        return rule

    def revoke_rule(
        self, owner_id: str, rule_id: str, *, actor_type: ActorType, actor_id: str
    ) -> PermissionRule:
        """Revoke a grant.

        Note the asymmetry with :meth:`create_rule`: revocation does not
        require strong auth. Reducing MyBot's authority should never be harder
        than granting it.
        """
        if actor_type != ActorType.USER:
            raise PermissionDenied("only a human may revoke permission rules")
        rule = self.session.execute(
            sa.select(PermissionRule).where(
                PermissionRule.owner_id == owner_id, PermissionRule.id == rule_id
            )
        ).scalar_one_or_none()
        if rule is None:
            raise LookupError("permission rule not found")
        rule.revoked_at = utcnow()
        rule.enabled = False
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.SECURITY,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="permission_rule",
            resource_id=rule.id,
            reason="permission revoked",
            result="revoked",
            details={"action_type": rule.action_type},
        )
        self._security_event(
            owner_id,
            SecurityEventType.PERMISSION_REVOKED,
            f"Permission revoked: {rule.action_type}",
            details={"rule_id": rule.id},
        )
        return rule

    # -- evaluation ------------------------------------------------------

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Evaluate an action against this owner's rules and security state."""
        state = self.get_security_state(request.owner_id)
        decision = self.engine.evaluate(
            request,
            self.rule_views(request.owner_id),
            locked=bool(state.locked),
            automations_enabled=bool(state.automations_enabled),
        )
        log.info(
            "policy.decision",
            action_type=request.action_type,
            outcome=decision.outcome.value,
            risk=decision.risk.value,
            requires_approval=decision.requires_approval,
            required_auth=decision.required_auth_level.value,
            rule=decision.matched_rule_id,
        )
        return decision

    # -- helpers ---------------------------------------------------------

    def _security_event(
        self,
        owner_id: str,
        event_type: SecurityEventType,
        summary: str,
        *,
        severity: str = "info",
        details: dict | None = None,
    ) -> None:
        from mybot_schemas.models import SecurityEvent

        self.session.add(
            SecurityEvent(
                owner_id=owner_id,
                event_type=event_type.value,
                severity=severity,
                summary=summary,
                details=details or {},
            )
        )
        self.session.flush()


def _to_view(rule: PermissionRule) -> RuleView:
    return RuleView(
        id=rule.id,
        action_type=rule.action_type,
        resource=rule.resource,
        max_amount=rule.max_amount,
        currency=rule.currency,
        allowed_recipients=tuple(rule.allowed_recipients or ()),
        allowed_time_window=rule.allowed_time_window,
        constraints=dict(rule.constraints or {}),
        requires_confirmation=bool(rule.requires_confirmation),
        requires_strong_auth=bool(rule.requires_strong_auth),
        min_confidence=float(rule.min_confidence),
        allow_automatic=bool(rule.allow_automatic),
        enabled=bool(rule.enabled),
        expires_at=rule.expires_at,
        revoked_at=rule.revoked_at,
    )


__all__ = ["PERMISSION_WRITE_AUTH", "PermissionDenied", "PolicyService"]
