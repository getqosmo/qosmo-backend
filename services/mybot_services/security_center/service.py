"""The Security Center.

A first-class product surface, not a settings page. The design target from the
spec is that a person can answer *"what can MyBot currently do?"* in under
thirty seconds, so this service assembles one coherent picture: devices,
connected services and their exact scopes, standing permissions, automations,
recent actions, and anything high-risk.

It also owns **lockdown**, which is asymmetric on purpose:

* Locking requires only a valid session. Panic must be cheap.
* Unlocking requires STRONG authentication. Recovery must be expensive.

Locking is not advisory. It blocks external mutations at the Action Firewall,
voids outstanding approvals, disables automations, and bumps an approval epoch
so nothing approved before the lock can be replayed after it.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlalchemy as sa
from mybot_schemas.actions import ACTION_REGISTRY
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActionStatus,
    ActorType,
    AuditEventType,
    AuthLevel,
    RiskLevel,
    SecurityEventType,
)
from mybot_schemas.models import (
    ActionProposal,
    AuthSession,
    AutomationRule,
    Device,
    Integration,
    SecurityEvent,
)
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

from ..action_firewall.service import ActionFirewall
from ..audit.service import AuditService
from ..policy.service import PolicyService
from .events import record_security_event

log = get_logger(__name__)

#: Unlocking must be at least this strong. Deliberately higher than locking.
UNLOCK_AUTH_LEVEL = AuthLevel.STRONG


class LockdownError(PermissionError):
    pass


@dataclass
class LockdownResult:
    locked: bool
    actions_blocked: int
    automations_disabled: int
    sessions_downgraded: int
    message: str


class SecurityCenterService:
    def __init__(
        self,
        session: Session,
        *,
        policy: PolicyService | None = None,
        firewall: ActionFirewall | None = None,
        audit: AuditService | None = None,
    ):
        self.session = session
        self.audit = audit or AuditService(session)
        self.policy = policy or PolicyService(session, self.audit)
        self.firewall = firewall

    # ------------------------------------------------------------------
    # Lockdown
    # ------------------------------------------------------------------

    def lock(
        self,
        owner_id: str,
        *,
        actor_id: str,
        reason: str = "requested by the owner",
        device_id: str | None = None,
    ) -> LockdownResult:
        """Engage lockdown. Cheap by design -- any valid session may do it."""
        state = self.policy.get_security_state(owner_id)
        now = utcnow()

        state.locked = True
        state.locked_at = now
        state.locked_reason = reason
        state.locked_by = actor_id
        state.automations_enabled = False
        # Every approval issued before this point is void.
        state.approval_epoch = int(state.approval_epoch or 0) + 1
        self.session.flush()

        blocked = 0
        if self.firewall is not None:
            blocked = self.firewall.invalidate_pending(owner_id, f"lockdown: {reason}")

        automations = list(
            self.session.execute(
                sa.select(AutomationRule).where(
                    AutomationRule.owner_id == owner_id, AutomationRule.enabled.is_(True)
                )
            ).scalars()
        )
        for automation in automations:
            automation.enabled = False

        # Elevated sessions drop to BASIC: a lock should not leave a STRONG
        # elevation sitting on a device that may itself be the problem.
        sessions = list(
            self.session.execute(
                sa.select(AuthSession).where(
                    AuthSession.owner_id == owner_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.auth_level != AuthLevel.BASIC.value,
                )
            ).scalars()
        )
        for auth_session in sessions:
            auth_session.auth_level = AuthLevel.BASIC.value
            auth_session.elevated_until = None
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.SECURITY,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="security_state",
            resource_id=state.id,
            reason=f"lockdown engaged: {reason}",
            result="locked",
            details={
                "actions_blocked": blocked,
                "automations_disabled": len(automations),
                "sessions_downgraded": len(sessions),
                "approval_epoch": state.approval_epoch,
            },
        )
        self._security_event(
            owner_id,
            SecurityEventType.LOCKDOWN_ENGAGED,
            "MyBot was locked down",
            severity="critical",
            details={"reason": reason, "device_id": device_id},
        )
        log.warning("security.lockdown_engaged", reason=reason, blocked=blocked)

        return LockdownResult(
            locked=True,
            actions_blocked=blocked,
            automations_disabled=len(automations),
            sessions_downgraded=len(sessions),
            message=(
                "MyBot is locked. External actions are blocked, pending approvals are void, "
                "and automations are off. Unlocking requires strong authentication."
            ),
        )

    def unlock(
        self,
        owner_id: str,
        *,
        actor_id: str,
        auth_level: AuthLevel,
        restore_automations: bool = False,
    ) -> LockdownResult:
        """Release lockdown. Requires STRONG authentication.

        Automations stay off unless explicitly restored -- coming back online
        should be a deliberate, step-by-step decision, not a single switch that
        re-enables everything at once.
        """
        if not auth_level.satisfies(UNLOCK_AUTH_LEVEL):
            self._security_event(
                owner_id,
                SecurityEventType.STRONG_AUTH_FAILURE,
                "Unlock attempted without strong authentication",
                severity="warning",
                details={"presented": auth_level.value},
            )
            raise LockdownError(
                f"unlocking MyBot requires {UNLOCK_AUTH_LEVEL.value} authentication "
                f"(presented: {auth_level.value})"
            )

        state = self.policy.get_security_state(owner_id)
        state.locked = False
        state.locked_at = None
        state.locked_reason = None
        state.locked_by = None
        if restore_automations:
            state.automations_enabled = True
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.SECURITY,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="security_state",
            resource_id=state.id,
            reason="lockdown released",
            approval_auth_level=auth_level.value,
            result="unlocked",
            details={"automations_restored": restore_automations},
        )
        self._security_event(
            owner_id,
            SecurityEventType.LOCKDOWN_RELEASED,
            "MyBot was unlocked",
            severity="warning",
            details={"auth_level": auth_level.value},
        )

        return LockdownResult(
            locked=False,
            actions_blocked=0,
            automations_disabled=0,
            sessions_downgraded=0,
            message=(
                "MyBot is unlocked."
                + ("" if restore_automations else " Automations are still off — turn them back on when you're ready.")
            ),
        )

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------

    def overview(self, owner_id: str, *, model_routing: dict | None = None, vault: dict | None = None) -> dict:
        """Everything needed to answer "what can MyBot do right now?"."""
        state = self.policy.get_security_state(owner_id)
        now = utcnow()

        devices = list(
            self.session.execute(
                sa.select(Device).where(Device.owner_id == owner_id).order_by(Device.created_at.desc())
            ).scalars()
        )
        integrations = list(
            self.session.execute(
                sa.select(Integration).where(Integration.owner_id == owner_id)
            ).scalars()
        )
        rules = self.policy.list_rules(owner_id)
        automations = list(
            self.session.execute(
                sa.select(AutomationRule).where(AutomationRule.owner_id == owner_id)
            ).scalars()
        )
        recent_actions = list(
            self.session.execute(
                sa.select(ActionProposal)
                .where(ActionProposal.owner_id == owner_id)
                .order_by(ActionProposal.created_at.desc())
                .limit(20)
            ).scalars()
        )
        events = list(
            self.session.execute(
                sa.select(SecurityEvent)
                .where(SecurityEvent.owner_id == owner_id)
                .order_by(SecurityEvent.created_at.desc())
                .limit(25)
            ).scalars()
        )

        # What MyBot can do without asking, right now. This is the headline
        # number the user reads first.
        automatic_grants = [
            r
            for r in rules
            if r.allow_automatic
            and not r.requires_confirmation
            and r.enabled
            and r.revoked_at is None
            and (r.expires_at is None or r.expires_at > now)
        ]

        high_risk_grants = [
            r
            for r in rules
            if r.enabled
            and r.revoked_at is None
            and r.action_type in ACTION_REGISTRY
            and ACTION_REGISTRY[r.action_type].risk.at_least(RiskLevel.HIGH)
        ]

        return {
            "lockdown": {
                "locked": bool(state.locked),
                "locked_at": state.locked_at.isoformat() if state.locked_at else None,
                "reason": state.locked_reason,
                "automations_enabled": bool(state.automations_enabled),
                "approval_epoch": state.approval_epoch,
                "unlock_requires": UNLOCK_AUTH_LEVEL.value,
            },
            "summary": {
                "can_act_without_asking": len(automatic_grants),
                "standing_permissions": len(rules),
                "high_risk_permissions": len(high_risk_grants),
                "connected_services": len([i for i in integrations if i.status in ("connected", "mock")]),
                "trusted_devices": len([d for d in devices if d.trusted and d.revoked_at is None]),
                "active_automations": len([a for a in automations if a.enabled]),
                "pending_approvals": len(
                    [a for a in recent_actions if a.status == ActionStatus.PENDING_APPROVAL.value]
                ),
            },
            "devices": [
                {
                    "id": d.id,
                    "name": d.name,
                    "kind": d.kind,
                    "platform": d.platform,
                    "trusted": d.trusted,
                    "can_provide_physical_presence": d.can_provide_physical_presence,
                    "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                    "revoked": d.revoked_at is not None,
                }
                for d in devices
            ],
            "integrations": [
                {
                    "id": i.id,
                    "provider": i.provider,
                    "display_name": i.display_name,
                    "status": i.status,
                    "scopes": i.scopes,
                    "write_enabled": i.write_enabled,
                    "account": i.account_label,
                    "last_sync_at": i.last_sync_at.isoformat() if i.last_sync_at else None,
                    "last_error": i.last_error,
                    "simulated": i.status == "mock",
                }
                for i in integrations
            ],
            "permissions": [
                {
                    "id": r.id,
                    "action_type": r.action_type,
                    "display": ACTION_REGISTRY[r.action_type].display
                    if r.action_type in ACTION_REGISTRY
                    else r.action_type,
                    "risk": ACTION_REGISTRY[r.action_type].risk.value
                    if r.action_type in ACTION_REGISTRY
                    else "UNKNOWN",
                    "resource": r.resource,
                    "description": r.description,
                    "max_amount": r.max_amount,
                    "allowed_recipients": r.allowed_recipients,
                    "requires_confirmation": r.requires_confirmation,
                    "requires_strong_auth": r.requires_strong_auth,
                    "allow_automatic": r.allow_automatic,
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                    "created_at": r.created_at.isoformat(),
                    "created_by": r.created_by,
                }
                for r in rules
            ],
            "automations": [
                {
                    "id": a.id,
                    "name": a.name,
                    "description": a.description,
                    "trigger_type": a.trigger_type,
                    "action_type": a.action_type,
                    "enabled": a.enabled,
                    "run_count": a.run_count,
                    "last_run_at": a.last_run_at.isoformat() if a.last_run_at else None,
                }
                for a in automations
            ],
            "recent_actions": [
                {
                    "id": a.id,
                    "action_type": a.action_type,
                    "display": ACTION_REGISTRY[a.action_type].display
                    if a.action_type in ACTION_REGISTRY
                    else a.action_type,
                    "status": a.status,
                    "risk": a.risk,
                    "requested_by": a.requested_by_label,
                    "created_at": a.created_at.isoformat(),
                    "outcome": a.execution_outcome,
                    "derived_from_untrusted": a.derived_from_untrusted,
                }
                for a in recent_actions
            ],
            "security_events": [
                {
                    "id": e.id,
                    "type": e.event_type,
                    "severity": e.severity,
                    "summary": e.summary,
                    "created_at": e.created_at.isoformat(),
                    "acknowledged": e.acknowledged_at is not None,
                }
                for e in events
            ],
            "model_routing": model_routing or {},
            "vault": vault or {},
            "audit": self.audit.verify_chain(owner_id).as_dict(),
        }

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def register_device(
        self,
        owner_id: str,
        *,
        name: str,
        kind: str = "web",
        platform: str = "unknown",
        trusted: bool = False,
        actor_id: str | None = None,
    ) -> Device:
        """Register a device. Untrusted by default -- always."""
        device = Device(
            owner_id=owner_id,
            name=name,
            kind=kind,
            platform=platform,
            trusted=trusted,
            can_provide_physical_presence=(kind == "core"),
            last_seen_at=utcnow(),
        )
        self.session.add(device)
        self.session.flush()
        self._security_event(
            owner_id,
            SecurityEventType.DEVICE_REGISTERED,
            f"Device registered: {name}",
            details={"device_id": device.id, "kind": kind, "trusted": trusted},
        )
        self.audit.record(
            owner_id,
            AuditEventType.SECURITY,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="device",
            resource_id=device.id,
            reason=f"device registered: {name}",
            result="registered",
            details={"kind": kind, "trusted": trusted},
        )
        return device

    def revoke_device(self, owner_id: str, device_id: str, *, actor_id: str) -> Device:
        """Revoke a device and kill its sessions immediately."""
        device = self.session.execute(
            sa.select(Device).where(Device.owner_id == owner_id, Device.id == device_id)
        ).scalar_one_or_none()
        if device is None:
            raise LookupError("device not found")
        device.revoked_at = utcnow()
        device.trusted = False

        sessions = list(
            self.session.execute(
                sa.select(AuthSession).where(
                    AuthSession.owner_id == owner_id,
                    AuthSession.device_id == device_id,
                    AuthSession.revoked_at.is_(None),
                )
            ).scalars()
        )
        for auth_session in sessions:
            auth_session.revoked_at = utcnow()
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.SECURITY,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="device",
            resource_id=device.id,
            reason="device revoked",
            result="revoked",
            details={"sessions_revoked": len(sessions)},
        )
        return device

    # ------------------------------------------------------------------

    def list_security_events(self, owner_id: str, limit: int = 50) -> list[SecurityEvent]:
        return list(
            self.session.execute(
                sa.select(SecurityEvent)
                .where(SecurityEvent.owner_id == owner_id)
                .order_by(SecurityEvent.created_at.desc())
                .limit(limit)
            ).scalars()
        )

    def _security_event(
        self,
        owner_id: str,
        event_type: SecurityEventType,
        summary: str,
        *,
        severity: str = "info",
        details: dict | None = None,
    ) -> SecurityEvent | None:
        """Record an attempt. See ``events.record_security_event``: this is
        committed independently so it survives a rollback of the request that
        was being refused."""
        return record_security_event(
            self.session,
            owner_id,
            event_type,
            summary,
            severity=severity,
            details=details,
        )


__all__ = ["LockdownError", "LockdownResult", "SecurityCenterService", "UNLOCK_AUTH_LEVEL"]
