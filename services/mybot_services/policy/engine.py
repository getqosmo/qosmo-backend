"""The deterministic policy engine.

This is the component that decides whether an action is authorized. It is
ordinary, boring, testable code. No model is consulted, no model output
reaches it except as inert data, and its decisions do not vary with phrasing.

**Evaluation order** (each step can only make the outcome stricter):

1. Registry lookup. Unregistered action type -> DENY.
2. Parameter schema validation. Malformed -> DENY.
3. Actor capability. An agent may only propose from ``AGENT_PROPOSABLE``.
4. Taint. Anything derived from untrusted external content can never reach a
   HIGH or CRITICAL action, at any confidence, with any rule in place.
5. Lockdown. While locked, every external mutation is refused.
6. Risk floor. The registry's risk level sets baseline approval and auth
   requirements.
7. Permission rules. May satisfy the "is there authority for this at all?"
   requirement for HIGH/CRITICAL, may add constraints, and may *raise*
   requirements. They can never lower them below the floor.
8. Confidence. A shaky inference never executes without a human.
9. Monotonicity assertion. The final decision is re-checked against the floor;
   a violation is a bug and fails closed.

**Failure is refusal.** Any exception inside evaluation produces a DENY with
the reason recorded. A policy engine that fails open is not a policy engine.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from fnmatch import fnmatch

from mybot_schemas.actions import (
    AGENT_PROPOSABLE,
    UNTRUSTED_FORBIDDEN,
    ActionSpec,
    UnknownActionType,
    get_spec,
    validate_params,
)
from mybot_schemas.enums import (
    ActorType,
    AuthLevel,
    PolicyOutcome,
    RiskLevel,
)
from mybot_security.logging import get_logger
from pydantic import ValidationError

log = get_logger(__name__)

#: In V0.1 nothing at MEDIUM or above executes without a human, regardless of
#: what any permission rule says. Raising this ceiling is a product decision,
#: made once, in code, not per-request by a model.
MAX_AUTOMATIC_RISK = RiskLevel.LOW

#: Risk -> minimum auth level for the approving human.
RISK_AUTH_FLOOR: dict[RiskLevel, AuthLevel] = {
    RiskLevel.LOW: AuthLevel.BASIC,
    RiskLevel.MEDIUM: AuthLevel.BASIC,
    RiskLevel.HIGH: AuthLevel.STRONG,
    RiskLevel.CRITICAL: AuthLevel.PHYSICAL,
}

#: Risk levels that require an explicit standing permission rule *in addition*
#: to a human approval. Clicking "approve" on a $4,820 payment is not enough if
#: the owner never granted MyBot payment authority at all.
REQUIRES_STANDING_GRANT = frozenset({RiskLevel.HIGH, RiskLevel.CRITICAL})


@dataclass(frozen=True)
class RuleView:
    """A permission rule as the engine sees it.

    A plain snapshot rather than the ORM object so evaluation is pure and can
    be unit-tested without a database.
    """

    id: str
    action_type: str
    resource: str
    max_amount: float | None
    currency: str | None
    allowed_recipients: tuple[str, ...]
    allowed_time_window: dict | None
    constraints: dict
    requires_confirmation: bool
    requires_strong_auth: bool
    min_confidence: float
    allow_automatic: bool
    enabled: bool
    expires_at: dt.datetime | None
    revoked_at: dt.datetime | None

    def is_active(self, now: dt.datetime) -> bool:
        if not self.enabled or self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= now:
            return False
        return True

    def matches(self, action_type: str, resource: str) -> bool:
        if self.action_type != action_type and self.action_type != "*":
            return False
        return fnmatch(resource or "", self.resource or "*")


@dataclass(frozen=True)
class PolicyRequest:
    """Everything the engine needs, as inert data."""

    owner_id: str
    action_type: str
    params: dict
    actor_type: ActorType
    #: Resource string used for rule matching, e.g. "calendar:primary".
    resource: str = "*"
    confidence: float = 1.0
    derived_from_untrusted: bool = False
    untrusted_source_ids: tuple[str, ...] = ()
    #: Auth level currently proven by the human, if one is present.
    presented_auth_level: AuthLevel = AuthLevel.NONE
    #: Extra facts for constraint checks, e.g. original event start time.
    context: dict = field(default_factory=dict)
    now: dt.datetime | None = None


@dataclass
class PolicyDecision:
    """The engine's verdict. Persisted verbatim on the proposal."""

    outcome: PolicyOutcome
    risk: RiskLevel
    base_risk: RiskLevel
    requires_approval: bool
    required_auth_level: AuthLevel
    reasons: list[str] = field(default_factory=list)
    matched_rule_id: str | None = None
    #: Human-readable constraint failures, shown in the UI when denied.
    violations: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.outcome != PolicyOutcome.DENY

    @property
    def automatic(self) -> bool:
        return self.outcome == PolicyOutcome.ALLOW and not self.requires_approval

    def as_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "risk": self.risk.value,
            "base_risk": self.base_risk.value,
            "requires_approval": self.requires_approval,
            "required_auth_level": self.required_auth_level.value,
            "reasons": list(self.reasons),
            "matched_rule_id": self.matched_rule_id,
            "violations": list(self.violations),
        }


def _deny(reason: str, *, risk: RiskLevel = RiskLevel.CRITICAL, base: RiskLevel | None = None,
          violations: list[str] | None = None) -> PolicyDecision:
    return PolicyDecision(
        outcome=PolicyOutcome.DENY,
        risk=risk,
        base_risk=base or risk,
        requires_approval=True,
        required_auth_level=AuthLevel.PHYSICAL,
        reasons=[reason],
        violations=violations or [],
    )


class PolicyEngine:
    """Pure evaluator. Construct once, call many times; holds no state."""

    def evaluate(
        self,
        request: PolicyRequest,
        rules: list[RuleView],
        *,
        locked: bool = False,
        automations_enabled: bool = True,
    ) -> PolicyDecision:
        try:
            return self._evaluate(
                request, rules, locked=locked, automations_enabled=automations_enabled
            )
        except Exception as exc:  # noqa: BLE001
            # Fail closed. An engine that throws must not be interpreted as
            # "no objection".
            log.exception("policy.evaluation_error", action_type=request.action_type)
            return _deny(f"policy evaluation failed and therefore refused: {type(exc).__name__}")

    # -- internals -------------------------------------------------------

    def _evaluate(
        self,
        request: PolicyRequest,
        rules: list[RuleView],
        *,
        locked: bool,
        automations_enabled: bool,
    ) -> PolicyDecision:
        now = request.now or dt.datetime.now(dt.UTC)
        reasons: list[str] = []

        # 1. Registry ----------------------------------------------------
        try:
            spec: ActionSpec = get_spec(request.action_type)
        except UnknownActionType:
            return _deny(
                f"action type {request.action_type!r} is not in the action registry; "
                "unregistered actions have no risk classification and cannot be authorized"
            )

        base_risk = spec.risk
        risk = base_risk

        # 2. Parameters --------------------------------------------------
        try:
            validate_params(request.action_type, request.params)
        except ValidationError as exc:
            fields = ", ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors()[:6])
            return _deny(
                "action parameters failed schema validation; a proposal missing or "
                f"malforming required information is rejected (fields: {fields})",
                risk=base_risk,
                base=base_risk,
            )

        # 3. Actor capability --------------------------------------------
        if request.actor_type == ActorType.AGENT and request.action_type not in AGENT_PROPOSABLE:
            return _deny(
                f"the reasoning layer may not propose {request.action_type!r}; "
                "this action must originate from a direct human interaction",
                risk=base_risk,
                base=base_risk,
            )

        # 4. Taint from untrusted content --------------------------------
        if request.derived_from_untrusted:
            if request.action_type in UNTRUSTED_FORBIDDEN:
                return _deny(
                    "this action was derived from untrusted external content "
                    "(email, document, web page) and is above the risk ceiling "
                    "for such input; refused regardless of confidence or permissions",
                    risk=RiskLevel.max_of([base_risk, RiskLevel.HIGH]),
                    base=base_risk,
                    violations=[
                        f"untrusted sources: {', '.join(request.untrusted_source_ids) or 'unknown'}"
                    ],
                )
            # Below the ceiling it is allowed to proceed, but never silently.
            risk = RiskLevel.max_of([risk, RiskLevel.MEDIUM])
            reasons.append(
                "risk raised to MEDIUM: proposal derives from untrusted external content, "
                "so a human must confirm it"
            )

        # 5. Lockdown ----------------------------------------------------
        if locked and spec.external_mutation:
            return _deny(
                "MyBot is locked down; external actions are blocked until it is unlocked",
                risk=risk,
                base=base_risk,
            )
        if not automations_enabled and request.actor_type == ActorType.AUTOMATION:
            return _deny(
                "automations are disabled for this account",
                risk=risk,
                base=base_risk,
            )

        # 6. Risk floor --------------------------------------------------
        required_auth = RISK_AUTH_FLOOR[risk]
        if spec.min_auth:
            required_auth = AuthLevel(
                max(required_auth, AuthLevel(spec.min_auth), key=lambda a: a.rank)
            )
        requires_approval = risk.at_least(RiskLevel.MEDIUM)
        if requires_approval:
            reasons.append(
                f"{risk.value} risk actions require explicit approval in this release"
            )

        # 7. Permission rules --------------------------------------------
        active = [r for r in rules if r.is_active(now) and r.matches(request.action_type, request.resource)]
        matched: RuleView | None = None
        violations: list[str] = []

        for rule in active:
            rule_violations = _check_constraints(rule, spec, request, now)
            if rule_violations:
                violations.extend(rule_violations)
                continue
            matched = rule
            break

        if risk in REQUIRES_STANDING_GRANT:
            if matched is None:
                detail = (
                    "; ".join(dict.fromkeys(violations))
                    if violations
                    else "no permission rule grants this capability"
                )
                return _deny(
                    f"{risk.value} risk action requires a standing permission rule "
                    f"granted through the Security Center, and none applies ({detail})",
                    risk=risk,
                    base=base_risk,
                    violations=violations,
                )
            reasons.append(f"permitted by rule {matched.id}")

        if matched is not None:
            if matched.requires_strong_auth and required_auth.rank < AuthLevel.STRONG.rank:
                required_auth = AuthLevel.STRONG
                reasons.append(f"rule {matched.id} requires strong authentication")
            if matched.requires_confirmation:
                requires_approval = True
                reasons.append(f"rule {matched.id} requires confirmation")
            if request.confidence < matched.min_confidence:
                requires_approval = True
                reasons.append(
                    f"confidence {request.confidence:.2f} is below the rule's minimum "
                    f"{matched.min_confidence:.2f}, so a human must confirm"
                )
        elif active and violations:
            # A rule was written for this action but the request falls outside
            # it. That is a stated boundary being crossed, not an absence of
            # opinion -- surface it even when approval would otherwise cover it.
            reasons.extend(f"outside permission rule bounds: {v}" for v in dict.fromkeys(violations))
            requires_approval = True

        # 8. Automatic execution -----------------------------------------
        can_be_automatic = (
            not requires_approval
            and risk.rank <= MAX_AUTOMATIC_RISK.rank
            and not request.derived_from_untrusted
        )
        if can_be_automatic and spec.external_mutation:
            # Even a LOW action that reaches outside needs an explicit grant.
            if matched is None or not matched.allow_automatic:
                can_be_automatic = False
                requires_approval = True
                reasons.append(
                    "low-risk action still touches an external service; "
                    "no rule permits it to run automatically"
                )
        if can_be_automatic and request.confidence < 0.8:
            can_be_automatic = False
            requires_approval = True
            reasons.append(
                f"confidence {request.confidence:.2f} is too low for automatic execution"
            )

        if not can_be_automatic:
            requires_approval = True

        # 9. Monotonicity ------------------------------------------------
        floor_auth = RISK_AUTH_FLOOR[base_risk]
        if spec.min_auth:
            floor_auth = AuthLevel(max(floor_auth, AuthLevel(spec.min_auth), key=lambda a: a.rank))
        if required_auth.rank < floor_auth.rank or risk.rank < base_risk.rank:
            # Should be unreachable. If it happens, something lowered a
            # requirement, which is the one bug class this engine exists to
            # prevent -- refuse rather than proceed.
            log.error(
                "policy.monotonicity_violation",
                action_type=request.action_type,
                risk=risk.value,
                base_risk=base_risk.value,
                required_auth=required_auth.value,
                floor_auth=floor_auth.value,
            )
            return _deny(
                "internal policy inconsistency: computed requirements fell below the "
                "registry floor; refusing",
                risk=base_risk,
                base=base_risk,
            )

        outcome = (
            PolicyOutcome.ALLOW_WITH_APPROVAL if requires_approval else PolicyOutcome.ALLOW
        )
        if not reasons:
            reasons.append("low-risk internal action permitted without approval")

        return PolicyDecision(
            outcome=outcome,
            risk=risk,
            base_risk=base_risk,
            requires_approval=requires_approval,
            required_auth_level=required_auth,
            reasons=reasons,
            matched_rule_id=matched.id if matched else None,
            violations=violations,
        )


def _check_constraints(
    rule: RuleView, spec: ActionSpec, request: PolicyRequest, now: dt.datetime
) -> list[str]:
    """Return the ways ``request`` falls outside ``rule``. Empty means it fits."""
    problems: list[str] = []
    params = request.params or {}

    # Amount ceiling.
    amount = params.get("amount")
    if rule.max_amount is not None:
        if amount is None:
            if spec.money:
                problems.append("rule caps an amount but the proposal specifies none")
        elif float(amount) > float(rule.max_amount):
            problems.append(
                f"amount {amount} exceeds the rule maximum of {rule.max_amount}"
            )
    if rule.currency and params.get("currency") and params["currency"] != rule.currency:
        problems.append(f"currency {params['currency']} is not permitted by this rule")

    # Recipient allowlist.
    if rule.allowed_recipients:
        recipient = params.get("payee") or params.get("destination_ref") or params.get("provider")
        recipients = list(params.get("to") or []) if not recipient else [recipient]
        if not recipients:
            problems.append("rule restricts recipients but the proposal names none")
        for candidate in recipients:
            if not any(fnmatch(str(candidate), pattern) for pattern in rule.allowed_recipients):
                problems.append(f"recipient {candidate!r} is not on the allowed list")

    # Time-of-day window.
    window = rule.allowed_time_window
    if window:
        local = now
        day = local.strftime("%a").lower()[:3]
        days = [d.lower()[:3] for d in window.get("days", [])]
        if days and day not in days:
            problems.append(f"today ({day}) is outside the rule's allowed days")
        start, end = window.get("start"), window.get("end")
        if start and end:
            current = local.strftime("%H:%M")
            if not (start <= current <= end):
                problems.append(
                    f"current time {current} UTC is outside the allowed window {start}-{end}"
                )

    # Action-specific constraints.
    max_shift = rule.constraints.get("max_shift_days")
    if max_shift is not None and request.action_type.startswith("calendar."):
        original = request.context.get("original_start")
        proposed = params.get("new_start")
        if original and proposed:
            try:
                delta = abs(
                    (dt.datetime.fromisoformat(proposed) - dt.datetime.fromisoformat(original)).days
                )
                if delta > int(max_shift):
                    problems.append(
                        f"moving the event by {delta} days exceeds the rule's "
                        f"{max_shift}-day limit"
                    )
            except (ValueError, TypeError):
                problems.append("could not verify the time shift against the rule limit")

    max_recipients = rule.constraints.get("max_recipients")
    if max_recipients is not None:
        count = len(params.get("to") or [])
        if count > int(max_recipients):
            problems.append(f"{count} recipients exceeds the rule limit of {max_recipients}")

    return problems


__all__ = [
    "MAX_AUTOMATIC_RISK",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRequest",
    "REQUIRES_STANDING_GRANT",
    "RISK_AUTH_FLOOR",
    "RuleView",
]
