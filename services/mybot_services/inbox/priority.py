"""Deterministic priority scoring for the Life Inbox.

Ranking is where a product like this quietly goes wrong. If an opaque model
decides what matters, the ordering shifts between runs, cannot be explained,
and cannot be argued with. So the score is arithmetic, every term is named,
and the breakdown is stored on the card -- "why is this at the top?" has an
actual answer.

An LLM may still *enrich* a card (better wording, a suggested next step). It
does not move it up the list.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from mybot_schemas.enums import InboxCategory, Urgency

#: Weights. Tuned so that a hard deadline inside a week beats almost anything
#: else, and money beats FYI.
W_DEADLINE = 45.0
W_FINANCIAL = 20.0
W_CATEGORY = 15.0
W_IMPORTANCE = 12.0
W_CONFIDENCE = 8.0

CATEGORY_WEIGHT: dict[str, float] = {
    InboxCategory.URGENT.value: 1.0,
    InboxCategory.APPROVAL.value: 0.85,
    InboxCategory.DECISION.value: 0.8,
    InboxCategory.MONEY.value: 0.7,
    InboxCategory.WORK.value: 0.6,
    InboxCategory.TRAVEL.value: 0.55,
    InboxCategory.HOME.value: 0.45,
    InboxCategory.FAMILY.value: 0.45,
    InboxCategory.FYI.value: 0.15,
    InboxCategory.HANDLED.value: 0.05,
}


@dataclass
class PriorityInputs:
    category: str
    #: Hours until the deadline. Negative means already overdue.
    hours_until_due: float | None = None
    #: Money at stake, in the owner's currency.
    financial_impact: float | None = None
    #: 0..1 from the source signal (e.g. a VIP sender, a flagged event).
    importance: float = 0.5
    confidence: float = 1.0
    #: Consequence of missing it, used as a multiplier.
    irreversible: bool = False
    #: The owner said they care about this kind of thing.
    matches_user_rule: bool = False


@dataclass
class PriorityResult:
    score: float
    urgency: Urgency
    breakdown: dict[str, float] = field(default_factory=dict)


def _deadline_term(hours: float | None) -> float:
    """Steep near the deadline, flat far from it.

    A thing due in 3 days should not look much like a thing due in 3 months,
    and something already overdue should stay loud.
    """
    if hours is None:
        return 0.0
    if hours < 0:
        return 1.0
    if hours <= 24:
        return 0.95
    if hours <= 72:
        return 0.8
    if hours <= 24 * 7:
        return 0.6
    if hours <= 24 * 14:
        return 0.35
    if hours <= 24 * 30:
        return 0.2
    return 0.08


def _financial_term(amount: float | None) -> float:
    if not amount or amount <= 0:
        return 0.0
    if amount >= 2000:
        return 1.0
    if amount >= 500:
        return 0.75
    if amount >= 100:
        return 0.5
    if amount >= 25:
        return 0.3
    return 0.15


def score(inputs: PriorityInputs) -> PriorityResult:
    deadline = _deadline_term(inputs.hours_until_due)
    financial = _financial_term(inputs.financial_impact)
    category = CATEGORY_WEIGHT.get(inputs.category, 0.3)
    importance = max(0.0, min(1.0, inputs.importance))
    confidence = max(0.0, min(1.0, inputs.confidence))

    breakdown = {
        "deadline": round(W_DEADLINE * deadline, 2),
        "financial": round(W_FINANCIAL * financial, 2),
        "category": round(W_CATEGORY * category, 2),
        "importance": round(W_IMPORTANCE * importance, 2),
        "confidence": round(W_CONFIDENCE * confidence, 2),
    }
    total = sum(breakdown.values())

    if inputs.irreversible:
        bonus = round(total * 0.12, 2)
        breakdown["irreversible"] = bonus
        total += bonus
    if inputs.matches_user_rule:
        bonus = round(total * 0.08, 2)
        breakdown["user_rule"] = bonus
        total += bonus

    # Low confidence should not be able to shout. Capping rather than scaling
    # keeps a well-evidenced medium item above a speculative "urgent" one.
    if confidence < 0.6:
        total = min(total, 55.0)
        breakdown["low_confidence_cap"] = 55.0

    total = round(min(total, 100.0), 2)
    return PriorityResult(score=total, urgency=_urgency_for(total, inputs), breakdown=breakdown)


def _urgency_for(total: float, inputs: PriorityInputs) -> Urgency:
    overdue = inputs.hours_until_due is not None and inputs.hours_until_due < 0
    if overdue or total >= 78:
        return Urgency.CRITICAL
    if total >= 58:
        return Urgency.HIGH
    if total >= 35:
        return Urgency.MEDIUM
    if total >= 15:
        return Urgency.LOW
    return Urgency.NONE


def hours_until(when: dt.datetime | None, *, now: dt.datetime | None = None) -> float | None:
    if when is None:
        return None
    now = now or dt.datetime.now(dt.UTC)
    return (when - now).total_seconds() / 3600.0


__all__ = [
    "CATEGORY_WEIGHT",
    "PriorityInputs",
    "PriorityResult",
    "hours_until",
    "score",
]
