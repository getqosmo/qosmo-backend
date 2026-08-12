"""The fixed vocabulary of things MyBot is allowed to conclude about someone.

A learning system with an open-ended vocabulary is unreviewable: you cannot
answer "what could this thing decide about me?" without reading the whole
codebase and guessing. So the set is closed, declared here, and every entry
states what evidence creates it, what it is allowed to influence, and — most
importantly — what it is *not*.

## The rule that shapes this file

**Learning shapes suggestions. Learning never grants authority.**

That is Rule 2 ("the AI can never modify its own permissions") applied to a
system whose entire purpose is to change its own behaviour over time. A
learning loop is exactly where self-granted permission creeps in, usually
disguised as convenience: *"you approved this nine times, so I'll stop
asking."* That sentence is a permission escalation performed by a statistic,
and MyBot will not make it. It will say "you approve these most times — want to
make that a standing rule?" and the human clicks the button.

So every entry below carries an ``influences`` field naming the surfaces it may
touch, and none of them is the policy engine. :func:`assert_never_authority`
enforces it, and there is a test that walks this table and fails if a new kind
ever claims a forbidden surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: Surfaces a learned preference may influence. Deliberately small.
Surface = Literal[
    "phrasing",  # how MyBot words things
    "ranking",  # what it shows first
    "defaults",  # pre-filled values in a proposal the human still approves
    "timing",  # when it schedules or notifies
    "suppression",  # what it stops bringing up
    "suggestion",  # what it offers to set up, human confirms
]

#: Surfaces learning may **never** touch, named explicitly so the barrier is
#: greppable rather than implied. These are the authority surfaces.
FORBIDDEN_SURFACES: frozenset[str] = frozenset(
    {
        "policy",  # permission rules
        "risk",  # risk classification of an action
        "approval",  # whether something counts as approved
        "auth",  # authentication level
        "execution",  # whether an action runs
        "audit",  # the record
        "lockdown",  # security state
    }
)


@dataclass(frozen=True)
class LearnableKind:
    key: str
    #: What the owner sees when they ask what MyBot has learned.
    label: str
    #: What creates evidence for this.
    evidence: str
    #: Which surfaces it may influence.
    influences: tuple[str, ...]
    #: Observations needed before it is applied at all.
    min_evidence: int
    #: Fraction of observations that must agree.
    min_agreement: float
    #: True when repeated non-observation should decay it. Preferences about
    #: how somebody lives change; preferences they stated out loud do not.
    decays: bool = True


LEARNABLE: dict[str, LearnableKind] = {
    "action_rejected": LearnableKind(
        key="action_rejected",
        label="Actions you consistently turn down",
        evidence="The owner rejected a proposed action of this type.",
        # Note what this does NOT do: it does not add a DENY rule to the policy
        # engine. It stops MyBot *offering*. The distinction matters -- a
        # learned deny in the policy engine would be learning writing authority,
        # even though it writes it in the safe direction. Today's safe direction
        # is tomorrow's precedent.
        influences=("suppression", "ranking"),
        min_evidence=3,
        min_agreement=0.8,
    ),
    "action_approved": LearnableKind(
        key="action_approved",
        label="Actions you almost always approve",
        evidence="The owner approved a proposed action of this type.",
        # Emphatically NOT "defaults" or anything resembling auto-approval.
        # This exists to let MyBot *offer* to create a standing rule, which the
        # human then creates. The offer is the feature; the click is the
        # security boundary.
        influences=("suggestion", "ranking"),
        min_evidence=5,
        min_agreement=0.9,
    ),
    "preferred_time": LearnableKind(
        key="preferred_time",
        label="When you like things scheduled",
        evidence="The owner picked or moved a slot to a particular part of the day.",
        influences=("timing", "defaults"),
        min_evidence=3,
        min_agreement=0.6,
    ),
    "notification_fatigue": LearnableKind(
        key="notification_fatigue",
        label="What you would rather not be pinged about",
        evidence="The owner dismissed notifications in a category without acting.",
        influences=("suppression", "timing"),
        min_evidence=4,
        min_agreement=0.75,
    ),
    "correction": LearnableKind(
        key="correction",
        label="Things you have corrected MyBot about",
        evidence="The owner explicitly told MyBot it had something wrong.",
        # A correction is the single highest-value learning signal in the
        # system: unambiguous, owner-authored, and about a specific fact. It
        # applies immediately -- making somebody repeat a correction three
        # times before it sticks is how you make an assistant infuriating.
        influences=("phrasing", "ranking", "defaults"),
        min_evidence=1,
        min_agreement=1.0,
        decays=False,
    ),
    "entity_importance": LearnableKind(
        key="entity_importance",
        label="People and things that matter most to you",
        evidence="The owner opened, asked about or acted on an entity repeatedly.",
        influences=("ranking",),
        min_evidence=4,
        min_agreement=0.5,
    ),
    "phrasing_style": LearnableKind(
        key="phrasing_style",
        label="How you like MyBot to talk to you",
        evidence="The owner stated a preference about length, tone or formality.",
        influences=("phrasing",),
        min_evidence=1,
        min_agreement=1.0,
        decays=False,
    ),
    "quiet_period": LearnableKind(
        key="quiet_period",
        label="When you do not want to hear from MyBot",
        evidence="The owner consistently ignored or dismissed items at a time of day.",
        influences=("timing", "suppression"),
        min_evidence=5,
        min_agreement=0.7,
    ),
}


class LearningBoundaryViolation(RuntimeError):
    """A learned preference tried to influence an authority surface.

    Raised rather than logged. If this ever fires in production it means the
    barrier between "what MyBot suggests" and "what MyBot may do" has a hole in
    it, and continuing would be worse than failing.
    """


def assert_never_authority(kind: LearnableKind) -> None:
    """Fail loudly if a learnable kind claims an authority surface.

    Called at import time over the whole table, so a kind that claims ``policy``
    cannot even be loaded, let alone applied. This is the architectural barrier
    the learning design rests on -- a comment saying "don't do this" is not one.
    """
    forbidden = FORBIDDEN_SURFACES.intersection(kind.influences)
    if forbidden:
        raise LearningBoundaryViolation(
            f"learnable kind {kind.key!r} claims authority surface(s) "
            f"{sorted(forbidden)}. Learning may shape suggestions; it may never "
            f"grant authority. See Rule 2."
        )


for _kind in LEARNABLE.values():
    assert_never_authority(_kind)


__all__ = [
    "FORBIDDEN_SURFACES",
    "LEARNABLE",
    "LearnableKind",
    "LearningBoundaryViolation",
    "Surface",
    "assert_never_authority",
]
