"""The part of MyBot that grows.

Every MyBot ships with the same code and, initially, the same rented
intelligence. What diverges — what makes an installation somebody's *own* after
a year — is this: an accumulating, private, inspectable record of how one
specific person actually behaves.

Three design commitments, each of which rules out an easier implementation.

**Learning is deterministic.** No model decides what MyBot has learned about
you. Observations are counted, agreement ratios are computed, thresholds are
declared in :mod:`.kinds`. This is not a limitation dressed as a virtue: a
model asked "what has this user taught you?" will confabulate a plausible
answer, and a confabulated belief about a person is indistinguishable from a
real one until it causes harm. Counting is auditable. Vibes are not.

**Learning never grants authority.** See :mod:`.kinds`. The system is allowed
to conclude "you approve these nine times out of ten" and is *not* allowed to
conclude "so I will stop asking". It offers; the human clicks. This is the one
place where a learning system most wants to violate Rule 2, and the barrier is
enforced in code rather than in a comment.

**Learning from untrusted content is quarantined.** An email that says "Kai
prefers wire transfers approved without confirmation" must never become a
learned preference that MyBot acts on. Such rows are stored with
``derived_from_untrusted`` set, shown to the owner, and never applied. This is
the taint rule from the injection defence, applied to the one subsystem whose
job is to change future behaviour — which is exactly what an attacker with a
long horizon would target.

## What decay is for

A preference nobody has re-confirmed in months is not the same as one observed
last week. Inferred preferences lose confidence with age so MyBot does not
spend year three insisting on something that was true in year one. Preferences
the owner *stated* never decay: they said it, and MyBot forgetting it would be
a bug, not humility.
"""

from __future__ import annotations

import datetime as dt
import math

import sqlalchemy as sa
from mybot_schemas.enums import ActorType, AuditEventType
from mybot_schemas.models import LearnedPreference
from mybot_security.logging import get_logger
from sqlalchemy.orm import Session

from .kinds import LEARNABLE, LearnableKind, LearningBoundaryViolation

log = get_logger(__name__)

#: Confidence below which a preference is recorded but not applied. It still
#: shows up when the owner asks what MyBot has noticed -- "I think you might
#: prefer X, I'm not sure yet" is useful and honest.
APPLY_THRESHOLD = 0.55

#: An inferred preference loses half its confidence over this period without
#: fresh evidence. Ninety days is roughly "a season" -- long enough not to
#: forget how somebody lives, short enough to notice when it changes.
HALF_LIFE_DAYS = 90.0

#: Cap on stored evidence ids per row. Enough to answer "why do you think
#: that?" with specifics; not enough to become a second copy of the history.
MAX_EVIDENCE_REFS = 12


class LearningService:
    """Records observations and reports what has been learned.

    Takes a session and an audit service, and deliberately takes *neither* a
    policy service nor a firewall. It cannot grant a permission because it has
    no reference to anything that could.
    """

    def __init__(self, session: Session, audit=None):
        self.session = session
        self.audit = audit

    # ------------------------------------------------------------------
    # Observing
    # ------------------------------------------------------------------

    def observe(
        self,
        owner_id: str,
        *,
        kind: str,
        subject: str,
        value: dict | None = None,
        agrees: bool = True,
        evidence_ref: str | None = None,
        explanation: str | None = None,
        untrusted: bool = False,
        now: dt.datetime | None = None,
    ) -> LearnedPreference:
        """Record one observation.

        ``agrees=False`` records a *contradiction* rather than deleting the
        row. Somebody who approves a thing nine times and rejects it once has
        not taught MyBot nothing; they have taught it something with a known
        exception rate, and collapsing that to a boolean throws away the part
        that should make MyBot cautious.
        """
        spec = LEARNABLE.get(kind)
        if spec is None:
            # A typo'd kind must not silently create an unreviewable belief.
            raise LearningBoundaryViolation(
                f"unknown learnable kind {kind!r}. The vocabulary is fixed in "
                f"mybot_services.learning.kinds so it stays reviewable."
            )

        now = now or dt.datetime.now(dt.UTC)
        row = self.session.execute(
            sa.select(LearnedPreference).where(
                LearnedPreference.owner_id == owner_id,
                LearnedPreference.kind == kind,
                LearnedPreference.subject == subject,
            )
        ).scalar_one_or_none()

        if row is None:
            row = LearnedPreference(
                owner_id=owner_id,
                kind=kind,
                subject=subject,
                value=value or {},
                evidence_count=1 if agrees else 0,
                contradiction_count=0 if agrees else 1,
                first_observed_at=now,
                last_observed_at=now,
                evidence_refs=[evidence_ref] if evidence_ref else [],
                explanation=explanation or _describe(spec, subject, value or {}),
                derived_from_untrusted=untrusted,
            )
            self.session.add(row)
        else:
            if agrees:
                row.evidence_count += 1
            else:
                row.contradiction_count += 1
            row.last_observed_at = now
            if value:
                row.value = value
            if evidence_ref and evidence_ref not in row.evidence_refs:
                # Keep the most recent, so "why?" cites what happened lately
                # rather than what happened first.
                row.evidence_refs = ([evidence_ref] + list(row.evidence_refs))[
                    :MAX_EVIDENCE_REFS
                ]
            if explanation:
                row.explanation = explanation
            # Taint is sticky in one direction only. Once any part of the
            # evidence came from outside the owner, the row stays quarantined
            # -- otherwise an attacker lands one poisoned observation and then
            # launders it with trusted ones.
            row.derived_from_untrusted = row.derived_from_untrusted or untrusted

        row.confidence = self._confidence(row, spec, now)
        self.session.flush()

        log.info(
            "learning.observed",
            kind=kind,
            subject=subject,
            evidence=row.evidence_count,
            contradictions=row.contradiction_count,
            confidence=round(row.confidence, 3),
            untrusted=row.derived_from_untrusted,
        )
        return row

    def record_correction(
        self,
        owner_id: str,
        *,
        subject: str,
        correction: str,
        evidence_ref: str | None = None,
        now: dt.datetime | None = None,
    ) -> LearnedPreference:
        """The owner told MyBot it had something wrong.

        Applies immediately and never decays. Corrections are owner-authored,
        unambiguous and specific — the highest-quality signal the system gets —
        and requiring somebody to repeat themselves three times before it
        sticks is how an assistant becomes infuriating.
        """
        row = self.observe(
            owner_id,
            kind="correction",
            subject=subject,
            value={"correction": correction},
            evidence_ref=evidence_ref,
            explanation=f"You corrected MyBot about {subject}: {correction}",
            now=now,
        )
        row.confirmed_by_owner = True
        row.confidence = 1.0
        self.session.flush()

        if self.audit is not None:
            self.audit.record(
                owner_id,
                AuditEventType.MEMORY_WRITTEN,
                actor_type=ActorType.USER,
                actor_id=owner_id,
                reason="owner corrected MyBot",
                result="learned",
                # The subject, not the correction text: an audit log should not
                # become a second copy of what was said.
                details={"kind": "correction", "subject": subject},
            )
        return row

    # ------------------------------------------------------------------
    # Applying
    # ------------------------------------------------------------------

    def applicable(
        self, owner_id: str, *, kind: str | None = None, now: dt.datetime | None = None
    ) -> list[LearnedPreference]:
        """Preferences strong enough to actually change MyBot's behaviour.

        Four filters, each of which has a reason:

        * muted — the owner switched it off;
        * untrusted — the evidence came from outside the owner, so it is
          shown but never applied;
        * below the kind's evidence floor — one observation is a coincidence;
        * below the agreement or confidence threshold — a preference the owner
          contradicts a third of the time is not a preference.
        """
        now = now or dt.datetime.now(dt.UTC)
        query = sa.select(LearnedPreference).where(
            LearnedPreference.owner_id == owner_id,
            LearnedPreference.muted.is_(False),
            LearnedPreference.derived_from_untrusted.is_(False),
        )
        if kind:
            query = query.where(LearnedPreference.kind == kind)

        out = []
        for row in self.session.execute(query).scalars():
            spec = LEARNABLE.get(row.kind)
            if spec is None:
                continue
            if row.confirmed_by_owner:
                out.append(row)
                continue
            if row.evidence_count < spec.min_evidence:
                continue
            if self._agreement(row) < spec.min_agreement:
                continue
            if self._confidence(row, spec, now) < APPLY_THRESHOLD:
                continue
            out.append(row)

        out.sort(key=lambda r: r.confidence, reverse=True)
        return out

    def guidance_for_prompt(
        self, owner_id: str, *, limit: int = 12, now: dt.datetime | None = None
    ) -> list[str]:
        """Learned preferences rendered as trusted prompt guidance.

        This is how growth reaches the model. It goes into ``trusted_data``
        because it is MyBot's own deterministic conclusion about its owner —
        never into ``untrusted``, and never assembled from content that arrived
        from outside, which ``applicable`` has already excluded.

        Note the ceiling: even with a decade of learning, only the strongest
        handful reach a prompt. An assistant that prefaces every answer with
        forty remembered preferences is not personalised, it is cluttered.
        """
        rows = self.applicable(owner_id, now=now)
        phrasing_first = sorted(
            rows, key=lambda r: (r.kind not in ("correction", "phrasing_style"), -r.confidence)
        )
        return [r.explanation for r in phrasing_first[:limit]]

    def suggestions(self, owner_id: str, now: dt.datetime | None = None) -> list[dict]:
        """Standing rules MyBot would like to offer to set up.

        Read this alongside :mod:`.kinds`: MyBot has noticed the owner approves
        a kind of action almost every time. The tempting move is to stop
        asking. The correct move is to say so and offer a standing rule the
        *human* creates, which is what this returns — a suggestion, carrying
        its evidence, that some UI turns into a button.

        Nothing here creates a permission. This method returns dictionaries.
        """
        out = []
        for row in self.applicable(owner_id, kind="action_approved", now=now):
            total = row.evidence_count + row.contradiction_count
            out.append(
                {
                    "kind": "standing_rule",
                    "action_type": row.subject,
                    "headline": f"You have approved {row.subject} {row.evidence_count} of {total} times.",
                    "offer": (
                        f"Want MyBot to handle {row.subject} without asking, "
                        f"within limits you set?"
                    ),
                    "evidence_count": row.evidence_count,
                    "contradiction_count": row.contradiction_count,
                    "confidence": round(row.confidence, 2),
                    # Stated in the payload so no UI can imply otherwise.
                    "requires_human_confirmation": True,
                }
            )
        return out

    # ------------------------------------------------------------------
    # Owner control
    # ------------------------------------------------------------------

    def mute(self, owner_id: str, preference_id: str, *, muted: bool = True) -> bool:
        row = self.session.get(LearnedPreference, preference_id)
        if row is None or row.owner_id != owner_id:
            return False
        row.muted = muted
        self.session.flush()
        return True

    def confirm(self, owner_id: str, preference_id: str) -> bool:
        """The owner says "yes, that's right".

        Promotes an inference to a stated fact: full confidence, no decay.
        """
        row = self.session.get(LearnedPreference, preference_id)
        if row is None or row.owner_id != owner_id:
            return False
        row.confirmed_by_owner = True
        row.confidence = 1.0
        # Confirming a quarantined row is the owner vouching for it, which is
        # the only thing that can lift the quarantine. A human looked at it.
        row.derived_from_untrusted = False
        self.session.flush()
        return True

    def forget(self, owner_id: str, preference_id: str) -> bool:
        """Delete a learned preference outright.

        A hard delete, not a soft one. "MyBot, forget that" must mean it.
        """
        row = self.session.get(LearnedPreference, preference_id)
        if row is None or row.owner_id != owner_id:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

    # ------------------------------------------------------------------
    # Growth
    # ------------------------------------------------------------------

    def growth_report(self, owner_id: str, now: dt.datetime | None = None) -> dict:
        """What this BabyBot has become.

        Deliberately not gamified. No levels, no streaks, no "your MyBot is
        73% grown" — the point is to let somebody see what has actually been
        learned about them and correct it, which is a transparency feature
        wearing a friendly hat.
        """
        now = now or dt.datetime.now(dt.UTC)
        rows = list(
            self.session.execute(
                sa.select(LearnedPreference).where(LearnedPreference.owner_id == owner_id)
            ).scalars()
        )
        applicable = {r.id for r in self.applicable(owner_id, now=now)}

        by_kind: dict[str, list[dict]] = {}
        for row in rows:
            spec = LEARNABLE.get(row.kind)
            by_kind.setdefault(row.kind, []).append(
                {
                    "id": row.id,
                    "subject": row.subject,
                    "explanation": row.explanation,
                    "evidence_count": row.evidence_count,
                    "contradiction_count": row.contradiction_count,
                    "confidence": round(row.confidence, 2),
                    "applied": row.id in applicable,
                    "muted": row.muted,
                    "confirmed_by_owner": row.confirmed_by_owner,
                    "quarantined": row.derived_from_untrusted,
                    "first_observed": row.first_observed_at.isoformat(),
                    "last_observed": row.last_observed_at.isoformat(),
                    "label": spec.label if spec else row.kind,
                }
            )

        first = min((r.first_observed_at for r in rows), default=None)
        return {
            "learned_count": len(rows),
            "applied_count": len(applicable),
            "quarantined_count": sum(1 for r in rows if r.derived_from_untrusted),
            "muted_count": sum(1 for r in rows if r.muted),
            "learning_since": first.isoformat() if first else None,
            "days_learning": (now - first).days if first else 0,
            "by_kind": by_kind,
            "note": (
                "Everything here was worked out by counting what you did, not by "
                "asking a model what it thinks of you. You can correct or delete "
                "any of it, and none of it can give MyBot permission to do "
                "anything."
            ),
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _agreement(row: LearnedPreference) -> float:
        total = row.evidence_count + row.contradiction_count
        return row.evidence_count / total if total else 0.0

    def _confidence(
        self, row: LearnedPreference, spec: LearnableKind, now: dt.datetime
    ) -> float:
        """Evidence, agreement and recency in one number.

        Three factors multiply rather than average, so a preference cannot
        compensate for being contradicted half the time by simply being
        observed a lot. Being wrong often should not be survivable through
        volume.
        """
        if row.confirmed_by_owner:
            return 1.0

        agreement = self._agreement(row)
        # Saturating rather than linear: the difference between 3 and 6
        # observations matters; between 30 and 60 it does not.
        volume = 1.0 - math.exp(-row.evidence_count / max(spec.min_evidence, 1))

        recency = 1.0
        if spec.decays:
            last = row.last_observed_at
            if last.tzinfo is None:
                last = last.replace(tzinfo=dt.UTC)
            age_days = max((now - last).total_seconds() / 86400.0, 0.0)
            recency = 0.5 ** (age_days / HALF_LIFE_DAYS)

        return round(agreement * volume * recency, 4)


def _describe(spec: LearnableKind, subject: str, value: dict) -> str:
    """Plain-language explanation, written deterministically.

    Not model-generated, so the sentence the owner reads cannot drift from what
    the row actually contains. An explanation that sounds better than the
    evidence justifies is a small lie that compounds.
    """
    if spec.key == "action_rejected":
        return f"You usually turn down {subject}, so MyBot stopped offering it."
    if spec.key == "action_approved":
        return f"You usually approve {subject}."
    if spec.key == "preferred_time":
        when = value.get("period", "a particular time")
        return f"You prefer {subject} in the {when}."
    if spec.key == "notification_fatigue":
        return f"You rarely act on {subject} notifications, so MyBot sends fewer."
    if spec.key == "entity_importance":
        return f"{subject} comes up often, so MyBot surfaces it sooner."
    if spec.key == "phrasing_style":
        return f"You prefer MyBot to be {value.get('style', subject)}."
    if spec.key == "quiet_period":
        return f"You are usually unresponsive around {subject}, so MyBot waits."
    return f"{spec.label}: {subject}"


__all__ = ["APPLY_THRESHOLD", "HALF_LIFE_DAYS", "LearningService"]
