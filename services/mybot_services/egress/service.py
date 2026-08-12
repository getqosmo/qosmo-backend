"""The egress ledger: everything that has ever left this machine.

## Why this exists

Every assistant on the market says some version of "we take your privacy
seriously". None of them can answer the only question that actually settles it:

    Show me every single thing that has left my house, when, where it went,
    and why.

Amazon and Google cannot ship this, and not because nobody has got round to it.
Their revenue *is* the outbound flow — advertising for one, commerce for the
other. A complete, honest egress ledger would be a list of their own business
model, itemised, on a screen the customer reads. The incentive runs the other
way, permanently.

MyBot has the opposite incentive, so it can afford to be exact. This module is
the exactness: every model call, whether it stayed local, where it went if it
did not, what sensitivity of data was in it, and whether identifiers were
masked first.

## What makes it trustworthy rather than reassuring

**It counts failures as egress.** A request that timed out still left. A ledger
that only records successes is a marketing surface.

**It is built from the same rows the router writes.** There is no separate
"telemetry" path that could drift from reality — if a model call happened,
``LLMRun`` has a row, and this reads those rows. The ledger cannot under-report
without the call itself having not happened.

**It says when it does not know.** Periods before the ledger existed are
reported as unknown rather than as zero. "We have no record" and "nothing
happened" are different sentences and only one of them is honest.

**In sovereign mode it reads zero, and that is checkable.** Not a claim in a
settings screen — a count, from the same table, that anybody can verify.
"""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from mybot_schemas.enums import Classification
from mybot_schemas.models import LLMRun
from sqlalchemy.orm import Session

#: What each purpose actually sends, in the owner's words. The ledger is
#: useless if reading it requires knowing the codebase.
PURPOSE_PLAIN: dict[str, str] = {
    "classification": "Deciding how important an email was",
    "extraction": "Reading details out of a document",
    "reasoning": "Working out what needed your attention",
    "planning": "Preparing a suggested action",
    "summarization": "Shortening something for you",
    "chat": "Answering a question you asked",
}

#: How to describe a classification to somebody who has never read the docs.
CLASSIFICATION_PLAIN: dict[str, str] = {
    "PUBLIC": "nothing private",
    "NORMAL": "ordinary details",
    "PERSONAL": "personal details",
    "SENSITIVE": "sensitive details",
    "HIGHLY_SENSITIVE": "highly sensitive details",
    "SECRET": "secrets",
}


class EgressService:
    """Assembles the outbound record for one owner."""

    def __init__(self, session: Session):
        self.session = session

    def ledger(
        self,
        owner_id: str,
        *,
        days: int = 30,
        limit: int = 200,
        only_external: bool = True,
        now: dt.datetime | None = None,
    ) -> dict:
        """Every outbound event in the window, newest first.

        ``only_external`` defaults true because that is the question being
        asked. Local calls are counted in the summary either way, so the
        proportion stays honest — "3 things left, 428 stayed here" is more
        informative than either number alone.
        """
        now = now or dt.datetime.now(dt.UTC)
        since = now - dt.timedelta(days=days)

        query = sa.select(LLMRun).where(
            LLMRun.owner_id == owner_id, LLMRun.created_at >= since
        )
        if only_external:
            query = query.where(LLMRun.left_machine.is_(True))

        rows = list(
            self.session.execute(query.order_by(LLMRun.created_at.desc()).limit(limit)).scalars()
        )

        totals = self.session.execute(
            sa.select(
                sa.func.count(LLMRun.id),
                sa.func.sum(sa.case((LLMRun.left_machine.is_(True), 1), else_=0)),
                # Rows from before the ledger existed. Counted separately and
                # never folded into either side.
                sa.func.sum(sa.case((LLMRun.left_machine.is_(None), 1), else_=0)),
            ).where(LLMRun.owner_id == owner_id, LLMRun.created_at >= since)
        ).one()

        total_calls = int(totals[0] or 0)
        left = int(totals[1] or 0)
        unknown = int(totals[2] or 0)

        destinations = self.session.execute(
            sa.select(LLMRun.destination, sa.func.count(LLMRun.id))
            .where(
                LLMRun.owner_id == owner_id,
                LLMRun.created_at >= since,
                LLMRun.left_machine.is_(True),
            )
            .group_by(LLMRun.destination)
        ).all()

        return {
            "window_days": days,
            "since": since.isoformat(),
            "total_events": total_calls,
            "left_machine": left,
            "stayed_local": total_calls - left - unknown,
            #: Calls from before the ledger existed. Reported, never absorbed.
            "unknown": unknown,
            "destinations": [
                {"host": host or "unknown", "count": count} for host, count in destinations
            ],
            # The headline. A zero here is the product's whole thesis, and it
            # comes from the same table as everything else.
            #
            # Requires `unknown == 0` too: claiming nothing left while holding
            # rows whose answer was never recorded would be the exact dishonesty
            # this ledger exists to avoid.
            "nothing_left": left == 0 and unknown == 0,
            "events": [self._describe(row) for row in rows],
            "note": (
                "Every model call MyBot makes is recorded here, including the ones "
                "that failed — a request that timed out still left. Prompts and "
                "replies are never stored, so this shows what was sent and where, "
                "not the words themselves."
            ),
        }

    def summary(self, owner_id: str, *, days: int = 30, now: dt.datetime | None = None) -> dict:
        """The one-line version, for the Security Center."""
        full = self.ledger(owner_id, days=days, limit=0, now=now)
        return {
            "window_days": days,
            "left_machine": full["left_machine"],
            "stayed_local": full["stayed_local"],
            "unknown": full["unknown"],
            "nothing_left": full["nothing_left"],
            "destinations": full["destinations"],
            "headline": self._headline(full),
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _headline(full: dict) -> str:
        days = full["window_days"]
        if full["total_events"] == 0:
            # Not the same as "nothing left" -- say so.
            return f"MyBot has not needed a model at all in the last {days} days."
        if full["nothing_left"]:
            return (
                f"Nothing has left this machine in {days} days. "
                f"{full['stayed_local']} requests, all answered here."
            )
        if full["left_machine"] == 0 and full["unknown"]:
            return (
                f"Nothing recorded as leaving in {days} days, but {full['unknown']} "
                f"requests predate this ledger and cannot be accounted for."
            )
        hosts = ", ".join(d["host"] for d in full["destinations"]) or "one service"
        line = (
            f"{full['left_machine']} of {full['total_events']} requests left this "
            f"machine in {days} days, to {hosts}."
        )
        if full["unknown"]:
            line += f" {full['unknown']} predate this ledger and are unaccounted for."
        return line

    @staticmethod
    def _describe(row: LLMRun) -> dict:
        """One outbound event, in language somebody can act on."""
        classification = row.max_classification_sent
        plain = CLASSIFICATION_PLAIN.get(classification, classification)

        if row.status == "ok":
            outcome = "answered"
        elif row.status == "unavailable":
            outcome = "could not be reached"
        elif row.status == "schema_violation":
            outcome = "replied with something unusable"
        else:
            outcome = "failed"

        return {
            "id": row.id,
            "at": row.created_at.isoformat(),
            # None means this row predates the ledger. The UI must render that
            # as "unknown", never as "stayed here".
            "left_machine": row.left_machine,
            "destination": row.destination,
            "what": PURPOSE_PLAIN.get(row.purpose, row.purpose),
            "model": f"{row.provider}:{row.model}",
            "sent": plain,
            "classification": classification,
            "identifiers_masked": row.pii_tokenized,
            "included_outside_content": row.contained_untrusted,
            "outcome": outcome,
            "status": row.status,
            # Proof the prompt itself was not kept: a hash is all there is.
            "prompt_fingerprint": (row.prompt_hash or "")[:12],
            "tokens_sent": row.prompt_tokens,
        }

    def highest_classification_ever_sent(self, owner_id: str) -> str | None:
        """The worst case, not the average.

        Somebody deciding whether to trust this wants to know the most
        sensitive thing that ever left, not the typical thing.
        """
        rows = self.session.execute(
            sa.select(LLMRun.max_classification_sent).where(
                LLMRun.owner_id == owner_id, LLMRun.left_machine.is_(True)
            )
        ).scalars()
        ranks = [Classification(r).rank for r in rows if r in Classification.__members__.values()]
        if not ranks:
            return None
        top = max(ranks)
        return next(c.value for c in Classification if c.rank == top)


__all__ = ["CLASSIFICATION_PLAIN", "PURPOSE_PLAIN", "EgressService"]
