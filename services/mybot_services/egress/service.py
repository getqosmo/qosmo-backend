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
the exactness: every model call *and* every connector sync — whether it stayed
local, where it went if it did not, what sensitivity of data was in it, and
whether identifiers were masked first.

A read counts. Syncing a mailbox sends the owner's identity and a query outward
even though the data flows back, and a ledger that counted only uploads would
be answering a friendlier question than the one being asked.

## What makes it trustworthy rather than reassuring

**It counts failures as egress.** A request that timed out still left. A ledger
that only records successes is a marketing surface.

**It is built from the rows the doing code writes.** There is no separate
"telemetry" path that could drift from reality: a model call cannot happen
without the router writing an ``LLMRun``, and a sync cannot happen without
``ConnectorSync`` writing an ``EgressEvent``. The ledger unions the two. It
cannot under-report without the work itself not having happened.

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
from mybot_schemas.models import EgressEvent, LLMRun
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

#: Non-model egress, in the owner's words.
KIND_PLAIN: dict[str, str] = {
    "connector.calendar": "Checking your calendar",
    "connector.email": "Checking your mailbox",
    "oauth": "Renewing access to a connected account",
    "notification": "Sending you a notification",
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

        # Two sources, unioned. Each is written by the code that actually
        # performs the outbound work, so neither can drift from reality -- see
        # the note on EgressEvent for why a single "telemetry" table populated
        # by a separate reporting path would be the wrong shape.
        model_rows = list(
            self.session.execute(
                sa.select(LLMRun)
                .where(LLMRun.owner_id == owner_id, LLMRun.created_at >= since)
                .order_by(LLMRun.created_at.desc())
                .limit(max(limit, 1) * 2)
            ).scalars()
        )
        other_rows = list(
            self.session.execute(
                sa.select(EgressEvent)
                .where(EgressEvent.owner_id == owner_id, EgressEvent.created_at >= since)
                .order_by(EgressEvent.created_at.desc())
                .limit(max(limit, 1) * 2)
            ).scalars()
        )

        described = [self._describe(r) for r in model_rows] + [
            self._describe_event(r) for r in other_rows
        ]
        described.sort(key=lambda e: e["at"], reverse=True)
        if only_external:
            described = [e for e in described if e["left_machine"] is not False]
        events = described[:limit] if limit else []

        # Counts come from the full set in the window, not from the truncated
        # event list -- a ledger whose totals depend on a page size would be
        # trivially misleading.
        everything = [self._describe(r) for r in self._all_model(owner_id, since)] + [
            self._describe_event(r) for r in self._all_events(owner_id, since)
        ]
        total_calls = len(everything)
        left = sum(1 for e in everything if e["left_machine"] is True)
        unknown = sum(1 for e in everything if e["left_machine"] is None)

        by_host: dict[str, int] = {}
        for entry in everything:
            if entry["left_machine"] is True:
                host = entry["destination"] or "unknown"
                by_host[host] = by_host.get(host, 0) + 1
        destinations = sorted(by_host.items(), key=lambda kv: (-kv[1], kv[0]))

        return {
            "window_days": days,
            "since": since.isoformat(),
            "total_events": total_calls,
            "left_machine": left,
            "stayed_local": total_calls - left - unknown,
            #: Calls from before the ledger existed. Reported, never absorbed.
            "unknown": unknown,
            "destinations": [{"host": host, "count": count} for host, count in destinations],
            # The headline. A zero here is the product's whole thesis, and it
            # comes from the same table as everything else.
            #
            # Requires `unknown == 0` too: claiming nothing left while holding
            # rows whose answer was never recorded would be the exact dishonesty
            # this ledger exists to avoid.
            "nothing_left": left == 0 and unknown == 0,
            "events": events,
            "note": (
                "Every model call and every check of a connected account is "
                "recorded here, including the ones that failed — a request that "
                "timed out still left. Checking your mail counts: the request "
                "goes out even though the mail comes back. Prompts and replies "
                "are never stored, so this shows what was sent and where, not the "
                "words themselves."
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

    def _all_model(self, owner_id: str, since: dt.datetime):
        return self.session.execute(
            sa.select(LLMRun).where(LLMRun.owner_id == owner_id, LLMRun.created_at >= since)
        ).scalars()

    def _all_events(self, owner_id: str, since: dt.datetime):
        return self.session.execute(
            sa.select(EgressEvent).where(
                EgressEvent.owner_id == owner_id, EgressEvent.created_at >= since
            )
        ).scalars()

    @staticmethod
    def _describe_event(row: EgressEvent) -> dict:
        """A connector sync, in the owner's words.

        Phrased as a request going out rather than data coming back, because
        that is what actually happened: syncing a mailbox sends the owner's
        identity and a query outward. A ledger that described this as "received
        12 emails" would be answering a friendlier question than the one asked.
        """
        what = KIND_PLAIN.get(row.kind, row.kind)
        if row.status == "ok":
            outcome = "answered"
        elif row.status == "unavailable":
            outcome = "could not be reached"
        else:
            outcome = "failed"

        return {
            "id": row.id,
            "at": row.created_at.isoformat(),
            "left_machine": row.left_machine,
            "destination": row.destination,
            "what": what,
            "model": row.provider,
            "sent": "a request for your own records",
            "classification": "NORMAL",
            "identifiers_masked": False,
            "included_outside_content": False,
            "outcome": outcome,
            "status": row.status,
            "prompt_fingerprint": "",
            "tokens_sent": None,
            "records_returned": row.records,
        }

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


__all__ = ["CLASSIFICATION_PLAIN", "KIND_PLAIN", "PURPOSE_PLAIN", "EgressService"]
