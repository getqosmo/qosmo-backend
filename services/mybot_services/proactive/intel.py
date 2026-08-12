"""Email and calendar intelligence.

Deliberately deterministic. These functions decide whether a message is a bill,
whether a meeting overlaps another, whether a deadline was stated -- and they
do it with rules, dates and pattern matching, not by asking a model to
summarise someone's inbox.

That choice is not conservatism for its own sake. Three reasons:

1. **The output drives obligations.** An invented deadline becomes a card that
   tells someone their registration expires when it does not.
2. **The input is hostile.** Email bodies are attacker-controlled. A
   classifier that is a regex cannot be talked into anything.
3. **It has to work offline**, with no provider configured, on the Core.

A model may still be layered on top to *enrich* -- better titles, a suggested
reply -- but never to establish that an obligation exists. See
``mybot_llm.enrichment`` for where that boundary sits.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from mybot_security.untrusted import scan_for_injection

# ---------------------------------------------------------------------------
# Email classification
# ---------------------------------------------------------------------------

CLASS_ACTIONABLE = "actionable"
CLASS_IMPORTANT = "important"
CLASS_WAITING = "waiting"
CLASS_FYI = "fyi"
CLASS_DEADLINE = "deadline"
CLASS_MARKETING = "marketing"
CLASS_TRANSACTIONAL = "transactional"
CLASS_SPAM_LIKE = "spam_like"

_MARKETING_MARKERS = (
    "unsubscribe", "view in browser", "manage preferences", "% off", "limited time",
    "shop now", "newsletter", "promo code", "flash sale",
)
_TRANSACTIONAL_MARKERS = (
    "receipt", "invoice", "order confirmation", "your statement", "payment received",
    "payment confirmation", "shipped", "tracking number", "renewed", "subscription",
)
_BILL_MARKERS = (
    "amount due", "payment due", "balance due", "autopay", "bill is ready",
    "statement is available", "due date", "minimum payment",
)
_DIRECT_ASK = (
    "can you", "could you", "would you", "please review", "please confirm",
    "let me know", "waiting on", "any update", "following up", "circling back",
    "need your", "your approval", "sign off", "?",
)
_DEADLINE_MARKERS = (
    "by friday", "by monday", "by tomorrow", "deadline", "expires", "expiration",
    "must be received", "no later than", "final notice", "renew by",
)
_SPAM_MARKERS = (
    "you have won", "claim your prize", "verify your account immediately",
    "wire transfer", "bitcoin", "gift card", "urgent action required",
)

_AMOUNT_RE = re.compile(r"[$£€]\s?([0-9][0-9,]*(?:\.[0-9]{2})?)")
_DATE_PATTERNS = (
    re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"),
    re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b"),
    re.compile(
        r"\b(January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+(\d{1,2}),?\s+(\d{4})\b",
        re.I,
    ),
)
_MONTHS = {
    m.lower(): i
    for i, m in enumerate(
        ["January", "February", "March", "April", "May", "June", "July",
         "August", "September", "October", "November", "December"],
        start=1,
    )
}


@dataclass
class EmailAnalysis:
    label: str
    confidence: float
    requires_reply: bool = False
    amounts: list[float] = field(default_factory=list)
    dates: list[dt.datetime] = field(default_factory=list)
    #: Named signals that produced the label. Shown in the "Why?" panel.
    signals: list[str] = field(default_factory=list)
    injection_suspected: bool = False
    injection_patterns: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "confidence": self.confidence,
            "requires_reply": self.requires_reply,
            "amounts": self.amounts,
            "dates": [d.isoformat() for d in self.dates],
            "signals": self.signals,
            "injection_suspected": self.injection_suspected,
            "injection_patterns": self.injection_patterns,
        }


def extract_dates(text: str, *, reference: dt.datetime | None = None) -> list[dt.datetime]:
    """Pull explicit calendar dates out of text.

    Only unambiguous formats. "next Tuesday" is not resolved here because
    resolving it wrongly creates a false obligation, and a missed date is a far
    cheaper error than a fabricated one.
    """
    found: list[dt.datetime] = []
    for pattern in _DATE_PATTERNS:
        for match in pattern.finditer(text or ""):
            try:
                groups = match.groups()
                if pattern.pattern.startswith(r"\b(\d{4})"):
                    year, month, day = int(groups[0]), int(groups[1]), int(groups[2])
                elif "/" in pattern.pattern:
                    month, day, year = int(groups[0]), int(groups[1]), int(groups[2])
                else:
                    month = _MONTHS[groups[0].lower()]
                    day, year = int(groups[1]), int(groups[2])
                found.append(dt.datetime(year, month, day, 12, 0, tzinfo=dt.UTC))
            except (ValueError, KeyError):
                continue
    return sorted(set(found))


def extract_amounts(text: str) -> list[float]:
    out: list[float] = []
    for match in _AMOUNT_RE.finditer(text or ""):
        try:
            out.append(float(match.group(1).replace(",", "")))
        except ValueError:
            continue
    return out


def classify_email(
    *,
    subject: str,
    body: str,
    from_address: str,
    to_addresses: list[str] | None = None,
    known_contacts: set[str] | None = None,
    now: dt.datetime | None = None,
) -> EmailAnalysis:
    """Classify a message from its own content. No model involved."""
    now = now or dt.datetime.now(dt.UTC)
    haystack = f"{subject}\n{body}".lower()
    signals: list[str] = []

    scan = scan_for_injection(f"{subject}\n{body}")

    marketing_hits = [m for m in _MARKETING_MARKERS if m in haystack]
    transactional_hits = [m for m in _TRANSACTIONAL_MARKERS if m in haystack]
    bill_hits = [m for m in _BILL_MARKERS if m in haystack]
    deadline_hits = [m for m in _DEADLINE_MARKERS if m in haystack]
    spam_hits = [m for m in _SPAM_MARKERS if m in haystack]
    ask_hits = [m for m in _DIRECT_ASK if m in haystack]

    amounts = extract_amounts(f"{subject}\n{body}")
    dates = extract_dates(f"{subject}\n{body}", reference=now)
    from_known = bool(known_contacts and from_address.lower() in known_contacts)
    personally_addressed = bool(to_addresses) and len(to_addresses) <= 3

    # Order matters: the most consequential classification wins.
    if bill_hits and amounts:
        signals.append(f"bill language: {', '.join(bill_hits[:3])}")
        signals.append(f"amount found: {amounts[0]:.2f}")
        label, confidence = CLASS_DEADLINE, 0.85
    elif deadline_hits and dates:
        signals.append(f"deadline language: {', '.join(deadline_hits[:3])}")
        label, confidence = CLASS_DEADLINE, 0.8
    elif spam_hits:
        signals.append(f"spam markers: {', '.join(spam_hits[:3])}")
        label, confidence = CLASS_SPAM_LIKE, 0.7
    elif marketing_hits and not from_known:
        signals.append(f"marketing markers: {', '.join(marketing_hits[:3])}")
        label, confidence = CLASS_MARKETING, 0.82
    elif transactional_hits:
        signals.append(f"transactional markers: {', '.join(transactional_hits[:3])}")
        label, confidence = CLASS_TRANSACTIONAL, 0.78
    elif ask_hits and personally_addressed:
        signals.append(f"direct ask: {', '.join(ask_hits[:3])}")
        label, confidence = CLASS_ACTIONABLE, 0.72
    elif from_known and personally_addressed:
        signals.append("from a known contact, addressed directly")
        label, confidence = CLASS_IMPORTANT, 0.65
    else:
        signals.append("no strong signal")
        label, confidence = CLASS_FYI, 0.5

    requires_reply = label in (CLASS_ACTIONABLE, CLASS_IMPORTANT) and bool(ask_hits)
    if from_known:
        confidence = min(1.0, confidence + 0.08)
        signals.append("sender is a known contact")

    if scan.suspected:
        # The classification is unchanged -- an injection attempt does not make
        # a message more important -- but it is recorded and surfaced.
        signals.append(f"⚠ injection-shaped content: {', '.join(scan.patterns)}")

    return EmailAnalysis(
        label=label,
        confidence=round(confidence, 2),
        requires_reply=requires_reply,
        amounts=amounts,
        dates=dates,
        signals=signals,
        injection_suspected=scan.suspected,
        injection_patterns=list(scan.patterns),
    )


# ---------------------------------------------------------------------------
# Calendar intelligence
# ---------------------------------------------------------------------------


@dataclass
class Conflict:
    first_id: str
    second_id: str
    first_title: str
    second_title: str
    overlap_minutes: int
    starts_at: dt.datetime
    #: Which one looks more movable. Used only to *suggest* -- MyBot proposes
    #: moving the appointment, never the meeting somebody else organised.
    suggested_move_id: str | None = None


def find_conflicts(events: list) -> list[Conflict]:
    """Pairwise overlap detection over a sorted event list.

    Cancelled and all-day events are excluded: an all-day "Vacation" block
    overlapping every meeting would bury the real double-bookings.
    """
    active = sorted(
        [e for e in events if not getattr(e, "cancelled", False) and not getattr(e, "all_day", False)],
        key=lambda e: e.start_at,
    )
    conflicts: list[Conflict] = []
    for i, first in enumerate(active):
        for second in active[i + 1 :]:
            if second.start_at >= first.end_at:
                break  # sorted, so nothing later can overlap either
            overlap = (min(first.end_at, second.end_at) - second.start_at).total_seconds() / 60
            if overlap <= 0:
                continue
            conflicts.append(
                Conflict(
                    first_id=first.id,
                    second_id=second.id,
                    first_title=first.title,
                    second_title=second.title,
                    overlap_minutes=int(overlap),
                    starts_at=second.start_at,
                    suggested_move_id=_more_movable(first, second),
                )
            )
    return conflicts


def _more_movable(first, second) -> str | None:
    """Guess which event is easier to move.

    A solo appointment beats a meeting with attendees; a shorter event beats a
    longer one. Only a hint for the proposal's default, and the user sees both
    options.
    """
    first_attendees = len(getattr(first, "attendees", []) or [])
    second_attendees = len(getattr(second, "attendees", []) or [])
    if first_attendees != second_attendees:
        return first.id if first_attendees < second_attendees else second.id
    first_len = (first.end_at - first.start_at).total_seconds()
    second_len = (second.end_at - second.start_at).total_seconds()
    return first.id if first_len <= second_len else second.id


def missing_location(events: list) -> list:
    """In-person-looking events with nowhere to be.

    Skips anything that names a video provider in its description -- those
    legitimately have no physical location.
    """
    out = []
    for event in events:
        if getattr(event, "all_day", False) or getattr(event, "cancelled", False):
            continue
        if event.location:
            continue
        blob = f"{event.title} {event.description or ''}".lower()
        if any(marker in blob for marker in ("zoom", "meet.google", "teams", "webex", "call", "http")):
            continue
        out.append(event)
    return out


def find_free_slot(
    events: list,
    *,
    duration_minutes: int,
    search_from: dt.datetime,
    search_until: dt.datetime,
    day_start_hour: int = 9,
    day_end_hour: int = 17,
    prefer_afternoon: bool = False,
    weekdays_only: bool = True,
) -> dt.datetime | None:
    """First gap that fits, respecting working hours and stated preferences.

    Steps in 15-minute increments and honours ``prefer_afternoon`` by trying
    the afternoon window first -- that is how the "I prefer afternoon
    appointments" memory becomes a behaviour rather than a note.

    ``weekdays_only`` defaults to True because the things MyBot reschedules are
    appointments with businesses. Proposing "your dentist, Saturday at 2pm" is
    technically a free slot and a useless suggestion.
    """
    busy = sorted(
        [(e.start_at, e.end_at) for e in events if not getattr(e, "cancelled", False)],
        key=lambda pair: pair[0],
    )
    duration = dt.timedelta(minutes=duration_minutes)
    step = dt.timedelta(minutes=15)

    windows = [(13, day_end_hour), (day_start_hour, 13)] if prefer_afternoon else [(day_start_hour, day_end_hour)]

    day = search_from.replace(minute=0, second=0, microsecond=0)
    while day < search_until:
        if weekdays_only and day.weekday() >= 5:
            day = (day + dt.timedelta(days=1)).replace(hour=0, minute=0)
            continue
        for start_hour, end_hour in windows:
            cursor = day.replace(hour=start_hour, minute=0)
            day_end = day.replace(hour=end_hour, minute=0)
            while cursor + duration <= day_end and cursor < search_until:
                if cursor >= search_from and not any(
                    cursor < busy_end and (cursor + duration) > busy_start
                    for busy_start, busy_end in busy
                ):
                    return cursor
                cursor += step
        day = (day + dt.timedelta(days=1)).replace(hour=0, minute=0)
    return None


__all__ = [
    "CLASS_ACTIONABLE",
    "CLASS_DEADLINE",
    "CLASS_FYI",
    "CLASS_IMPORTANT",
    "CLASS_MARKETING",
    "CLASS_SPAM_LIKE",
    "CLASS_TRANSACTIONAL",
    "CLASS_WAITING",
    "Conflict",
    "EmailAnalysis",
    "classify_email",
    "extract_amounts",
    "extract_dates",
    "find_conflicts",
    "find_free_slot",
    "missing_location",
]
