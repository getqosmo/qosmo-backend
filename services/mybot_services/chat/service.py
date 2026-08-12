"""Ask MyBot.

Chat is a secondary interface, and it is built to be *grounded* rather than
conversational. The rule: every claim about the owner's life comes from a tool
result, and every answer carries the record ids it came from.

The pipeline is intent-first:

1. A deterministic intent router recognises the questions that matter most --
   "what do I need to worry about?", "what bills are coming up?", "when does my
   registration expire?", "remember that…". These are answered entirely from
   structured data with no model in the loop, so they cannot hallucinate and
   they work with no provider configured.
2. Anything else falls through to a tool-augmented model call. The model sees
   *tool results*, not the database, and its answer is checked for grounding
   before it is returned.

Conversation history is deliberately weak evidence. The model is not asked to
remember facts from earlier turns -- it is asked to call a tool. That is what
"the assistant should query internal tools rather than hallucinating from
conversation history" means in practice.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

import sqlalchemy as sa
from mybot_llm.base import LLMRequest, LLMUnavailable, SchemaViolation
from mybot_llm.router import ModelRouter
from mybot_schemas.db.types import new_uuid, utcnow
from mybot_schemas.enums import Classification, LLMPurpose, MemoryKind
from mybot_schemas.models import ChatMessage
from mybot_security.logging import get_logger
from mybot_security.untrusted import PromptContext
from sqlalchemy.orm import Session

from ..action_firewall.service import ActionFirewall
from ..brief.service import BriefService
from ..inbox.service import InboxService
from .tools import AgentTools, ToolResult

log = get_logger(__name__)

MAX_HISTORY_MESSAGES = 12


@dataclass
class ChatAnswer:
    text: str
    conversation_id: str
    citations: list[str] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    action_proposal_ids: list[str] = field(default_factory=list)
    #: True when the answer came from deterministic code with no model call.
    grounded_only: bool = True
    model_used: str | None = None
    #: Systems that could not be consulted, so the UI can caveat honestly.
    unavailable: list[str] = field(default_factory=list)
    structured: dict | None = None

    def as_dict(self) -> dict:
        return {
            "text": self.text,
            "conversation_id": self.conversation_id,
            "citations": self.citations,
            "tool_calls": self.tool_calls,
            "action_proposal_ids": self.action_proposal_ids,
            "grounded_only": self.grounded_only,
            "model_used": self.model_used,
            "unavailable": self.unavailable,
            "structured": self.structured,
        }


# ---------------------------------------------------------------------------
# Intent patterns
# ---------------------------------------------------------------------------

_WORRY = re.compile(
    r"(?i)\b(what do i need to (worry|know) about|what needs? (my )?attention|"
    r"what should i (worry|know) about|anything i (should|need to) know|"
    r"what did i forget|what am i forgetting)\b"
)
_BILLS = re.compile(r"(?i)\b(bills?|payments?|invoices?|due)\b.*\b(coming|upcoming|soon|due|next)\b|\b(what|which) bills?\b")
_EXPIRES = re.compile(r"(?i)\b(when does|when will|when is)\b.*\b(expire|expires|renew|renewal|due)\b")
_REMEMBER = re.compile(r"(?i)^\s*(remember|note|keep in mind|don'?t forget)\s+(that\s+)?(?P<content>.+)$")
_REMIND_RULE = re.compile(r"(?i)^\s*(remind me|always|from now on|going forward)\b.*")
_WEEK = re.compile(r"(?i)\b(what'?s? (happening|on|coming up)|my (schedule|week|day)|this week|today)\b")
_FIND_EMAIL = re.compile(r"(?i)\b(find|search|look for|show me)\b.*\b(email|message|mail)\b")

#: Preferences are phrased as "I prefer X"; distinguished from a plain fact so
#: the structured extractor runs.
_PREFERENCE = re.compile(r"(?i)\b(i (prefer|like|want|always|never)|my preference)\b")


class ChatService:
    def __init__(
        self,
        session: Session,
        owner_id: str,
        *,
        firewall: ActionFirewall,
        router: ModelRouter | None = None,
    ):
        self.session = session
        self.owner_id = owner_id
        self.firewall = firewall
        self.tools = AgentTools(session, owner_id, firewall)
        self.router = router or ModelRouter()
        self.brief = BriefService(session)
        self.inbox = InboxService(session)

    # ------------------------------------------------------------------

    def ask(
        self,
        question: str,
        *,
        conversation_id: str | None = None,
        coverage: dict | None = None,
    ) -> ChatAnswer:
        conversation_id = conversation_id or new_uuid()
        question = (question or "").strip()
        if not question:
            return ChatAnswer(text="Ask me anything about your life admin.", conversation_id=conversation_id)

        self._record(conversation_id, "user", question)

        answer = self._route(question, conversation_id, coverage or {})

        self._record(
            conversation_id,
            "assistant",
            answer.text,
            tool_calls=answer.tool_calls,
            citations=answer.citations,
            action_proposal_ids=answer.action_proposal_ids,
        )
        return answer

    # ------------------------------------------------------------------
    # Deterministic intents
    # ------------------------------------------------------------------

    def _route(self, question: str, conversation_id: str, coverage: dict) -> ChatAnswer:
        if _WORRY.search(question):
            return self._answer_worry(conversation_id, coverage)

        match = _REMEMBER.match(question)
        if match:
            return self._answer_remember(match.group("content"), conversation_id)
        if _REMIND_RULE.match(question):
            return self._answer_remember(question, conversation_id, as_rule=True)

        if _BILLS.search(question):
            return self._answer_bills(conversation_id)
        if _EXPIRES.search(question):
            return self._answer_expiry(question, conversation_id)
        if _WEEK.search(question):
            return self._answer_schedule(conversation_id)
        if _FIND_EMAIL.search(question):
            return self._answer_email_search(question, conversation_id)

        return self._answer_general(question, conversation_id, coverage)

    def _answer_worry(self, conversation_id: str, coverage: dict) -> ChatAnswer:
        report = self.brief.worry_report(self.owner_id, coverage=coverage)
        lines: list[str] = []
        citations: list[str] = []

        for group, items in report["groups"].items():
            lines.append(f"\n{group}")
            for item in items:
                lines.append(f"  • {item['explanation']}")
                citations.append(f"inbox_item:{item['id']}")
                citations.extend(item.get("source_ids", []))

        if not report["groups"]:
            text = report["closing"]
        else:
            text = "\n".join(lines).strip() + "\n\n" + report["closing"]

        return ChatAnswer(
            text=text,
            conversation_id=conversation_id,
            citations=list(dict.fromkeys(citations)),
            tool_calls=[{"tool": "worry_report", "deterministic": True}],
            grounded_only=True,
            unavailable=[k for k, v in coverage.items() if not v.get("ok", True)],
            structured=report,
        )

    def _answer_remember(
        self, content: str, conversation_id: str, *, as_rule: bool = False
    ) -> ChatAnswer:
        content = content.strip().rstrip(".")
        if as_rule:
            kind = MemoryKind.RULE
        elif _PREFERENCE.search(content):
            kind = MemoryKind.PREFERENCE
        else:
            kind = MemoryKind.FACT

        memory = self.tools.memory_write(content, kind=kind.value)
        detail = ""
        if memory.structured:
            pairs = ", ".join(f"{k} = {v}" for k, v in memory.structured.items())
            detail = f" I also recorded it as a setting I can act on ({pairs})."

        return ChatAnswer(
            text=f"Noted. I'll remember that {content}.{detail}",
            conversation_id=conversation_id,
            citations=[f"memory:{memory.id}"],
            tool_calls=[{"tool": "memory_write", "kind": kind.value}],
            grounded_only=True,
        )

    def _answer_bills(self, conversation_id: str) -> ChatAnswer:
        result = self.tools.obligations_list(within_days=45)
        money = [i for i in result.items if i.get("amount") or i.get("kind") in ("bill", "subscription_renewal", "utility")]
        rows = money or result.items

        if not rows:
            return ChatAnswer(
                text="Nothing is due in the next 45 days that I know about.",
                conversation_id=conversation_id,
                tool_calls=[result.as_dict()],
            )

        lines = []
        for item in rows[:10]:
            when = _friendly_date(item.get("due_at"))
            amount = f" — ${item['amount']:,.2f}" if item.get("amount") else ""
            lines.append(f"• {item['title']}{amount} ({when})")
            if item.get("confidence", 1.0) < 0.85:
                lines[-1] += f" [confidence {item['confidence']:.0%}]"

        return ChatAnswer(
            text="Coming up:\n" + "\n".join(lines),
            conversation_id=conversation_id,
            citations=result.citations,
            tool_calls=[result.as_dict()],
            grounded_only=True,
        )

    def _answer_expiry(self, question: str, conversation_id: str) -> ChatAnswer:
        """Answer "when does X expire?" from facts, documents and obligations.

        Searches all three and reports what it finds, with the source. If
        nothing matches, it says so rather than guessing a plausible date.
        """
        subject = _extract_subject(question)
        citations: list[str] = []
        # Keyed by (thing, kind-of-date, date) so the same deadline reported by
        # a fact, an obligation and a document collapses to one line instead of
        # three that look like three different dates.
        findings: dict[tuple[str, str, str], str] = {}

        def _add(thing: str, kind: str, raw_date, line: str) -> None:
            key = (thing.strip().lower(), kind, str(raw_date)[:10])
            findings.setdefault(key, line)

        entities = self.tools.lifegraph_find_entity(subject, limit=5)
        citations.extend(entities.citations)
        for entity in entities.items:
            facts = self.tools.lifegraph_get_facts(entity["id"])
            citations.extend(facts.citations)
            for fact in facts.items:
                if not any(k in fact["key"] for k in ("expir", "renew", "due")):
                    continue
                _add(
                    entity["name"],
                    fact["key"],
                    fact["value"],
                    f"{entity['name']}: {fact['key'].replace('_', ' ')} is "
                    f"{_friendly_date(str(fact['value']))} "
                    f"(source: {fact['source']}"
                    + (f", “{fact['evidence']}”" if fact.get("evidence") else "")
                    + ")",
                )

        obligations = self.tools.obligations_list(within_days=400)
        citations.extend(obligations.citations)
        for item in obligations.items:
            if subject and subject.lower() in item["title"].lower():
                _add(
                    item["title"].replace(" renewal", "").replace(" payment", ""),
                    "expiration_date",
                    item["due_at"],
                    f"{item['title']} is due {_friendly_date(item['due_at'])}"
                    + (f" (source: {item['source']})" if item.get("source") else ""),
                )

        documents = self.tools.document_list()
        citations.extend(documents.citations)
        for document in documents.items:
            blob = f"{document.get('document_type') or ''} {document['filename']}".lower()
            if not subject or subject.lower() not in blob:
                continue
            label = (document.get("document_type") or document["filename"]).replace("_", " ")
            for field_data in document.get("fields", []):
                if "expir" not in str(field_data.get("field", "")):
                    continue
                _add(
                    label,
                    "expiration_date",
                    field_data.get("value"),
                    f"{label.title()}: expires "
                    f"{_friendly_date(field_data.get('value'))} "
                    f"(from {document['filename']}, confidence "
                    f"{float(field_data.get('confidence', 0)):.0%})",
                )

        if not findings:
            return ChatAnswer(
                text=(
                    f"I don't have an expiry date on record for “{subject}”. "
                    "If you add the document or tell me the date, I'll track it."
                ),
                conversation_id=conversation_id,
                citations=list(dict.fromkeys(citations)),
                tool_calls=[entities.as_dict(), obligations.as_dict()],
            )

        return ChatAnswer(
            text="\n".join(f"• {line}" for line in findings.values()),
            conversation_id=conversation_id,
            citations=list(dict.fromkeys(citations)),
            tool_calls=[entities.as_dict(), obligations.as_dict(), documents.as_dict()],
            grounded_only=True,
        )

    def _answer_schedule(self, conversation_id: str) -> ChatAnswer:
        events = self.tools.calendar_list_events(days_ahead=7)
        if not events.items:
            return ChatAnswer(
                text="Nothing on your calendar for the next seven days.",
                conversation_id=conversation_id,
                tool_calls=[events.as_dict()],
            )
        lines = []
        for event in events.items:
            start = dt.datetime.fromisoformat(event["start"])
            when = start.strftime("%a %-d %b, %-I:%M %p")
            location = f" — {event['location']}" if event.get("location") else ""
            lines.append(f"• {when}: {event['title']}{location}")
        return ChatAnswer(
            text="This week:\n" + "\n".join(lines),
            conversation_id=conversation_id,
            citations=events.citations,
            tool_calls=[events.as_dict()],
            grounded_only=True,
        )

    def _answer_email_search(self, question: str, conversation_id: str) -> ChatAnswer:
        subject = _extract_subject(question)
        result = self.tools.email_search(query=subject, limit=10)
        if not result.items:
            return ChatAnswer(
                text=f"I couldn't find any message matching “{subject}”.",
                conversation_id=conversation_id,
                tool_calls=[result.as_dict()],
            )
        lines = []
        for message in result.items:
            received = dt.datetime.fromisoformat(message["received_at"]).strftime("%-d %b")
            flag = "  ⚠ contains instruction-shaped text" if message["injection_suspected"] else ""
            lines.append(f"• {message['from']} — “{message['subject']}” ({received}){flag}")
        return ChatAnswer(
            text="\n".join(lines),
            conversation_id=conversation_id,
            citations=result.citations,
            tool_calls=[result.as_dict()],
            grounded_only=True,
        )

    # ------------------------------------------------------------------
    # Model-assisted fallback
    # ------------------------------------------------------------------

    def _answer_general(self, question: str, conversation_id: str, coverage: dict) -> ChatAnswer:
        """Answer an open question from tool results.

        The model receives only what the tools returned. It never sees the
        database, never sees credentials, and cannot call anything. If it
        produces something the tool results do not support, the grounding check
        below downgrades the answer rather than shipping it.
        """
        gathered: list[ToolResult] = [
            self.tools.inbox_list(limit=10),
            self.tools.obligations_list(within_days=60),
            self.tools.calendar_list_events(days_ahead=14),
            self.tools.memory_search(limit_query(question)),
        ]
        citations = [c for result in gathered for c in result.citations]

        context = PromptContext(
            instructions=(
                "You are MyBot, a private assistant for one person. Answer only from the "
                "TOOL_RESULT blocks below. If they do not contain the answer, say you do not "
                "have it on record. Never invent a date, an amount, or an obligation. Be brief "
                "and concrete. You cannot take actions; you can only report and suggest."
            )
        )
        context.add_trusted(f"QUESTION: {question}")
        for result in gathered:
            context.add_trusted(f"TOOL_RESULT {result.name}: {_json(result.items)}")

        request = LLMRequest(
            purpose=LLMPurpose.CHAT,
            context=context,
            max_classification=Classification.PERSONAL,
            max_tokens=600,
        )

        try:
            response, run = self.router.run(self.session, self.owner_id, request)
            text = response.text.strip()
            model_used = f"{run.provider}:{run.model}"
        except (LLMUnavailable, SchemaViolation) as exc:
            log.warning("chat.model_unavailable", error=type(exc).__name__)
            return self._fallback_answer(gathered, conversation_id, citations)
        except Exception:  # noqa: BLE001
            log.exception("chat.model_error")
            return self._fallback_answer(gathered, conversation_id, citations)

        if not _is_grounded(text, gathered):
            log.warning("chat.ungrounded_answer_suppressed")
            return self._fallback_answer(
                gathered,
                conversation_id,
                citations,
                note=(
                    "I could not verify an answer against your records, so here is what I "
                    "actually have:"
                ),
            )

        return ChatAnswer(
            text=text,
            conversation_id=conversation_id,
            citations=list(dict.fromkeys(citations)),
            tool_calls=[r.as_dict() for r in gathered],
            grounded_only=False,
            model_used=model_used,
            unavailable=[k for k, v in coverage.items() if not v.get("ok", True)],
        )

    def _fallback_answer(
        self,
        gathered: list[ToolResult],
        conversation_id: str,
        citations: list[str],
        note: str | None = None,
    ) -> ChatAnswer:
        """Deterministic answer used when no model is available or trusted.

        Not an error page: it is a real, if plainer, answer built from the same
        tool results. The product keeps working with no provider configured.
        """
        lines: list[str] = []
        for result in gathered:
            if not result.items:
                continue
            label = result.name.replace("_", " ")
            lines.append(f"\n{label}:")
            for item in result.items[:5]:
                headline = item.get("title") or item.get("content") or item.get("name") or ""
                detail = item.get("explanation") or item.get("due_at") or ""
                lines.append(f"  • {headline}{f' — {detail}' if detail else ''}")

        body = "\n".join(lines).strip()
        if not body:
            body = "I don't have anything on record that answers that."
        return ChatAnswer(
            text=f"{note}\n{body}" if note else body,
            conversation_id=conversation_id,
            citations=list(dict.fromkeys(citations)),
            tool_calls=[r.as_dict() for r in gathered],
            grounded_only=True,
        )

    # ------------------------------------------------------------------

    def history(self, conversation_id: str, limit: int = MAX_HISTORY_MESSAGES) -> list[ChatMessage]:
        return list(
            self.session.execute(
                sa.select(ChatMessage)
                .where(
                    ChatMessage.owner_id == self.owner_id,
                    ChatMessage.conversation_id == conversation_id,
                )
                .order_by(ChatMessage.created_at.desc())
                .limit(limit)
            ).scalars()
        )[::-1]

    def _record(
        self,
        conversation_id: str,
        role: str,
        content: str,
        *,
        tool_calls: list | None = None,
        citations: list | None = None,
        action_proposal_ids: list | None = None,
    ) -> ChatMessage:
        message = ChatMessage(
            owner_id=self.owner_id,
            conversation_id=conversation_id,
            role=role,
            content=content,
            tool_calls=tool_calls or [],
            citations=citations or [],
            action_proposal_ids=action_proposal_ids or [],
        )
        self.session.add(message)
        self.session.flush()
        return message


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _is_grounded(text: str, gathered: list[ToolResult]) -> bool:
    """Cheap grounding check on model output.

    Looks for the two kinds of specific claim that do real damage when
    fabricated -- money amounts and calendar dates -- and rejects the answer if
    one appears that no tool result supports.

    It is not a proof of correctness, and it is deliberately tuned to avoid
    *false* rejections: amounts are compared numerically (so ``$148.20``
    matches a stored ``148.2``), and dates are compared as dates. Suppressing a
    correct answer is its own kind of failure.
    """
    corpus = _json([item for result in gathered for item in result.items])

    supported_amounts = {
        round(float(match), 2) for match in re.findall(r"-?\d+(?:\.\d+)?", corpus)
    }
    for raw in re.findall(r"[$£€]\s?([0-9][0-9,]*(?:\.[0-9]{1,2})?)", text):
        try:
            claimed = round(float(raw.replace(",", "")), 2)
        except ValueError:  # pragma: no cover - regex guarantees a number
            continue
        if claimed not in supported_amounts:
            return False

    supported_dates = set(re.findall(r"\d{4}-\d{2}-\d{2}", corpus))
    for date_str in re.findall(r"\b(\d{4}-\d{2}-\d{2})\b", text):
        if date_str not in supported_dates:
            return False

    return True


def _json(payload) -> str:
    import json

    return json.dumps(payload, default=str, ensure_ascii=False)


def limit_query(question: str) -> str:
    words = [w for w in re.findall(r"[a-zA-Z]{4,}", question)]
    return words[0] if words else ""


def _extract_subject(question: str) -> str:
    """Pull the topic out of a question.

    Blunt but predictable: strip interrogatives and possessives and keep the
    nouns. A wrong guess produces "I don't have that on record", which is a
    safe failure.
    """
    cleaned = re.sub(
        r"(?i)\b(when|does|do|is|are|will|my|the|a|an|expire|expires|renew|renewal|due|find|search|"
        r"look|for|show|me|email|message|mail|from|about|what|which)\b",
        " ",
        question,
    )
    cleaned = re.sub(r"[^\w\s]", " ", cleaned)
    tokens = [t for t in cleaned.split() if len(t) > 2]
    return " ".join(tokens[:4]).strip()


def _friendly_date(value) -> str:
    if not value:
        return "no date on record"
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    days = (parsed - utcnow()).days
    stamp = parsed.strftime("%B %-d, %Y")
    if days < 0:
        return f"{stamp} — {abs(days)} day{'s' if abs(days) != 1 else ''} ago"
    if days == 0:
        return f"{stamp} — today"
    if days == 1:
        return f"{stamp} — tomorrow"
    return f"{stamp} — in {days} days"


__all__ = ["ChatAnswer", "ChatService"]
