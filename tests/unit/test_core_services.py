"""Unit tests for the domain services."""

from __future__ import annotations

import datetime as dt

import pytest
from mybot_schemas.enums import (
    Classification,
    EntityType,
    InboxCategory,
    MemoryKind,
    Recurrence,
    SourceKind,
    Urgency,
)
from mybot_services.inbox.priority import PriorityInputs, score
from mybot_services.inbox.service import CardDraft
from mybot_services.life_graph.service import normalize_name
from mybot_services.proactive.intel import (
    classify_email,
    extract_amounts,
    extract_dates,
    find_conflicts,
    find_free_slot,
)

# ---------------------------------------------------------------------------
# Life Graph
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        # "&" becomes "and", which is then dropped as a stop word -- so the
        # acronym check below can match "pseg" against "public service
        # electric gas".
        ("PSE&G", "pse g"),
        ("PSEG", "pseg"),
        ("Public Service Electric & Gas Company", "public service electric gas"),
        ("Acme, Inc.", "acme"),
        ("Café München", "cafe munchen"),
    ],
)
def test_normalize_name(raw, expected):
    assert normalize_name(raw) == expected


def test_entity_resolution_merges_confident_matches(services, as_alice):
    services.graph.create_entity(
        as_alice, entity_type=EntityType.ORGANIZATION, name="Netflix"
    )
    entity, created = services.graph.resolve_entity(
        as_alice, entity_type=EntityType.ORGANIZATION, name="netflix"
    )
    assert created is False
    assert entity.name == "Netflix"


def test_entity_resolution_does_not_merge_aggressively(services, as_alice):
    """Two different people who share a surname must stay two people."""
    services.graph.create_entity(as_alice, entity_type=EntityType.PERSON, name="John Petrov")
    entity, created = services.graph.resolve_entity(
        as_alice, entity_type=EntityType.PERSON, name="Sarah Petrov"
    )
    assert created is True
    assert entity.name == "Sarah Petrov"
    # Two separate rows, and the original is untouched.
    others = services.graph.list_entities(as_alice, entity_type=EntityType.PERSON.value)
    assert {e.name for e in others} == {"John Petrov", "Sarah Petrov"}


def test_acronym_resolution(services, as_alice):
    services.graph.create_entity(
        as_alice,
        entity_type=EntityType.ORGANIZATION,
        name="Public Service Electric and Gas",
        aliases=["PSE&G"],
    )
    entity, created = services.graph.resolve_entity(
        as_alice, entity_type=EntityType.ORGANIZATION, name="PSE&G"
    )
    assert created is False


def test_facts_supersede_rather_than_overwrite(services, as_alice):
    entity = services.graph.create_entity(
        as_alice, entity_type=EntityType.VEHICLE, name="Car"
    )
    services.graph.assert_fact(
        as_alice,
        entity.id,
        "registration_expires",
        "2026-10-14",
        source_kind=SourceKind.DOCUMENT,
        evidence="NJ MVC notice",
        confidence=0.9,
    )
    services.graph.assert_fact(
        as_alice,
        entity.id,
        "registration_expires",
        "2026-10-18",
        source_kind=SourceKind.USER_CORRECTION,
        confidence=1.0,
    )

    current = services.graph.current_fact(as_alice, entity.id, "registration_expires")
    assert current.value["value"] == "2026-10-18"
    assert current.source_kind == SourceKind.USER_CORRECTION.value

    history = services.graph.fact_history(as_alice, entity.id, "registration_expires")
    assert len(history) == 2
    assert history[0].superseded_by_id == current.id
    assert history[0].value["value"] == "2026-10-14"


def test_weak_inference_cannot_override_a_user_statement(services, as_alice):
    """The person is the authority on their own life."""
    entity = services.graph.create_entity(
        as_alice, entity_type=EntityType.PERSON, name="Sam"
    )
    services.graph.assert_fact(
        as_alice, entity.id, "birthday", "1990-04-02",
        source_kind=SourceKind.USER_STATEMENT, confidence=1.0,
    )
    services.graph.assert_fact(
        as_alice, entity.id, "birthday", "1991-01-01",
        source_kind=SourceKind.INFERENCE, confidence=0.7, inferred=True,
    )
    current = services.graph.current_fact(as_alice, entity.id, "birthday")
    assert current.value["value"] == "1990-04-02"


def test_merge_entities_moves_facts_and_relationships(services, as_alice):
    keep = services.graph.create_entity(
        as_alice, entity_type=EntityType.ORGANIZATION, name="PSE&G"
    )
    merge = services.graph.create_entity(
        as_alice, entity_type=EntityType.ORGANIZATION, name="Public Service Electric"
    )
    services.graph.assert_fact(as_alice, merge.id, "phone", "555-0000")

    result = services.graph.merge_entities(as_alice, keep.id, merge.id)
    assert services.graph.current_fact(as_alice, result.id, "phone") is not None
    assert "Public Service Electric" in result.aliases
    assert services.graph.get_entity(as_alice, merge.id).merged_into_id == keep.id


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------


def test_preferences_are_structured_for_machine_use(services, as_alice):
    services.memory.remember(
        as_alice, "I prefer afternoon appointments", kind=MemoryKind.PREFERENCE
    )
    assert services.memory.preferences(as_alice)["appointment_time_of_day"] == "afternoon"


def test_transient_kinds_are_refused_as_durable_memory(services, as_alice):
    for kind in (MemoryKind.WORKING, MemoryKind.CONVERSATION):
        with pytest.raises(ValueError):
            services.memory.remember(as_alice, "chatter", kind=kind)


def test_memory_correction_supersedes_and_keeps_history(services, as_alice):
    original = services.memory.remember(
        as_alice, "My registration expires October 14", kind=MemoryKind.FACT
    )
    corrected = services.memory.correct(
        as_alice, original.id, "My registration expires October 18"
    )

    assert corrected.source_kind == SourceKind.USER_CORRECTION.value
    assert services.memory.get(as_alice, original.id).superseded_by_id == corrected.id
    # The superseded one is out of the way but not gone.
    active = services.memory.search(as_alice)
    assert all(m.id != original.id for m in active)


def test_forget_removes_content_but_records_the_deletion(services, as_alice):
    memory = services.memory.remember(as_alice, "Something private", kind=MemoryKind.FACT)
    assert services.memory.forget(as_alice, memory.id) is True
    assert services.memory.get(as_alice, memory.id) is None

    events = services.audit.list_events(as_alice, event_type="memory.deleted")
    assert len(events) == 1
    # The audit records that a deletion happened -- not what was deleted, and
    # not the subject line, which is derived from the content.
    recorded = str(events[0].details) + str(events[0].reason)
    assert "Something private" not in recorded
    assert "private" not in recorded.lower()
    assert events[0].details["content_removed"] is True
    assert events[0].resource_id == memory.id


# ---------------------------------------------------------------------------
# Obligations
# ---------------------------------------------------------------------------


def test_completing_a_recurring_obligation_schedules_the_next(services, as_alice, now):
    obligation = services.obligations.create(
        as_alice,
        title="Electric bill",
        due_at=now + dt.timedelta(days=2),
        recurrence=Recurrence.MONTHLY,
        amount=148.20,
    )
    services.obligations.complete(as_alice, obligation.id)
    remaining = [o for o in services.obligations.open_obligations(as_alice)]
    assert len(remaining) == 1
    assert remaining[0].id != obligation.id
    assert remaining[0].due_at > obligation.due_at


def test_overdue_marking(services, as_alice, now):
    services.obligations.create(
        as_alice, title="Late thing", due_at=now - dt.timedelta(days=1)
    )
    assert services.obligations.mark_overdue(as_alice, now=now) == 1
    assert services.obligations.open_obligations(as_alice)[0].status == "overdue"


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------


def test_priority_is_deterministic():
    inputs = PriorityInputs(
        category=InboxCategory.MONEY.value, hours_until_due=48, financial_impact=200
    )
    results = [score(inputs).score for _ in range(50)]
    assert len(set(results)) == 1


def test_overdue_beats_distant():
    overdue = score(PriorityInputs(category=InboxCategory.URGENT.value, hours_until_due=-24))
    distant = score(PriorityInputs(category=InboxCategory.URGENT.value, hours_until_due=24 * 60))
    assert overdue.score > distant.score
    assert overdue.urgency == Urgency.CRITICAL


def test_larger_amounts_score_higher():
    small = score(PriorityInputs(category=InboxCategory.MONEY.value, financial_impact=15))
    large = score(PriorityInputs(category=InboxCategory.MONEY.value, financial_impact=5000))
    assert large.score > small.score


def test_low_confidence_is_capped():
    """A speculative "urgent" item cannot outshout a well-evidenced one."""
    shaky = score(
        PriorityInputs(
            category=InboxCategory.URGENT.value,
            hours_until_due=1,
            financial_impact=10_000,
            confidence=0.4,
        )
    )
    assert shaky.score <= 55.0
    assert "low_confidence_cap" in shaky.breakdown


def test_priority_breakdown_explains_the_score():
    result = score(
        PriorityInputs(
            category=InboxCategory.MONEY.value, hours_until_due=12, financial_impact=600
        )
    )
    assert set(result.breakdown) >= {"deadline", "financial", "category", "importance", "confidence"}
    assert abs(sum(v for k, v in result.breakdown.items()) - result.score) < 1.0


# ---------------------------------------------------------------------------
# Calendar & email intelligence
# ---------------------------------------------------------------------------


class _Event:
    def __init__(self, id, title, start, end, attendees=(), all_day=False, cancelled=False,
                 location=None, description=None):
        self.id = id
        self.title = title
        self.start_at = start
        self.end_at = end
        self.attendees = list(attendees)
        self.all_day = all_day
        self.cancelled = cancelled
        self.location = location
        self.description = description


def test_conflict_detection(now):
    base = now.replace(hour=14, minute=0, second=0, microsecond=0)
    events = [
        _Event("a", "Dentist", base, base + dt.timedelta(hours=1)),
        _Event("b", "Investor meeting", base + dt.timedelta(minutes=30),
               base + dt.timedelta(minutes=90), attendees=["dana@example.com"]),
        _Event("c", "Later", base + dt.timedelta(hours=3), base + dt.timedelta(hours=4)),
    ]
    conflicts = find_conflicts(events)
    assert len(conflicts) == 1
    assert conflicts[0].overlap_minutes == 30
    # The solo appointment is the one suggested for moving, not the meeting.
    assert conflicts[0].suggested_move_id == "a"


def test_all_day_events_do_not_create_conflicts(now):
    events = [
        _Event("v", "Vacation", now, now + dt.timedelta(days=5), all_day=True),
        _Event("m", "Meeting", now + dt.timedelta(hours=1), now + dt.timedelta(hours=2)),
    ]
    assert find_conflicts(events) == []


def test_free_slot_respects_afternoon_preference(now):
    day = (now + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    slot = find_free_slot(
        [],
        duration_minutes=60,
        search_from=day,
        search_until=day + dt.timedelta(days=2),
        prefer_afternoon=True,
    )
    assert slot is not None
    assert slot.hour >= 13


def test_free_slot_avoids_busy_times(now):
    day = (now + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    busy = [_Event("x", "Blocked", day.replace(hour=13), day.replace(hour=16))]
    slot = find_free_slot(
        busy,
        duration_minutes=60,
        search_from=day,
        search_until=day + dt.timedelta(days=1),
        prefer_afternoon=True,
    )
    assert slot is not None
    assert not (day.replace(hour=13) <= slot < day.replace(hour=16))


@pytest.mark.parametrize(
    "subject,body,expected",
    [
        ("Your bill is ready", "Amount Due: $148.20\nDue Date: 2026-09-01", "deadline"),
        ("40% off today!", "Flash sale. Unsubscribe here.", "marketing"),
        ("Order confirmation", "Your receipt for order 123", "transactional"),
        ("Contract review", "Could you review clause 7 and let me know?", "actionable"),
    ],
)
def test_email_classification(subject, body, expected):
    analysis = classify_email(
        subject=subject, body=body, from_address="someone@example.com",
        to_addresses=["me@example.com"],
    )
    assert analysis.label == expected
    assert analysis.signals


def test_email_extraction_of_dates_and_amounts():
    analysis = classify_email(
        subject="Your bill is ready",
        body="Amount Due: $1,234.56\nDue Date: 2026-09-01",
        from_address="billing@example.com",
        to_addresses=["me@example.com"],
    )
    assert 1234.56 in analysis.amounts
    assert any(d.date().isoformat() == "2026-09-01" for d in analysis.dates)


def test_ambiguous_dates_are_not_invented():
    """"next Tuesday" must not become a concrete deadline."""
    assert extract_dates("Let's meet next Tuesday or maybe the week after") == []


def test_amount_extraction():
    assert extract_amounts("Total: $79.00 and a fee of $4.50") == [79.0, 4.5]


# ---------------------------------------------------------------------------
# Inbox & brief
# ---------------------------------------------------------------------------


def test_inbox_upsert_is_idempotent(services, as_alice, now):
    draft = CardDraft(
        dedupe_key="test:1",
        rule_id="test.rule",
        category=InboxCategory.URGENT,
        title="A thing",
        explanation="It needs you.",
        due_at=now + dt.timedelta(days=1),
    )
    first = services.inbox.upsert(as_alice, draft, now=now)
    second = services.inbox.upsert(as_alice, draft, now=now)
    assert first.id == second.id
    assert len(services.inbox.list_items(as_alice)) == 1


def test_inbox_upsert_preserves_user_state_but_refreshes_content(services, as_alice, now):
    draft = CardDraft(
        dedupe_key="test:2",
        rule_id="test.rule",
        category=InboxCategory.MONEY,
        title="Bill",
        explanation="Due in 5 days.",
        due_at=now + dt.timedelta(days=5),
    )
    item = services.inbox.upsert(as_alice, draft, now=now)
    original_score = item.priority_score  # upsert mutates the same row
    services.inbox.snooze(as_alice, item.id, now + dt.timedelta(days=1))

    draft.explanation = "Due tomorrow."
    draft.due_at = now + dt.timedelta(days=1)
    updated = services.inbox.upsert(as_alice, draft, now=now)
    assert updated.explanation == "Due tomorrow."
    assert updated.state == "snoozed"
    assert updated.priority_score > original_score


def test_brief_is_generated_from_structured_data(services, as_alice, now):
    services.obligations.create(
        as_alice,
        title="Car registration renewal",
        due_at=now + dt.timedelta(days=4),
        kind="registration_renewal",
        consequence="Driving with an expired registration risks a citation.",
        source_kind=SourceKind.DOCUMENT,
        source_detail="NJ MVC notice",
    )
    services.proactive.scan(as_alice, now=now)
    brief = services.brief.generate(as_alice, now=now, coverage={"calendar": {"ok": True}})

    assert "Good" in brief.greeting
    assert brief.needs_you
    # Every line traces to a record.
    for line in brief.needs_you:
        assert line.source_kind == "inbox_item"
        assert line.source_id
        assert line.detail["reason"]


def test_brief_is_honest_when_a_system_could_not_be_checked(services, as_alice, now):
    brief = services.brief.generate(
        as_alice,
        now=now,
        coverage={"calendar": {"ok": False, "reason": "not connected"}, "email": {"ok": True}},
    )
    assert "could not check" in brief.closing
    assert "calendar" in brief.closing


def test_brief_says_nothing_else_only_when_everything_was_checked(services, as_alice, now):
    brief = services.brief.generate(
        as_alice, now=now, coverage={"calendar": {"ok": True}, "email": {"ok": True}}
    )
    assert brief.closing == "Nothing else requires your attention."


def test_worry_report_groups_and_closes_honestly(services, as_alice, now):
    services.obligations.create(
        as_alice, title="Electric bill", due_at=now + dt.timedelta(days=2), amount=148.20
    )
    services.proactive.scan(as_alice, now=now)

    report = services.brief.worry_report(as_alice, coverage={"email": {"ok": True}})
    assert report["total"] >= 1
    assert report["checked_everything"] is True

    degraded = services.brief.worry_report(
        as_alice, coverage={"email": {"ok": False, "reason": "not connected"}}
    )
    assert degraded["checked_everything"] is False
    assert "could not check" in degraded["closing"]


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


def test_document_extraction_records_value_source_and_confidence(services, as_alice, vault, db):
    from mybot_services.document_ingestion.service import DocumentIngestionService

    ingestion = DocumentIngestionService(db, vault, audit=services.audit, graph=services.graph)
    result = ingestion.ingest(
        as_alice,
        filename="passport.txt",
        content=b"UNITED STATES PASSPORT\nPlace of Birth: NJ\nPassport Number: X12345678\n"
        b"Expiration Date: 2027-05-18\n",
        mime_type="text/plain",
    )

    assert result.document.document_type == "passport"
    assert result.document.classification == Classification.HIGHLY_SENSITIVE.value

    expiry = next(f for f in result.fields if f.field == "expiration_date")
    assert expiry.value == "2027-05-18"
    assert expiry.confidence > 0.9
    assert "2027-05-18" in expiry.evidence

    # The passport number is stored masked, never in the clear.
    number = next(f for f in result.fields if f.field == "passport_number")
    assert number.value.endswith("5678")
    assert "X12345678" not in number.value


def test_document_contents_are_encrypted_at_rest(services, as_alice, vault, db):
    from mybot_services.document_ingestion.service import DocumentIngestionService

    ingestion = DocumentIngestionService(db, vault, audit=services.audit, graph=services.graph)
    secret = b"Passport Number: X12345678\nExpiration Date: 2027-05-18\n"
    result = ingestion.ingest(
        as_alice, filename="passport.txt", content=secret, mime_type="text/plain"
    )

    path = ingestion.settings.data_dir / result.document.storage_path
    raw = path.read_bytes()
    assert b"X12345678" not in raw
    assert ingestion.read_content(as_alice, result.document) == secret


def test_unreadable_document_says_so_rather_than_failing_silently(services, as_alice, vault, db):
    from mybot_services.document_ingestion.service import DocumentIngestionService

    ingestion = DocumentIngestionService(db, vault, audit=services.audit, graph=services.graph)
    result = ingestion.ingest(
        as_alice, filename="scan.png", content=b"\x89PNG\r\n\x1a\n fake", mime_type="image/png"
    )
    assert result.document.extraction_status == "unsupported"
    assert "OCR is not available" in (result.document.extraction_error or "")
    assert result.fields == []


def test_low_confidence_extraction_does_not_create_an_obligation(services, as_alice, vault, db):
    """Only a confidently-read future date becomes a deadline."""
    from mybot_services.document_ingestion.service import DocumentIngestionService

    ingestion = DocumentIngestionService(db, vault, audit=services.audit, graph=services.graph)
    result = ingestion.ingest(
        as_alice,
        filename="notes.txt",
        content=b"Some notes with a stray date 2027-01-01 and no labels at all.",
        mime_type="text/plain",
    )
    assert result.obligations_created == []
