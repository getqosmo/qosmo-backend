"""The egress ledger.

The claim this backs is the sharpest one MyBot makes, so the tests are about
the ways a privacy ledger normally lies rather than about whether it can count:

* it must record failed calls — a request that timed out still left;
* it must never conflate "we have no record" with "nothing happened";
* "nothing left this machine" must be false while any row is unaccounted for;
* it must not become a second copy of the prompts it is reporting on;
* it must be per-owner, like everything else.
"""

from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa
from mybot_llm.base import LLMProvider, LLMRequest, LLMResponse, LLMUnavailable
from mybot_llm.router import ModelRouter
from mybot_schemas.enums import Classification, LLMPurpose
from mybot_schemas.models import LLMRun
from mybot_security.untrusted import PromptContext
from mybot_services.egress import EgressService


class Cloud(LLMProvider):
    name = "cloud"
    local = False

    def available(self) -> bool:
        return True

    def model_id(self) -> str:
        return "cloud-1"

    def destination(self) -> str:
        return "api.example.com"

    def complete(self, request):
        return LLMResponse(text="ok", provider=self.name, model="cloud-1", prompt_tokens=42)


class Down(Cloud):
    name = "cloud-down"

    def complete(self, request):
        raise LLMUnavailable("timed out")


class Local(LLMProvider):
    name = "on-device"
    local = True

    def available(self) -> bool:
        return True

    def model_id(self) -> str:
        return "local-1"

    def complete(self, request):
        return LLMResponse(text="ok", provider=self.name, model="local-1")


@pytest.fixture
def egress(db):
    return EgressService(db)


def _legacy_row(db, owner_id: str) -> str:
    """A row as it exists after the migration but before the router stamped it.

    Written then NULLed at SQL level, because that is genuinely what an
    upgraded database holds -- the ORM default deliberately makes it impossible
    to create an unknown row going forward.
    """
    row = LLMRun(owner_id=owner_id, provider="legacy", model="?", purpose="chat")
    db.add(row)
    db.flush()
    db.execute(
        sa.update(LLMRun).where(LLMRun.id == row.id).values(left_machine=None, destination=None)
    )
    db.expire_all()
    return row.id


def _request(purpose=LLMPurpose.CHAT, classification=Classification.PERSONAL):
    return LLMRequest(
        purpose=purpose,
        context=PromptContext(instructions="test"),
        max_classification=classification,
    )


def _route(provider, monkeypatch):
    monkeypatch.setenv("MYBOT_LLM_DEFAULT_PROVIDER", provider.name)
    from mybot_schemas.config import reset_settings_cache

    reset_settings_cache()
    return ModelRouter(providers={provider.name: provider})


# ---------------------------------------------------------------------------


def test_a_call_that_left_is_recorded_with_its_destination(db, alice, as_alice, monkeypatch):
    router = _route(Cloud(), monkeypatch)
    try:
        router.run(db, alice.id, _request())
    finally:
        from mybot_schemas.config import reset_settings_cache

        reset_settings_cache()

    row = db.execute(sa.select(LLMRun)).scalar_one()
    assert row.left_machine is True
    assert row.destination == "api.example.com"


def test_a_local_call_is_recorded_as_having_stayed(db, alice, as_alice, monkeypatch):
    router = _route(Local(), monkeypatch)
    try:
        router.run(db, alice.id, _request())
    finally:
        from mybot_schemas.config import reset_settings_cache

        reset_settings_cache()

    row = db.execute(sa.select(LLMRun)).scalar_one()
    assert row.left_machine is False
    assert row.destination is None


def test_a_failed_call_still_counts_as_egress(db, alice, egress, as_alice, monkeypatch):
    """The most common way a privacy ledger lies.

    A request that timed out still left the machine. A ledger that records only
    successes is a marketing surface.
    """
    router = _route(Down(), monkeypatch)
    try:
        with pytest.raises(LLMUnavailable):
            router.run(db, alice.id, _request())
    finally:
        from mybot_schemas.config import reset_settings_cache

        reset_settings_cache()

    row = db.execute(sa.select(LLMRun)).scalar_one()
    assert row.left_machine is True
    assert row.status == "unavailable"

    ledger = egress.ledger(alice.id)
    assert ledger["left_machine"] == 1
    assert ledger["nothing_left"] is False
    assert ledger["events"][0]["outcome"] == "could not be reached"


# ---------------------------------------------------------------------------
# "No record" is not "nothing happened"
# ---------------------------------------------------------------------------


def test_rows_predating_the_ledger_are_unknown_not_zero(db, alice, egress, as_alice):
    """The honesty property the whole design turns on.

    Backfilling old rows with False would make the ledger assert that nothing
    left during a period it has no record of.
    """
    _legacy_row(db, alice.id)

    ledger = egress.ledger(alice.id)
    assert ledger["unknown"] == 1
    assert ledger["left_machine"] == 0
    assert ledger["stayed_local"] == 0, "an unknown row must not be counted as local"


def test_nothing_left_is_false_while_anything_is_unaccounted_for(db, alice, egress, as_alice):
    _legacy_row(db, alice.id)

    ledger = egress.ledger(alice.id)
    assert ledger["nothing_left"] is False
    assert "cannot be accounted for" in egress.summary(alice.id)["headline"]


def test_nothing_left_is_true_only_when_everything_is_accounted_for(
    db, alice, egress, as_alice, monkeypatch
):
    router = _route(Local(), monkeypatch)
    try:
        for _ in range(3):
            router.run(db, alice.id, _request())
    finally:
        from mybot_schemas.config import reset_settings_cache

        reset_settings_cache()

    ledger = egress.ledger(alice.id)
    assert ledger["nothing_left"] is True
    assert ledger["stayed_local"] == 3
    assert ledger["unknown"] == 0
    assert "Nothing has left this machine" in egress.summary(alice.id)["headline"]


def test_no_activity_is_not_reported_as_nothing_leaving(db, alice, egress, as_alice):
    """"MyBot has not needed a model" and "nothing left" are different claims."""
    headline = egress.summary(alice.id)["headline"]
    assert "has not needed a model" in headline


# ---------------------------------------------------------------------------
# The ledger is not a second copy of the data
# ---------------------------------------------------------------------------


def test_the_ledger_stores_no_prompt_or_reply(db, alice, egress, as_alice, monkeypatch):
    """A privacy surface that logs the prompts it reports on has made things
    worse, not better."""
    secret = "Dr Sandhu root canal $1,480 outstanding"

    class Nosy(Cloud):
        def complete(self, request):
            return LLMResponse(text=secret, provider=self.name, model="cloud-1")

    router = _route(Nosy(), monkeypatch)
    context = PromptContext(instructions="test")
    context.add_trusted(secret)
    try:
        router.run(
            db,
            alice.id,
            LLMRequest(purpose=LLMPurpose.CHAT, context=context),
        )
    finally:
        from mybot_schemas.config import reset_settings_cache

        reset_settings_cache()

    import json

    blob = json.dumps(egress.ledger(alice.id))
    assert secret not in blob
    assert "Sandhu" not in blob
    assert "1,480" not in blob

    row = db.execute(sa.select(LLMRun)).scalar_one()
    assert secret not in json.dumps(
        {c.name: str(getattr(row, c.name)) for c in row.__table__.columns}
    )


def test_events_are_described_in_plain_language(db, alice, egress, as_alice, monkeypatch):
    """A ledger you need the source code to read is not transparency."""
    router = _route(Cloud(), monkeypatch)
    try:
        router.run(db, alice.id, _request(LLMPurpose.EXTRACTION, Classification.PERSONAL))
    finally:
        from mybot_schemas.config import reset_settings_cache

        reset_settings_cache()

    event = egress.ledger(alice.id)["events"][0]
    assert event["what"] == "Reading details out of a document"
    assert event["sent"] == "personal details"
    assert event["destination"] == "api.example.com"


# ---------------------------------------------------------------------------
# Worst case, and isolation
# ---------------------------------------------------------------------------


def test_highest_ever_sent_reports_the_worst_case_not_the_average(
    db, alice, egress, as_alice
):
    for level in (Classification.PUBLIC, Classification.SENSITIVE, Classification.NORMAL):
        db.add(
            LLMRun(
                owner_id=alice.id,
                provider="cloud",
                model="c",
                purpose="chat",
                left_machine=True,
                max_classification_sent=level.value,
            )
        )
    db.flush()

    assert egress.highest_classification_ever_sent(alice.id) == "SENSITIVE"


def test_local_calls_do_not_count_toward_the_worst_case(db, alice, egress, as_alice):
    db.add(
        LLMRun(
            owner_id=alice.id,
            provider="local",
            model="l",
            purpose="chat",
            left_machine=False,
            max_classification_sent=Classification.HIGHLY_SENSITIVE.value,
        )
    )
    db.flush()

    assert egress.highest_classification_ever_sent(alice.id) is None


def test_the_ledger_is_owner_scoped(db, alice, bob, as_alice):
    db.add(
        LLMRun(owner_id=alice.id, provider="cloud", model="c", purpose="chat", left_machine=True)
    )
    db.flush()

    assert EgressService(db).ledger(alice.id)["left_machine"] == 1
    assert EgressService(db).ledger(bob.id)["left_machine"] == 0


def test_the_window_is_respected(db, alice, egress, as_alice):
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=90)
    row = LLMRun(
        owner_id=alice.id, provider="cloud", model="c", purpose="chat", left_machine=True
    )
    db.add(row)
    db.flush()
    row.created_at = old
    db.flush()

    assert egress.ledger(alice.id, days=30)["left_machine"] == 0
    assert egress.ledger(alice.id, days=365)["left_machine"] == 1


# ---------------------------------------------------------------------------
# Sovereign mode is checkable, not just claimed
# ---------------------------------------------------------------------------


def test_sovereign_mode_produces_a_provably_empty_ledger(
    db, alice, egress, as_alice, monkeypatch
):
    """The demo no competitor can run.

    Not a claim in a settings screen -- a count, from the same table every
    other number comes from.
    """
    monkeypatch.setenv("MYBOT_SOVEREIGN", "true")
    monkeypatch.setenv("MYBOT_LLM_DEFAULT_PROVIDER", "cloud")
    from mybot_schemas.config import reset_settings_cache

    reset_settings_cache()
    try:
        router = ModelRouter(providers={"cloud": Cloud()})
        for _ in range(5):
            router.run(db, alice.id, _request())
    finally:
        reset_settings_cache()

    ledger = egress.ledger(alice.id)
    assert ledger["left_machine"] == 0
    assert ledger["stayed_local"] == 5
    assert ledger["nothing_left"] is True
    assert ledger["destinations"] == []


def test_the_api_exposes_the_ledger(api, registered):
    account = registered()
    body = api.get("/api/v1/egress", headers=account["headers"]).json()

    assert body["left_machine"] == 0
    assert "events" in body
    assert "note" in body

    summary = api.get("/api/v1/egress/summary", headers=account["headers"]).json()
    assert "headline" in summary
    assert summary["highest_ever_sent"] is None


def test_a_new_row_can_never_be_unknown(db, alice, as_alice):
    """Unknown exists only for history.

    The column default deliberately coerces an omitted or None value to False,
    so a code path that forgets to stamp egress produces a wrong-but-visible
    row rather than silently widening the "we don't know" bucket over time.
    """
    row = LLMRun(owner_id=alice.id, provider="x", model="y", purpose="chat", left_machine=None)
    db.add(row)
    db.flush()

    assert row.left_machine is False


# ---------------------------------------------------------------------------
# Connector syncs are egress too
#
# The hole this closes: the ledger is the sharpest claim MyBot makes, and it
# previously counted only model calls. A sync to Gmail sends the owner's
# identity and a query outward, so a ledger reading "nothing left" while a
# mailbox was being polled would be the exact dishonesty it exists to prevent.
# ---------------------------------------------------------------------------


def test_a_real_connector_sync_is_recorded_as_egress(db, alice, egress, services, as_alice):
    from mybot_schemas.models import EgressEvent

    class RemoteCalendar:
        provider = "google_calendar"
        host = "www.googleapis.com"

        def list_events(self, owner_id, since, until):
            return []

    services.sync._record_egress(
        alice.id, kind="connector.calendar", connector=RemoteCalendar(), status="ok", records=7
    )
    db.flush()

    row = db.execute(sa.select(EgressEvent)).scalar_one()
    assert row.left_machine is True
    assert row.destination == "www.googleapis.com"

    ledger = egress.ledger(alice.id)
    assert ledger["left_machine"] == 1
    assert ledger["nothing_left"] is False
    assert ledger["destinations"] == [{"host": "www.googleapis.com", "count": 1}]
    assert ledger["events"][0]["what"] == "Checking your calendar"


def test_a_simulated_connector_is_recorded_as_having_stayed(db, alice, egress, as_alice):
    """Recorded, not omitted.

    The mock connectors run in-process, so nothing leaves -- but the event
    still belongs in the local count, or the ledger's "answered here" number
    quietly under-reports what MyBot actually did.
    """
    from mybot_services.proactive.sync import ConnectorSync

    class InProcess:
        provider = "mock_calendar"
        host = None

    ConnectorSync(db, None)._record_egress(
        alice.id, kind="connector.calendar", connector=InProcess(), status="ok", records=4
    )
    db.flush()

    ledger = egress.ledger(alice.id, only_external=False)
    assert ledger["left_machine"] == 0
    assert ledger["stayed_local"] == 1
    assert ledger["nothing_left"] is True


def test_a_failed_sync_still_counts_as_egress(db, alice, egress, as_alice):
    from mybot_services.proactive.sync import ConnectorSync

    class Remote:
        provider = "gmail"
        host = "gmail.googleapis.com"

    ConnectorSync(db, None)._record_egress(
        alice.id,
        kind="connector.email",
        connector=Remote(),
        status="unavailable",
        detail="connection reset",
    )
    db.flush()

    ledger = egress.ledger(alice.id)
    assert ledger["left_machine"] == 1
    assert ledger["events"][0]["outcome"] == "could not be reached"


def test_the_real_sync_path_records_egress(db, alice, egress, services, as_alice):
    """Through ConnectorSync.sync_all, not a helper -- so the wiring is
    exercised rather than the recording function."""
    services.sync.sync_all(alice.id)
    db.flush()

    ledger = egress.ledger(alice.id, only_external=False)
    kinds = {e["what"] for e in ledger["events"]}
    assert "Checking your calendar" in kinds
    assert "Checking your mailbox" in kinds
    # The demo registry is simulated, so nothing should have left.
    assert ledger["left_machine"] == 0
    assert ledger["stayed_local"] >= 2


def test_model_calls_and_syncs_appear_in_one_ledger(db, alice, egress, as_alice, monkeypatch):
    from mybot_services.proactive.sync import ConnectorSync

    class Remote:
        provider = "gmail"
        host = "gmail.googleapis.com"

    router = _route(Cloud(), monkeypatch)
    try:
        router.run(db, alice.id, _request())
    finally:
        from mybot_schemas.config import reset_settings_cache

        reset_settings_cache()

    ConnectorSync(db, None)._record_egress(
        alice.id, kind="connector.email", connector=Remote(), status="ok", records=12
    )
    db.flush()

    ledger = egress.ledger(alice.id)
    assert ledger["left_machine"] == 2
    assert {d["host"] for d in ledger["destinations"]} == {
        "api.example.com",
        "gmail.googleapis.com",
    }
    # Newest first, across both sources.
    assert [e["at"] for e in ledger["events"]] == sorted(
        [e["at"] for e in ledger["events"]], reverse=True
    )


def test_counts_do_not_depend_on_the_page_size(db, alice, egress, as_alice):
    """A ledger whose totals shrink when you ask for fewer rows would be
    trivially misleading."""
    from mybot_services.proactive.sync import ConnectorSync

    class Remote:
        provider = "gmail"
        host = "gmail.googleapis.com"

    sync = ConnectorSync(db, None)
    for _ in range(25):
        sync._record_egress(
            alice.id, kind="connector.email", connector=Remote(), status="ok", records=1
        )
    db.flush()

    assert egress.ledger(alice.id, limit=5)["left_machine"] == 25
    assert len(egress.ledger(alice.id, limit=5)["events"]) == 5
    assert egress.ledger(alice.id, limit=200)["left_machine"] == 25


def test_sovereign_mode_does_not_silence_connector_egress(db, alice, egress, as_alice):
    """Sovereign mode governs *models*, not connectors.

    Somebody running sovereign with Gmail connected must not be told nothing
    left -- their mail provider is still being contacted, and conflating the
    two would be the ledger telling a comfortable lie.
    """
    from mybot_services.proactive.sync import ConnectorSync

    class Remote:
        provider = "gmail"
        host = "gmail.googleapis.com"

    ConnectorSync(db, None)._record_egress(
        alice.id, kind="connector.email", connector=Remote(), status="ok", records=3
    )
    db.flush()

    ledger = egress.ledger(alice.id)
    assert ledger["nothing_left"] is False
    assert ledger["left_machine"] == 1
