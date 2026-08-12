"""Owner isolation.

The single most consequential property in a product like this: Alice must
never see Bob's life. These tests attack it from every direction the
application actually exposes -- services, the ORM, and HTTP with a valid token
for the wrong account.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from mybot_schemas.db.scope import OwnerScopeError, session_owner_scope
from mybot_schemas.enums import ActorType, EntityType, MemoryKind
from mybot_schemas.models import OWNED_MODELS, Entity
from mybot_services.action_firewall.service import ProposalRequest


def test_every_personal_model_is_owner_scoped():
    """A new personal table that forgets ``OwnedMixin`` cannot land silently.

    Walks the mapper registry rather than a hand-maintained list, so the test
    stays true as the schema grows.
    """
    from mybot_schemas.db.base import Base, OwnedMixin

    #: Tables that legitimately hold no per-owner data.
    exempt = {"users"}
    unscoped = []
    for mapper in Base.registry.mappers:
        model = mapper.class_
        table = model.__tablename__
        if table in exempt:
            continue
        if not issubclass(model, OwnedMixin):
            unscoped.append(table)
    assert unscoped == [], (
        f"these tables hold personal data but are not owner-scoped: {unscoped}. "
        "Inherit OwnedMixin so the ORM-level owner filter applies."
    )


def test_orm_filter_hides_other_owners_rows(db, alice, bob):
    with session_owner_scope(db, alice.id):
        db.add(
            Entity(
                owner_id=alice.id,
                entity_type=EntityType.PERSON.value,
                name="Alice's contact",
                normalized_name="alices contact",
            )
        )
        db.flush()
    with session_owner_scope(db, bob.id):
        db.add(
            Entity(
                owner_id=bob.id,
                entity_type=EntityType.PERSON.value,
                name="Bob's contact",
                normalized_name="bobs contact",
            )
        )
        db.flush()

    # A query with no owner predicate at all still only returns one owner's rows.
    with session_owner_scope(db, alice.id):
        rows = db.execute(sa.select(Entity)).scalars().all()
        assert [r.name for r in rows] == ["Alice's contact"]

    with session_owner_scope(db, bob.id):
        rows = db.execute(sa.select(Entity)).scalars().all()
        assert [r.name for r in rows] == ["Bob's contact"]


def test_direct_id_lookup_for_another_owner_returns_nothing(db, alice, bob):
    with session_owner_scope(db, alice.id):
        entity = Entity(
            owner_id=alice.id,
            entity_type=EntityType.PERSON.value,
            name="Private",
            normalized_name="private",
        )
        db.add(entity)
        db.flush()
        entity_id = entity.id

    with session_owner_scope(db, bob.id):
        found = db.execute(sa.select(Entity).where(Entity.id == entity_id)).scalar_one_or_none()
        assert found is None


def test_unscoped_read_of_owned_data_fails_closed(db, alice):
    with session_owner_scope(db, alice.id):
        db.add(
            Entity(
                owner_id=alice.id,
                entity_type=EntityType.PERSON.value,
                name="X",
                normalized_name="x",
            )
        )
        db.flush()

    # No scope bound: the guard raises rather than returning everything.
    with pytest.raises(OwnerScopeError):
        db.execute(sa.select(Entity)).scalars().all()


def test_services_cannot_read_across_owners(services, db, alice, bob):
    with session_owner_scope(db, alice.id):
        memory = services.memory.remember(
            alice.id, "Alice's private note", kind=MemoryKind.FACT
        )
        memory_id = memory.id

    with session_owner_scope(db, bob.id):
        assert services.memory.get(bob.id, memory_id) is None
        assert services.memory.search(bob.id, "private") == []


def test_action_lookup_across_owners_raises_not_found(services, db, alice, bob):
    with session_owner_scope(db, alice.id):
        proposal = services.firewall.propose(
            ProposalRequest(
                owner_id=alice.id,
                action_type="calendar.reschedule",
                params={
                    "event_id": "e1",
                    "new_start": "2030-01-01T10:00:00+00:00",
                    "new_end": "2030-01-01T11:00:00+00:00",
                },
                actor_type=ActorType.USER,
            )
        )
        proposal_id = proposal.id

    with session_owner_scope(db, bob.id):
        with pytest.raises(LookupError):
            services.firewall.get(bob.id, proposal_id)
        # Approving somebody else's action must be impossible, not merely denied.
        with pytest.raises(LookupError):
            services.firewall.approve(
                bob.id, proposal_id, approver_user_id=bob.id, auth_level="BASIC"
            )


def test_audit_chains_are_per_owner(services, db, alice, bob):
    with session_owner_scope(db, alice.id):
        for _ in range(3):
            services.audit.record(alice.id, "test.event")
        assert services.audit.count_events(alice.id) == 3
    with session_owner_scope(db, bob.id):
        services.audit.record(bob.id, "test.event")
        assert services.audit.count_events(bob.id) == 1
        # Bob cannot read Alice's chain even by asking for it explicitly.
        assert services.audit.list_events(alice.id) == []


# ---------------------------------------------------------------------------
# Through the HTTP API, with a real token for the wrong account
# ---------------------------------------------------------------------------


def test_api_cross_owner_resource_access_returns_404(api, registered):
    alice = registered("alice-api@example.com", "Alice")
    bob = registered("bob-api@example.com", "Bob")

    created = api.post(
        "/api/v1/entities",
        json={"type": "Person", "name": "Alice's doctor"},
        headers=alice["headers"],
    )
    assert created.status_code == 201
    entity_id = created.json()["id"]

    # Bob holds a perfectly valid token -- for the wrong life.
    response = api.get(f"/api/v1/entities/{entity_id}", headers=bob["headers"])
    assert response.status_code == 404

    listing = api.get("/api/v1/entities", headers=bob["headers"]).json()
    assert all(item["name"] != "Alice's doctor" for item in listing["items"])


def test_api_cross_owner_memory_deletion_is_refused(api, registered):
    alice = registered("alice-mem@example.com", "Alice")
    bob = registered("bob-mem@example.com", "Bob")

    created = api.post(
        "/api/v1/memory",
        json={"content": "Alice takes medication at 8pm"},
        headers=alice["headers"],
    )
    memory_id = created.json()["id"]

    assert api.delete(f"/api/v1/memory/{memory_id}", headers=bob["headers"]).status_code == 404
    # Still there for its owner.
    assert api.get("/api/v1/memory", headers=alice["headers"]).json()["items"]


def test_api_cross_owner_action_approval_is_refused(api, registered):
    alice = registered("alice-act@example.com", "Alice")
    bob = registered("bob-act@example.com", "Bob")

    created = api.post(
        "/api/v1/actions",
        json={
            "action_type": "calendar.create",
            "params": {
                "title": "Alice's appointment",
                "start": "2030-03-01T10:00:00+00:00",
                "end": "2030-03-01T11:00:00+00:00",
            },
        },
        headers=alice["headers"],
    )
    assert created.status_code == 201
    action_id = created.json()["id"]

    assert api.get(f"/api/v1/actions/{action_id}", headers=bob["headers"]).status_code == 404
    assert (
        api.post(f"/api/v1/actions/{action_id}/approve", json={}, headers=bob["headers"]).status_code
        == 404
    )
    assert (
        api.post(f"/api/v1/actions/{action_id}/reject", json={}, headers=bob["headers"]).status_code
        == 404
    )

    # And Alice's action is untouched.
    still_pending = api.get(f"/api/v1/actions/{action_id}", headers=alice["headers"]).json()
    assert still_pending["status"] == "pending_approval"


def test_api_export_contains_only_the_callers_data(api, registered):
    alice = registered("alice-exp@example.com", "Alice")
    bob = registered("bob-exp@example.com", "Bob")

    api.post("/api/v1/memory", json={"content": "alice-secret-string"}, headers=alice["headers"])
    api.post("/api/v1/memory", json={"content": "bob-secret-string"}, headers=bob["headers"])

    export = api.get("/api/v1/account/export", headers=bob["headers"])
    assert export.status_code == 200
    body = export.text
    assert "bob-secret-string" in body
    assert "alice-secret-string" not in body


def test_api_deletion_does_not_touch_other_owners(api, registered, elevate):
    alice = registered("alice-del@example.com", "Alice")
    bob = registered("bob-del@example.com", "Bob")

    api.post("/api/v1/memory", json={"content": "alice keeps this"}, headers=alice["headers"])
    api.post("/api/v1/memory", json={"content": "bob deletes this"}, headers=bob["headers"])

    elevate(bob)
    response = api.post(
        "/api/v1/account/data/delete",
        json={"confirm": "DELETE MY DATA"},
        headers=bob["headers"],
    )
    assert response.status_code == 200

    assert api.get("/api/v1/memory", headers=bob["headers"]).json()["items"] == []
    alice_memories = api.get("/api/v1/memory", headers=alice["headers"]).json()["items"]
    assert any("alice keeps this" in m["content"] for m in alice_memories)


def test_owned_models_registry_is_populated():
    """Sanity check on the reflection helper used by export and deletion."""
    names = {m.__name__ for m in OWNED_MODELS}
    for expected in ("Entity", "Memory", "Obligation", "ActionProposal", "AuditEvent"):
        assert expected in names
    assert "User" not in names
