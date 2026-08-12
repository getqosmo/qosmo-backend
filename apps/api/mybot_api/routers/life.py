"""Life Graph, memory and obligations.

The "everything MyBot knows, and you can edit all of it" surface. Every read
here is owner-scoped twice over: by the ORM filter armed in ``deps``, and by an
explicit predicate in each service call. A resource belonging to somebody else
returns 404, never 403 -- the latter confirms it exists.
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Query, status
from mybot_schemas.enums import (
    Classification,
    EntityType,
    MemoryKind,
    ObligationStatus,
    Recurrence,
    SourceKind,
)
from pydantic import BaseModel, Field

from ..deps import Principal, ServiceBundle, get_principal, get_services
from ..serializers import entity_out, memory_out, obligation_out

router = APIRouter(prefix="/api/v1", tags=["life"])

NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


class EntityIn(BaseModel):
    type: str
    name: str = Field(min_length=1, max_length=300)
    summary: str | None = None
    attributes: dict = Field(default_factory=dict)
    classification: str = Classification.PERSONAL.value


class EntityPatch(BaseModel):
    name: str | None = None
    summary: str | None = None
    attributes: dict | None = None
    classification: str | None = None


class MemoryIn(BaseModel):
    content: str = Field(min_length=1, max_length=4000)
    kind: str = MemoryKind.FACT.value
    subject: str | None = None
    tags: list[str] = Field(default_factory=list)
    entity_id: str | None = None
    classification: str = Classification.PERSONAL.value


class MemoryCorrection(BaseModel):
    content: str = Field(min_length=1, max_length=4000)


class ObligationIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    due_at: dt.datetime | None = None
    kind: str = "generic"
    description: str | None = None
    consequence: str | None = None
    amount: float | None = None
    currency: str | None = None
    recurrence: str = Recurrence.NONE.value
    entity_id: str | None = None


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------


@router.get("/entities")
def list_entities(
    type: str | None = Query(default=None),
    q: str | None = Query(default=None),
    include_archived: bool = Query(default=False),
    limit: int = Query(default=200, le=500),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    entities = services.graph.list_entities(
        principal.owner_id,
        entity_type=type,
        query=q,
        include_archived=include_archived,
        limit=limit,
    )
    return {
        "items": [entity_out(e) for e in entities],
        "counts": services.graph.counts_by_type(principal.owner_id),
        "types": [t.value for t in EntityType],
    }


@router.get("/entities/{entity_id}")
def get_entity(
    entity_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    entity = services.graph.get_entity(principal.owner_id, entity_id)
    if entity is None:
        raise NOT_FOUND
    facts = services.graph.current_facts(principal.owner_id, entity_id)
    neighbours = services.graph.neighbours(principal.owner_id, entity_id)
    payload = entity_out(entity, facts=facts)
    payload["relationships"] = [
        {
            "id": rel.id,
            "type": rel.relation_type,
            "direction": "out" if rel.from_id == entity_id else "in",
            "other": {"id": other.id, "name": other.name, "type": other.entity_type},
            "attributes": rel.attributes or {},
        }
        for rel, other in neighbours
    ]
    return payload


@router.post("/entities", status_code=status.HTTP_201_CREATED)
def create_entity(
    payload: EntityIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    entity = services.graph.create_entity(
        principal.owner_id,
        entity_type=payload.type,
        name=payload.name,
        summary=payload.summary,
        attributes=payload.attributes,
        classification=Classification(payload.classification),
        source_kind=SourceKind.USER_STATEMENT,
        actor_id=principal.owner_id,
    )
    return entity_out(entity)


@router.patch("/entities/{entity_id}")
def patch_entity(
    entity_id: str,
    payload: EntityPatch,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        entity = services.graph.update_entity(
            principal.owner_id,
            entity_id,
            name=payload.name,
            summary=payload.summary,
            attributes=payload.attributes,
            classification=Classification(payload.classification) if payload.classification else None,
            actor_id=principal.owner_id,
        )
    except LookupError:
        raise NOT_FOUND from None
    return entity_out(entity)


@router.delete("/entities/{entity_id}")
def archive_entity(
    entity_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Archive, not delete.

    Hard deletion of a graph node would orphan the facts and audit references
    that explain past conclusions. Permanent removal of personal content goes
    through ``/api/v1/account/data`` where the distinction is explicit.
    """
    try:
        entity = services.graph.archive_entity(
            principal.owner_id, entity_id, actor_id=principal.owner_id
        )
    except LookupError:
        raise NOT_FOUND from None
    return entity_out(entity)


@router.get("/entities/{entity_id}/facts/{key}/history")
def fact_history(
    entity_id: str,
    key: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Every version of one fact, including superseded ones.

    This is what makes "you told me October 18, the notice said October 14"
    answerable months later.
    """
    from ..serializers import fact_out

    history = services.graph.fact_history(principal.owner_id, entity_id, key)
    return {"key": key, "history": [fact_out(f) for f in history]}


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------


@router.get("/memory")
def list_memories(
    q: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    memories = services.memory.search(principal.owner_id, q, kind=kind, limit=200)
    return {
        "items": [memory_out(m) for m in memories],
        "preferences": services.memory.preferences(principal.owner_id),
        "kinds": [k.value for k in MemoryKind if k not in (MemoryKind.WORKING, MemoryKind.CONVERSATION)],
    }


@router.post("/memory", status_code=status.HTTP_201_CREATED)
def create_memory(
    payload: MemoryIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        memory = services.memory.remember(
            principal.owner_id,
            payload.content,
            kind=MemoryKind(payload.kind),
            subject=payload.subject,
            entity_id=payload.entity_id,
            tags=payload.tags,
            classification=Classification(payload.classification),
            source_kind=SourceKind.USER_STATEMENT,
            actor_id=principal.owner_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
    return memory_out(memory)


@router.post("/memory/{memory_id}/correct")
def correct_memory(
    memory_id: str,
    payload: MemoryCorrection,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Apply a correction.

    The old memory is superseded rather than overwritten, and the replacement
    is attributed to the user -- which makes it outrank any inference.
    """
    try:
        memory = services.memory.correct(
            principal.owner_id, memory_id, payload.content, actor_id=principal.owner_id
        )
    except LookupError:
        raise NOT_FOUND from None
    return memory_out(memory)


@router.delete("/memory/{memory_id}")
def delete_memory(
    memory_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    """Delete a memory for real. The content is removed."""
    deleted = services.memory.forget(principal.owner_id, memory_id, actor_id=principal.owner_id)
    if not deleted:
        raise NOT_FOUND
    return {"deleted": True, "id": memory_id}


# ---------------------------------------------------------------------------
# Obligations
# ---------------------------------------------------------------------------


@router.get("/obligations")
def list_obligations(
    status_filter: str | None = Query(default=None, alias="status"),
    within_days: int | None = Query(default=None),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    from mybot_schemas.db.types import utcnow

    due_before = (
        utcnow() + dt.timedelta(days=within_days) if within_days is not None else None
    )
    rows = services.obligations.list(
        principal.owner_id, status=status_filter, due_before=due_before
    )
    return {"items": [obligation_out(o) for o in rows]}


@router.post("/obligations", status_code=status.HTTP_201_CREATED)
def create_obligation(
    payload: ObligationIn,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    obligation = services.obligations.create(
        principal.owner_id,
        title=payload.title,
        due_at=payload.due_at,
        kind=payload.kind,
        description=payload.description,
        consequence=payload.consequence,
        amount=payload.amount,
        currency=payload.currency,
        recurrence=Recurrence(payload.recurrence),
        entity_id=payload.entity_id,
        source_kind=SourceKind.USER_STATEMENT,
        actor_id=principal.owner_id,
    )
    return obligation_out(obligation)


@router.post("/obligations/{obligation_id}/complete")
def complete_obligation(
    obligation_id: str,
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        obligation = services.obligations.complete(
            principal.owner_id, obligation_id, actor_id=principal.owner_id
        )
    except LookupError:
        raise NOT_FOUND from None
    return obligation_out(obligation)


@router.patch("/obligations/{obligation_id}/status")
def set_obligation_status(
    obligation_id: str,
    new_status: str = Query(alias="status"),
    principal: Principal = Depends(get_principal),
    services: ServiceBundle = Depends(get_services),
):
    try:
        obligation = services.obligations.update_status(
            principal.owner_id,
            obligation_id,
            ObligationStatus(new_status),
            actor_id=principal.owner_id,
        )
    except LookupError:
        raise NOT_FOUND from None
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown status"
        ) from None
    return obligation_out(obligation)
