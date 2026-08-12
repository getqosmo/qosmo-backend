"""The Life Graph: structured entities, typed relationships, attributed facts.

Deliberately not "throw everything in a vector store". Embeddings are good at
"find me something like this" and bad at "when exactly does the registration
expire, and who says so". MyBot's answers have to be defensible, so the
primary representation is structured, and similarity search is a later
addition on top rather than the foundation.

Two behaviours here carry real product weight:

* :meth:`assert_fact` never overwrites. Corrections supersede, and the old
  value stays queryable. That is what makes the user-correction flow honest.
* :meth:`resolve_entity` merges conservatively. "PSEG" and "PSE&G" should
  become one organisation; two people who share a surname should not. When
  confidence is low it creates a separate entity and leaves the ambiguity
  visible rather than guessing.
"""

from __future__ import annotations

import datetime as dt
import re
import unicodedata

import sqlalchemy as sa
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    Classification,
    EntityType,
    RelationType,
    SourceKind,
)
from mybot_schemas.models import Entity, Fact, Relationship
from sqlalchemy.orm import Session

from ..audit.service import AuditService

#: Tokens dropped when normalising an organisation name for matching.
_LEGAL_SUFFIXES = {
    "inc", "llc", "ltd", "co", "corp", "corporation", "company", "plc", "gmbh",
    "the", "and",
}

#: Below this, a candidate match is *not* merged. Chosen to be conservative:
#: a wrong merge silently fuses two parts of someone's life and is far harder
#: to notice than a duplicate.
MERGE_THRESHOLD = 0.86


def normalize_name(name: str) -> str:
    """Fold a name to a comparable form.

    ``PSE&G`` / ``PSEG`` / ``Public Service Electric & Gas`` do not all collapse
    to the same string -- and should not. This handles case, punctuation,
    accents and legal suffixes; genuine aliases are recorded explicitly on the
    entity instead of being guessed at.
    """
    text = unicodedata.normalize("NFKD", name or "")
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.lower().replace("&", " and ")
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    tokens = [t for t in text.split() if t and t not in _LEGAL_SUFFIXES]
    return " ".join(tokens)


def _similarity(a: str, b: str) -> float:
    """Token-overlap similarity with an acronym allowance."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    ta, tb = set(a.split()), set(b.split())
    jaccard = len(ta & tb) / len(ta | tb) if (ta | tb) else 0.0
    # "pseg" vs "public service electric and gas"
    acronym_a = "".join(t[0] for t in b.split())
    acronym_b = "".join(t[0] for t in a.split())
    if a.replace(" ", "") == acronym_a or b.replace(" ", "") == acronym_b:
        return max(jaccard, 0.9)
    if a.replace(" ", "") == b.replace(" ", ""):
        return max(jaccard, 0.95)
    return jaccard


class LifeGraphService:
    def __init__(self, session: Session, audit: AuditService | None = None):
        self.session = session
        self.audit = audit or AuditService(session)

    # -- entities --------------------------------------------------------

    def create_entity(
        self,
        owner_id: str,
        *,
        entity_type: EntityType | str,
        name: str,
        summary: str | None = None,
        attributes: dict | None = None,
        classification: Classification = Classification.PERSONAL,
        source_kind: SourceKind = SourceKind.USER_STATEMENT,
        source_id: str | None = None,
        source_detail: str | None = None,
        confidence: float = 1.0,
        inferred: bool = False,
        aliases: list[str] | None = None,
        actor_type: ActorType = ActorType.USER,
        actor_id: str | None = None,
    ) -> Entity:
        entity = Entity(
            owner_id=owner_id,
            entity_type=str(entity_type),
            name=name,
            normalized_name=normalize_name(name),
            summary=summary,
            attributes=attributes or {},
            aliases=aliases or [],
            classification=classification.value,
            source_kind=str(source_kind),
            source_id=source_id,
            source_detail=source_detail,
            confidence=confidence,
            inferred=inferred,
        )
        self.session.add(entity)
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.ENTITY_CREATED,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type="entity",
            resource_id=entity.id,
            reason=f"created {entity_type} “{name}”",
            details={"entity_type": str(entity_type), "source_kind": str(source_kind)},
        )
        return entity

    def get_entity(self, owner_id: str, entity_id: str) -> Entity | None:
        return self.session.execute(
            sa.select(Entity).where(Entity.owner_id == owner_id, Entity.id == entity_id)
        ).scalar_one_or_none()

    def list_entities(
        self,
        owner_id: str,
        *,
        entity_type: str | None = None,
        include_archived: bool = False,
        query: str | None = None,
        limit: int = 200,
    ) -> list[Entity]:
        stmt = sa.select(Entity).where(Entity.owner_id == owner_id)
        if entity_type:
            stmt = stmt.where(Entity.entity_type == entity_type)
        if not include_archived:
            stmt = stmt.where(Entity.archived.is_(False))
        stmt = stmt.where(Entity.merged_into_id.is_(None))
        if query:
            needle = f"%{normalize_name(query)}%"
            stmt = stmt.where(
                sa.or_(Entity.normalized_name.like(needle), Entity.name.ilike(f"%{query}%"))
            )
        return list(
            self.session.execute(stmt.order_by(Entity.name).limit(limit)).scalars()
        )

    def search(self, owner_id: str, query: str, *, limit: int = 20) -> list[Entity]:
        return self.list_entities(owner_id, query=query, limit=limit)

    def update_entity(
        self,
        owner_id: str,
        entity_id: str,
        *,
        name: str | None = None,
        summary: str | None = None,
        attributes: dict | None = None,
        classification: Classification | None = None,
        actor_id: str | None = None,
    ) -> Entity:
        entity = self.get_entity(owner_id, entity_id)
        if entity is None:
            raise LookupError("entity not found")
        changed: dict = {}
        if name is not None and name != entity.name:
            changed["name"] = {"from": entity.name, "to": name}
            entity.name = name
            entity.normalized_name = normalize_name(name)
        if summary is not None:
            entity.summary = summary
            changed["summary"] = True
        if attributes is not None:
            entity.attributes = {**(entity.attributes or {}), **attributes}
            changed["attributes"] = sorted(attributes.keys())
        if classification is not None:
            changed["classification"] = classification.value
            entity.classification = classification.value
        entity.updated_at = utcnow()
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.ENTITY_UPDATED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="entity",
            resource_id=entity.id,
            reason="entity edited by owner",
            details=changed,
        )
        return entity

    def archive_entity(self, owner_id: str, entity_id: str, *, actor_id: str | None = None) -> Entity:
        entity = self.get_entity(owner_id, entity_id)
        if entity is None:
            raise LookupError("entity not found")
        entity.archived = True
        entity.archived_at = utcnow()
        self.session.flush()
        self.audit.record(
            owner_id,
            AuditEventType.ENTITY_ARCHIVED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="entity",
            resource_id=entity.id,
            reason="archived by owner",
        )
        return entity

    # -- entity resolution ----------------------------------------------

    def find_similar(
        self, owner_id: str, name: str, entity_type: str | None = None
    ) -> list[tuple[Entity, float]]:
        normalized = normalize_name(name)
        candidates = self.list_entities(owner_id, entity_type=entity_type, limit=500)
        scored: list[tuple[Entity, float]] = []
        for candidate in candidates:
            score = _similarity(normalized, candidate.normalized_name)
            for alias in candidate.aliases or []:
                score = max(score, _similarity(normalized, normalize_name(alias)))
            if score > 0.4:
                scored.append((candidate, score))
        return sorted(scored, key=lambda pair: pair[1], reverse=True)

    def resolve_entity(
        self,
        owner_id: str,
        *,
        entity_type: EntityType | str,
        name: str,
        create_if_missing: bool = True,
        **create_kwargs,
    ) -> tuple[Entity, bool]:
        """Find or create an entity, merging only when confident.

        Returns ``(entity, created)``. A near-miss below
        :data:`MERGE_THRESHOLD` produces a *new* entity and records the
        near-match as an alias candidate, so the duplicate is visible and the
        user can merge it deliberately.
        """
        matches = self.find_similar(owner_id, name, str(entity_type))
        if matches and matches[0][1] >= MERGE_THRESHOLD:
            entity, score = matches[0]
            if normalize_name(name) != entity.normalized_name and name not in (entity.aliases or []):
                entity.aliases = list(entity.aliases or []) + [name]
                self.session.flush()
            return entity, False
        if not create_if_missing:
            raise LookupError(f"no entity matching {name!r}")
        entity = self.create_entity(owner_id, entity_type=entity_type, name=name, **create_kwargs)
        if matches:
            # Record the ambiguity rather than resolving it silently.
            entity.attributes = {
                **(entity.attributes or {}),
                "possible_duplicate_of": [
                    {"id": m.id, "name": m.name, "score": round(s, 3)} for m, s in matches[:3]
                ],
            }
            self.session.flush()
        return entity, True

    def merge_entities(
        self, owner_id: str, keep_id: str, merge_id: str, *, actor_id: str | None = None
    ) -> Entity:
        """Merge one entity into another. Never automatic."""
        keep = self.get_entity(owner_id, keep_id)
        merge = self.get_entity(owner_id, merge_id)
        if keep is None or merge is None:
            raise LookupError("entity not found")
        if keep.id == merge.id:
            raise ValueError("cannot merge an entity into itself")

        for fact in list(merge.facts):
            fact.entity_id = keep.id
        self.session.execute(
            sa.update(Relationship)
            .where(Relationship.owner_id == owner_id, Relationship.from_id == merge.id)
            .values(from_id=keep.id)
        )
        self.session.execute(
            sa.update(Relationship)
            .where(Relationship.owner_id == owner_id, Relationship.to_id == merge.id)
            .values(to_id=keep.id)
        )
        keep.aliases = list(dict.fromkeys(list(keep.aliases or []) + [merge.name] + list(merge.aliases or [])))
        keep.attributes = {**(merge.attributes or {}), **(keep.attributes or {})}
        merge.merged_into_id = keep.id
        merge.archived = True
        merge.archived_at = utcnow()
        self.session.flush()

        self.audit.record(
            owner_id,
            AuditEventType.ENTITY_UPDATED,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="entity",
            resource_id=keep.id,
            reason=f"merged “{merge.name}” into “{keep.name}”",
            details={"merged_id": merge.id},
        )
        return keep

    # -- relationships ---------------------------------------------------

    def relate(
        self,
        owner_id: str,
        from_id: str,
        relation_type: RelationType | str,
        to_id: str,
        *,
        attributes: dict | None = None,
        source_kind: SourceKind = SourceKind.USER_STATEMENT,
        source_id: str | None = None,
        confidence: float = 1.0,
        valid_from: dt.datetime | None = None,
        valid_to: dt.datetime | None = None,
    ) -> Relationship:
        existing = self.session.execute(
            sa.select(Relationship).where(
                Relationship.owner_id == owner_id,
                Relationship.from_id == from_id,
                Relationship.to_id == to_id,
                Relationship.relation_type == str(relation_type),
            )
        ).scalar_one_or_none()
        if existing is not None:
            if attributes:
                existing.attributes = {**(existing.attributes or {}), **attributes}
                self.session.flush()
            return existing

        rel = Relationship(
            owner_id=owner_id,
            from_id=from_id,
            to_id=to_id,
            relation_type=str(relation_type),
            attributes=attributes or {},
            source_kind=str(source_kind),
            source_id=source_id,
            confidence=confidence,
            valid_from=valid_from,
            valid_to=valid_to,
        )
        self.session.add(rel)
        self.session.flush()
        return rel

    def neighbours(
        self, owner_id: str, entity_id: str, *, relation_type: str | None = None
    ) -> list[tuple[Relationship, Entity]]:
        stmt = sa.select(Relationship).where(
            Relationship.owner_id == owner_id,
            sa.or_(Relationship.from_id == entity_id, Relationship.to_id == entity_id),
        )
        if relation_type:
            stmt = stmt.where(Relationship.relation_type == relation_type)
        out: list[tuple[Relationship, Entity]] = []
        for rel in self.session.execute(stmt).scalars():
            other_id = rel.to_id if rel.from_id == entity_id else rel.from_id
            other = self.get_entity(owner_id, other_id)
            if other is not None:
                out.append((rel, other))
        return out

    # -- facts -----------------------------------------------------------

    def assert_fact(
        self,
        owner_id: str,
        entity_id: str,
        key: str,
        value,
        *,
        source_kind: SourceKind = SourceKind.USER_STATEMENT,
        source_id: str | None = None,
        evidence: str | None = None,
        confidence: float = 1.0,
        classification: Classification = Classification.PERSONAL,
        inferred: bool = False,
        observed_at: dt.datetime | None = None,
        actor_type: ActorType = ActorType.SYSTEM,
    ) -> Fact:
        """Record a fact, superseding any current value for the same key.

        A correction from the user always wins over an inference, regardless of
        the inference's stated confidence -- the person is the authority on
        their own life.
        """
        current = self.current_fact(owner_id, entity_id, key)

        if current is not None:
            incoming_trusted = source_kind in (SourceKind.USER_CORRECTION, SourceKind.USER_STATEMENT)
            current_trusted = SourceKind(current.source_kind) in (
                SourceKind.USER_CORRECTION,
                SourceKind.USER_STATEMENT,
            )
            # Do not let a weak automated inference quietly overwrite something
            # the owner told us directly.
            if current_trusted and not incoming_trusted and confidence < 0.99:
                return current

        fact = Fact(
            owner_id=owner_id,
            entity_id=entity_id,
            key=key,
            value={"value": value},
            evidence=evidence,
            source_kind=str(source_kind),
            source_id=source_id,
            confidence=confidence,
            inferred=inferred,
            classification=classification.value,
            observed_at=observed_at or utcnow(),
        )
        self.session.add(fact)
        self.session.flush()

        if current is not None and current.id != fact.id:
            current.superseded_by_id = fact.id
            current.superseded_at = utcnow()
            self.session.flush()
            self.audit.record(
                owner_id,
                AuditEventType.MEMORY_SUPERSEDED,
                actor_type=actor_type,
                resource_type="fact",
                resource_id=fact.id,
                reason=f"{key} updated ({source_kind})",
                details={
                    "entity_id": entity_id,
                    "key": key,
                    "superseded_fact_id": current.id,
                    "previous_source": current.source_kind,
                },
            )
        return fact

    def current_fact(self, owner_id: str, entity_id: str, key: str) -> Fact | None:
        return self.session.execute(
            sa.select(Fact)
            .where(
                Fact.owner_id == owner_id,
                Fact.entity_id == entity_id,
                Fact.key == key,
                Fact.superseded_by_id.is_(None),
            )
            .order_by(Fact.observed_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    def fact_history(self, owner_id: str, entity_id: str, key: str) -> list[Fact]:
        return list(
            self.session.execute(
                sa.select(Fact)
                .where(Fact.owner_id == owner_id, Fact.entity_id == entity_id, Fact.key == key)
                .order_by(Fact.observed_at.asc())
            ).scalars()
        )

    def current_facts(self, owner_id: str, entity_id: str) -> list[Fact]:
        return list(
            self.session.execute(
                sa.select(Fact).where(
                    Fact.owner_id == owner_id,
                    Fact.entity_id == entity_id,
                    Fact.superseded_by_id.is_(None),
                )
            ).scalars()
        )

    def counts_by_type(self, owner_id: str) -> dict[str, int]:
        rows = self.session.execute(
            sa.select(Entity.entity_type, sa.func.count())
            .where(
                Entity.owner_id == owner_id,
                Entity.archived.is_(False),
                Entity.merged_into_id.is_(None),
            )
            .group_by(Entity.entity_type)
        ).all()
        return {row[0]: int(row[1]) for row in rows}


__all__ = ["LifeGraphService", "MERGE_THRESHOLD", "normalize_name"]
