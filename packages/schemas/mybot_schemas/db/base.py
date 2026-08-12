"""Declarative base and the mixins that carry MyBot's cross-cutting guarantees."""

from __future__ import annotations

import datetime as dt

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

from ..enums import Classification, SourceKind
from .scope import install_owner_guard
from .types import UTCDateTime, UUIDStr, new_uuid, utcnow


class Base(DeclarativeBase):
    """Root of the MyBot schema."""

    type_annotation_map = {
        dt.datetime: UTCDateTime,
    }


class UUIDPk:
    id: Mapped[str] = mapped_column(UUIDStr, primary_key=True, default=new_uuid)


class Timestamped:
    created_at: Mapped[dt.datetime] = mapped_column(
        UTCDateTime, default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class OwnedMixin:
    """Marks a table as holding one specific person's data.

    Inheriting this is what wires a model into the global owner filter in
    ``scope.py``.  Every personal table must inherit it; ``tests/security``
    asserts that by reflection, so a new model that forgets cannot land.
    """

    @declared_attr
    def owner_id(cls) -> Mapped[str]:  # noqa: N805
        return mapped_column(
            UUIDStr,
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        )


class Classified:
    """Data-classification metadata used for redaction and egress control."""

    classification: Mapped[str] = mapped_column(
        sa.String(20), default=Classification.PERSONAL.value, nullable=False
    )


class Provenanced:
    """Where this came from, and how much we believe it.

    ``confidence`` is deliberately on the record rather than inferred at read
    time: the proactive engine refuses to escalate low-confidence facts into
    external actions, and it can only do that if the number is stored.
    """

    source_kind: Mapped[str] = mapped_column(
        sa.String(32), default=SourceKind.SYSTEM.value, nullable=False
    )
    source_id: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    source_detail: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    confidence: Mapped[float] = mapped_column(sa.Float, default=1.0, nullable=False)
    inferred: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)


class SoftDeletable:
    """Archive vs. delete.

    Archiving hides something from the product surface.  Actual deletion is a
    separate, audited operation -- see ``docs/DATA_MODEL.md`` for why personal
    content deletion and audit retention are handled differently.
    """

    archived: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False, index=True)
    archived_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    deleted_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


# Install the ORM-level owner predicate for every OwnedMixin subclass.
install_owner_guard(OwnedMixin)


__all__ = [
    "Base",
    "Classified",
    "OwnedMixin",
    "Provenanced",
    "SoftDeletable",
    "Timestamped",
    "UUIDPk",
]
