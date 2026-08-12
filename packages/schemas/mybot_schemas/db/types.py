"""Portable column types.

MyBot runs on SQLite (local Core, `mybot demo`, tests) and PostgreSQL (server
profile) from the same model definitions.  These decorators paper over the
differences without letting either dialect leak into the domain layer.
"""

from __future__ import annotations

import datetime as dt
import uuid

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

#: JSON that becomes JSONB on Postgres (indexable) and TEXT-backed JSON on
#: SQLite.  Used for structured entity attributes so new entity types do not
#: require a migration.
JSONDict = sa.JSON().with_variant(JSONB, "postgresql")


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes that survive SQLite.

    SQLite has no native timezone support and will happily hand back naive
    datetimes, which then compare incorrectly against aware ones and silently
    corrupt deadline maths.  This normalises on the way in and re-attaches UTC
    on the way out.
    """

    impl = sa.DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(sa.DateTime(timezone=True))
        return dialect.type_descriptor(sa.DateTime())

    def process_bind_param(self, value: dt.datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError(
                "naive datetime rejected: MyBot stores timezone-aware UTC only"
            )
        return value.astimezone(dt.UTC).replace(tzinfo=None if dialect.name != "postgresql" else dt.UTC)

    def process_result_value(self, value: dt.datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.UTC)
        return value.astimezone(dt.UTC)


class UUIDStr(TypeDecorator):
    """UUIDs stored as canonical 36-char strings.

    Deliberately not the native Postgres UUID type: identifiers appear in
    exports, audit hashes and URLs, and a single textual representation
    everywhere removes a whole class of "same id, different bytes" bugs.
    """

    impl = sa.String(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return str(value)
        # Validate: refuse to store something that is not an id.
        uuid.UUID(str(value))
        return str(value)

    def process_result_value(self, value, dialect):
        return value


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["JSONDict", "UTCDateTime", "UUIDStr", "new_uuid", "utcnow"]
