"""Engine, session factory, and the append-only enforcement for the audit log.

The audit chain is only worth something if it cannot be quietly edited.  Three
layers guard it:

1. No API surface exposes update or delete for audit rows.
2. ORM ``before_update`` / ``before_delete`` hooks in this module raise.
3. Database triggers (created in the migration) reject UPDATE and DELETE even
   for something holding a raw connection.

Layer 3 is the one that survives a compromised application process, which is
exactly the scenario the threat model assumes.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import get_settings
from .base import Base

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


class AuditImmutableError(RuntimeError):
    """Raised on any attempt to mutate or delete an audit record."""


def _configure_sqlite(dbapi_connection, _record):
    """SQLite needs to be told to behave.

    Foreign keys are off by default -- without this the ``ON DELETE CASCADE``
    that backs data deletion silently does nothing.  WAL keeps the local Core
    responsive while the proactive engine writes in the background.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def create_engine_from_settings(url: str | None = None) -> Engine:
    settings = get_settings()
    url = url or settings.database_url
    kwargs: dict = {"future": True, "echo": False}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            # Tests share one in-memory database across sessions.
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    engine = sa.create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine_from_settings()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_engine(), autoflush=False, expire_on_commit=False, future=True
        )
    return _SessionFactory


def configure_engine(engine: Engine) -> None:
    """Swap in an engine (tests, alternate profiles)."""
    global _engine, _SessionFactory
    _engine = engine
    _SessionFactory = sessionmaker(
        bind=engine, autoflush=False, expire_on_commit=False, future=True
    )


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session. Commits on success, rolls back on any exception."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(engine: Engine | None = None) -> None:
    """Create the schema plus the audit-immutability triggers.

    Used by tests and ``mybot init``.  The migration path (Alembic) produces
    the same result; both call :func:`install_audit_triggers` so the guarantee
    does not depend on which one you used.
    """
    engine = engine or get_engine()
    Base.metadata.create_all(engine)
    install_audit_triggers(engine)


def install_audit_triggers(engine: Engine) -> None:
    """Database-level append-only enforcement for ``audit_events``.

    Deliberately at the storage layer: an attacker who has the application
    process still cannot rewrite history through it.
    """
    dialect = engine.dialect.name
    with engine.begin() as conn:
        if dialect == "sqlite":
            conn.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only');
                END;
                """
            )
            conn.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only');
                END;
                """
            )
        elif dialect == "postgresql":
            conn.exec_driver_sql(
                """
                CREATE OR REPLACE FUNCTION mybot_audit_append_only()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_events is append-only';
                END;
                $$ LANGUAGE plpgsql;
                """
            )
            conn.exec_driver_sql("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;")
            conn.exec_driver_sql(
                """
                CREATE TRIGGER audit_events_no_update
                BEFORE UPDATE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION mybot_audit_append_only();
                """
            )
            conn.exec_driver_sql("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;")
            conn.exec_driver_sql(
                """
                CREATE TRIGGER audit_events_no_delete
                BEFORE DELETE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION mybot_audit_append_only();
                """
            )


def _install_orm_audit_guard() -> None:
    # The model class is resolved lazily inside the handler: this module is
    # imported while ``models`` is still being defined, so a top-level import
    # would be circular.
    def _audit_class() -> type | None:
        from .. import models

        return getattr(models, "AuditEvent", None)

    @event.listens_for(Session, "before_flush")
    def _block_audit_mutation(session: Session, _flush_context, _instances):
        audit_cls = _audit_class()
        if audit_cls is None:  # pragma: no cover - only during import bootstrap
            return
        for obj in session.dirty:
            if isinstance(obj, audit_cls) and session.is_modified(obj):
                raise AuditImmutableError(
                    "audit events are append-only; attempted modification of "
                    f"event {getattr(obj, 'id', '?')}"
                )
        for obj in session.deleted:
            if isinstance(obj, audit_cls):
                raise AuditImmutableError(
                    "audit events are append-only; attempted deletion of "
                    f"event {getattr(obj, 'id', '?')}"
                )


_install_orm_audit_guard()


__all__ = [
    "AuditImmutableError",
    "configure_engine",
    "create_all",
    "create_engine_from_settings",
    "get_engine",
    "get_session_factory",
    "install_audit_triggers",
    "session_scope",
]
