"""Owner isolation, enforced by the ORM rather than by discipline.

The failure mode this module exists to prevent is the most boring and most
common one in multi-tenant software: a query that forgot its ``WHERE
owner_id = ?``. Reviews miss it, tests miss the one endpoint nobody thought
about, and one person reads another person's life.

So MyBot does not rely on every call site remembering:

* Every table holding personal data inherits :class:`OwnedMixin`.
* A session-wide ``do_orm_execute`` hook injects an owner predicate into
  *every* ORM SELECT touching an owned model, via ``with_loader_criteria``.
* With no scope bound, owned models cannot be read at all -- the query raises.
  System work must say so explicitly with a reason.

**Where the scope lives.** The binding is on the *session*, not on a thread or
a context variable. A unit of work belongs to one owner; that is a property of
the transaction, not of whichever thread happens to be running it. This also
sidesteps a real trap: an ASGI framework runs middleware, dependencies and
sync route handlers in different tasks and threadpool workers, so a
``ContextVar`` set in one is not reliably resettable in another.

A context-variable scope is kept as a secondary mechanism for code that has no
session in hand yet -- the CLI, tests, background jobs -- and the session
binding takes precedence when both are present.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar

from sqlalchemy import event
from sqlalchemy.orm import Session, with_loader_criteria

#: Keys used in ``Session.info``.
OWNER_KEY = "mybot_owner_id"
SYSTEM_KEY = "mybot_system_scope"

_current_owner: ContextVar[str | None] = ContextVar("mybot_current_owner", default=None)
_system_scope: ContextVar[bool] = ContextVar("mybot_system_scope", default=False)


class OwnerScopeError(RuntimeError):
    """Raised when owned data is touched without an explicit scope.

    A security control, not a convenience error. Callers must not catch it to
    "try again unscoped".
    """


class CrossOwnerAccess(PermissionError):
    """Raised when a resource exists but belongs to somebody else.

    Callers translate this into the same 404 they return for a missing
    resource -- distinguishing the two leaks the existence of another user's
    data.
    """


# ---------------------------------------------------------------------------
# Session-bound scope (the primary mechanism)
# ---------------------------------------------------------------------------


def bind_owner(session: Session, owner_id: str) -> None:
    """Bind a session to one owner for its remaining lifetime."""
    if not owner_id:
        raise OwnerScopeError("bind_owner requires a non-empty owner id")
    session.info[OWNER_KEY] = owner_id
    session.info.pop(SYSTEM_KEY, None)


def bound_owner(session: Session) -> str | None:
    return session.info.get(OWNER_KEY)


@contextlib.contextmanager
def session_owner_scope(session: Session, owner_id: str) -> Iterator[str]:
    """Temporarily bind a session to an owner."""
    if not owner_id:
        raise OwnerScopeError("session_owner_scope requires a non-empty owner id")
    previous_owner = session.info.get(OWNER_KEY)
    previous_system = session.info.get(SYSTEM_KEY)
    session.info[OWNER_KEY] = owner_id
    session.info.pop(SYSTEM_KEY, None)
    try:
        yield owner_id
    finally:
        _restore(session, previous_owner, previous_system)


@contextlib.contextmanager
def session_system_scope(session: Session, reason: str) -> Iterator[None]:
    """Run unscoped queries on this session.

    Reserved for genuinely cross-owner machinery: resolving a bearer token
    before the owner is known, migrations, integrity verification, seeding.
    ``reason`` is required so these sites are greppable.
    """
    if not reason:
        raise OwnerScopeError("session_system_scope requires a stated reason")
    previous_owner = session.info.get(OWNER_KEY)
    previous_system = session.info.get(SYSTEM_KEY)
    session.info[SYSTEM_KEY] = True
    session.info.pop(OWNER_KEY, None)
    try:
        yield
    finally:
        _restore(session, previous_owner, previous_system)


def _restore(session: Session, owner, system) -> None:
    if owner is None:
        session.info.pop(OWNER_KEY, None)
    else:
        session.info[OWNER_KEY] = owner
    if system is None:
        session.info.pop(SYSTEM_KEY, None)
    else:
        session.info[SYSTEM_KEY] = system


# ---------------------------------------------------------------------------
# Context-variable scope (CLI, tests, background jobs)
# ---------------------------------------------------------------------------


def current_owner_id() -> str | None:
    return _current_owner.get()


def require_owner_id() -> str:
    owner = _current_owner.get()
    if owner is None:
        raise OwnerScopeError("no owner scope active")
    return owner


def in_system_scope() -> bool:
    return _system_scope.get()


@contextlib.contextmanager
def owner_scope(owner_id: str) -> Iterator[str]:
    """Bind ORM reads in this execution context to a single owner."""
    if not owner_id:
        raise OwnerScopeError("owner_scope requires a non-empty owner id")
    token = _current_owner.set(owner_id)
    sys_token = _system_scope.set(False)
    try:
        yield owner_id
    finally:
        _current_owner.reset(token)
        _system_scope.reset(sys_token)


@contextlib.contextmanager
def system_scope(reason: str) -> Iterator[None]:
    """Run without an owner predicate in this execution context."""
    if not reason:
        raise OwnerScopeError("system_scope requires a stated reason")
    token = _system_scope.set(True)
    owner_token = _current_owner.set(None)
    try:
        yield
    finally:
        _system_scope.reset(token)
        _current_owner.reset(owner_token)


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


def install_owner_guard(mixin_class: type) -> None:
    """Attach the global SELECT filter for ``mixin_class`` subclasses."""

    @event.listens_for(Session, "do_orm_execute")
    def _apply_owner_criteria(execute_state):  # pragma: no cover - exercised everywhere
        if not execute_state.is_select:
            return
        # Lazy and relationship loads inherit the parent query's criteria;
        # filtering again here would break eager loading.
        if execute_state.is_column_load or execute_state.is_relationship_load:
            return
        if execute_state.execution_options.get("mybot_unscoped", False):
            return

        info = getattr(execute_state.session, "info", {}) or {}
        if info.get(SYSTEM_KEY) or _system_scope.get():
            return

        owner = info.get(OWNER_KEY) or _current_owner.get()
        if owner is None:
            # Fail closed. A query for owned data with no owner bound is a
            # bug, and returning everything would be the worst possible
            # interpretation of it.
            if _statement_touches_owned(execute_state, mixin_class):
                raise OwnerScopeError(
                    "attempted to read owner-scoped data with no owner scope active; "
                    "bind the session with bind_owner()/session_owner_scope(), or state "
                    "a reason with session_system_scope()"
                )
            return

        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                mixin_class,
                lambda cls: cls.owner_id == owner,
                include_aliases=True,
            )
        )


def _statement_touches_owned(execute_state, mixin_class: type) -> bool:
    """Best-effort detection of owned models in an unscoped statement."""
    try:
        for desc in execute_state.statement.column_descriptions:
            entity = desc.get("entity")
            if entity is not None and isinstance(entity, type) and issubclass(entity, mixin_class):
                return True
    except Exception:  # pragma: no cover - defensive
        return True
    return False


__all__ = [
    "CrossOwnerAccess",
    "OWNER_KEY",
    "OwnerScopeError",
    "SYSTEM_KEY",
    "bind_owner",
    "bound_owner",
    "current_owner_id",
    "in_system_scope",
    "install_owner_guard",
    "owner_scope",
    "require_owner_id",
    "session_owner_scope",
    "session_system_scope",
    "system_scope",
]
