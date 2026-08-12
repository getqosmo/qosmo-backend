"""Database plumbing: base classes, portable types, owner scoping, sessions."""

from .base import Base, Classified, OwnedMixin, Provenanced, SoftDeletable, Timestamped, UUIDPk
from .scope import (
    CrossOwnerAccess,
    OwnerScopeError,
    current_owner_id,
    owner_scope,
    require_owner_id,
    system_scope,
)
from .session import create_all, get_engine, get_session_factory, session_scope
from .types import new_uuid, utcnow

__all__ = [
    "Base",
    "Classified",
    "CrossOwnerAccess",
    "OwnedMixin",
    "OwnerScopeError",
    "Provenanced",
    "SoftDeletable",
    "Timestamped",
    "UUIDPk",
    "create_all",
    "current_owner_id",
    "get_engine",
    "get_session_factory",
    "new_uuid",
    "owner_scope",
    "require_owner_id",
    "session_scope",
    "system_scope",
    "utcnow",
]
