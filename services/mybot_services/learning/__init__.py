"""Per-owner learning: the part of MyBot that becomes somebody's own."""

from .kinds import (
    FORBIDDEN_SURFACES,
    LEARNABLE,
    LearnableKind,
    LearningBoundaryViolation,
    assert_never_authority,
)
from .service import APPLY_THRESHOLD, HALF_LIFE_DAYS, LearningService

__all__ = [
    "APPLY_THRESHOLD",
    "FORBIDDEN_SURFACES",
    "HALF_LIFE_DAYS",
    "LEARNABLE",
    "LearnableKind",
    "LearningBoundaryViolation",
    "LearningService",
    "assert_never_authority",
]
