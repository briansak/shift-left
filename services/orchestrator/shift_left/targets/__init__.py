"""Managed targets — device-centric NetSecOps configuration."""

from shift_left.targets.registry import ManagedTargetRegistry
from shift_left.targets.validation import (
    ManagedTargetConfigError,
    validate_managed_targets,
)

__all__ = [
    "ManagedTargetConfigError",
    "ManagedTargetRegistry",
    "validate_managed_targets",
]
