"""Implementation details for constants auth_methods."""

from enum import StrEnum


class AuthMethod(StrEnum):
    """Represent authmethod."""
    PRIMARY = "primary"
    FALLBACK = "fallback"