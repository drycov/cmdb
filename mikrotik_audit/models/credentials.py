"""Implementation details for models credentials."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Credentials:
    """Represent credentials."""
    username: str
    password: str