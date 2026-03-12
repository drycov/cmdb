from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Credentials:
    username: str
    password: str