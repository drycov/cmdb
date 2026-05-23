"""Implementation details for report writers base."""

from __future__ import annotations

from typing import Any, Protocol


class ReportWriter(Protocol):
    """Write reportwriter output."""
    def open(self) -> None: ...

    def begin_section(self, name: str, headers: list[str]) -> None: ...

    def write_row(self, section: str, row: dict[str, Any]) -> None: ...

    def close_section(self, name: str) -> None: ...

    def close(self) -> None: ...