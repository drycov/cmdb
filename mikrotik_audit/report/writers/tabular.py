"""Implementation details for report writers tabular."""

from __future__ import annotations

from typing import Any, Iterable


def merge_headers(existing_headers: Iterable[str], new_headers: Iterable[str]) -> list[str]:
    """Handle merge headers."""
    merged = list(existing_headers)
    for header in new_headers:
        if header not in merged:
            merged.append(header)
    return merged


def project_row(headers: list[str], row: dict[str, Any]) -> list[Any]:
    """Handle project row."""
    return [row.get(header, "") for header in headers]
