"""Implementation details for sot pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from .domain import NetworkSnapshot, SnapshotMetadata


@dataclass(slots=True)
class RawCommandPayload:
    """Represent rawcommandpayload."""
    device_address: str
    command: str
    collected_at: datetime
    payload: str
    duration_ms: int | None = None
    parser_name: str | None = None
    parser_version: str | None = None
    warning: str | None = None


@dataclass(slots=True)
class PipelineContext:
    """Represent pipelinecontext."""
    snapshot_id: UUID
    scope: str
    started_at: datetime
    requested_by: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    raw_payloads: list[RawCommandPayload] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> SnapshotMetadata:
        return SnapshotMetadata(
            snapshot_id=self.snapshot_id,
            scope=self.scope,
            started_at=self.started_at,
            tags=self.tags,
            status="running",
        )


@dataclass(slots=True)
class StageResult:
    """Represent the stageresult payload."""
    snapshot: NetworkSnapshot | None = None
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)
