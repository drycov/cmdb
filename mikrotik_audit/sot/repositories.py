"""Implementation details for sot repositories."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from .domain import (
    BroadcastDomain,
    Device,
    NetworkSnapshot,
    Recommendation,
    RemediationPlan,
    Risk,
    TopologyLink,
    VLANPropagation,
)
from .pipeline import RawCommandPayload


class SnapshotRepository(Protocol):
    """Persist data through the snapshotrepository repository."""
    async def create_snapshot(self, snapshot: NetworkSnapshot) -> None: ...
    async def get_snapshot(self, snapshot_id: UUID) -> NetworkSnapshot | None: ...
    async def mark_completed(self, snapshot_id: UUID) -> None: ...


class EvidenceRepository(Protocol):
    """Persist data through the evidencerepository repository."""
    async def append_raw_payloads(self, snapshot_id: UUID, payloads: list[RawCommandPayload]) -> None: ...
    async def list_raw_payloads(self, snapshot_id: UUID) -> list[RawCommandPayload]: ...


class DeviceRepository(Protocol):
    """Persist data through the devicerepository repository."""
    async def upsert_devices(self, snapshot_id: UUID, devices: list[Device]) -> None: ...
    async def list_devices(self, snapshot_id: UUID) -> list[Device]: ...
    async def get_device(self, snapshot_id: UUID, device_id: UUID) -> Device | None: ...


class TopologyRepository(Protocol):
    """Persist data through the topologyrepository repository."""
    async def replace_links(self, snapshot_id: UUID, links: list[TopologyLink]) -> None: ...
    async def list_links(self, snapshot_id: UUID) -> list[TopologyLink]: ...


class L2Repository(Protocol):
    """Persist data through the l2repository repository."""
    async def replace_broadcast_domains(self, snapshot_id: UUID, domains: list[BroadcastDomain]) -> None: ...
    async def list_broadcast_domains(self, snapshot_id: UUID) -> list[BroadcastDomain]: ...
    async def replace_vlan_propagations(self, snapshot_id: UUID, propagations: list[VLANPropagation]) -> None: ...
    async def list_vlan_propagations(self, snapshot_id: UUID) -> list[VLANPropagation]: ...


class RiskRepository(Protocol):
    """Persist data through the riskrepository repository."""
    async def replace_risks(self, snapshot_id: UUID, risks: list[Risk]) -> None: ...
    async def list_risks(self, snapshot_id: UUID) -> list[Risk]: ...


class RecommendationRepository(Protocol):
    """Persist data through the recommendationrepository repository."""
    async def replace_recommendations(self, snapshot_id: UUID, recommendations: list[Recommendation]) -> None: ...
    async def list_recommendations(self, snapshot_id: UUID) -> list[Recommendation]: ...


class RemediationRepository(Protocol):
    """Persist data through the remediationrepository repository."""
    async def save_plan(self, plan: RemediationPlan) -> None: ...
    async def list_plans(self, snapshot_id: UUID) -> list[RemediationPlan]: ...
