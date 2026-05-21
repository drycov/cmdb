from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SnapshotCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: Literal["global", "site", "device_set"] = "global"
    site_ids: list[UUID] = Field(default_factory=list)
    device_ids: list[UUID] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    collect_now: bool = True
    max_targets: int | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class SnapshotSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: UUID
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    device_count: int = 0
    risk_count: int = 0
    link_count: int = 0


class SnapshotDetailResponse(SnapshotSummaryResponse):
    scope: str
    collector_version: str
    parser_version: str
    tags: dict[str, str] = Field(default_factory=dict)


class SnapshotJobResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: UUID
    status: str
    accepted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeviceSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: UUID
    snapshot_id: UUID
    identity: str
    management_ip: str | None = None
    role: str
    vendor: str
    model: str | None = None
    board_name: str | None = None
    ros_version: str | None = None
    platform: str | None = None
    architecture: str | None = None


class InterfaceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface_id: UUID
    name: str
    role: str
    mac_address: str | None = None
    admin_up: bool | None = None
    oper_up: bool | None = None
    mtu: int | None = None
    speed_mbps: int | None = None
    duplex: str | None = None
    bridge_name: str | None = None
    pvid: int | None = None
    native_vlan: int | None = None
    tagged_vlans: list[int] = Field(default_factory=list)
    untagged_vlans: list[int] = Field(default_factory=list)


class VlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vlan_id: int
    name: str | None = None
    bridge_name: str | None = None
    tagged_interfaces: list[str] = Field(default_factory=list)
    untagged_interfaces: list[str] = Field(default_factory=list)
    svi_interfaces: list[str] = Field(default_factory=list)


class RouteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_id: UUID
    destination: str | None = None
    gateway: str | None = None
    protocol: str | None = None
    distance: int | None = None
    is_default: bool = False
    dynamic: bool = False
    disabled: bool = False


class BridgeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bridge_id: UUID
    name: str
    protocol_mode: str | None = None
    vlan_filtering: bool | None = None
    igmp_snooping: bool | None = None
    port_names: list[str] = Field(default_factory=list)


class NeighborResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    neighbor_id: UUID
    local_interface: str
    protocol: str
    remote_identity: str | None = None
    remote_interface: str | None = None
    remote_ip: str | None = None
    remote_mac: str | None = None
    confidence: float = 0.0


class OspfNeighborResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ospf_neighbor_id: UUID
    router_id: str | None = None
    address: str | None = None
    state: str | None = None
    interface_name: str | None = None
    dr_address: str | None = None
    bdr_address: str | None = None
    state_changes: int | None = None


class DeviceDetailResponse(DeviceSummaryResponse):
    interfaces: list[InterfaceResponse] = Field(default_factory=list)
    vlans: list[VlanResponse] = Field(default_factory=list)
    routes: list[RouteResponse] = Field(default_factory=list)
    bridges: list[BridgeResponse] = Field(default_factory=list)
    neighbors: list[NeighborResponse] = Field(default_factory=list)
    ospf_neighbors: list[OspfNeighborResponse] = Field(default_factory=list)


class TopologyGraphNodeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: UUID
    identity: str
    management_ip: str | None = None
    role: str
    vendor: str
    model: str | None = None


class TopologyGraphEdgeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    link_id: UUID
    layer: str
    source_device_id: UUID
    source_interface: str
    target_device_id: UUID | None = None
    target_interface: str | None = None
    relation: str
    confidence: float


class TopologyGraphResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: UUID
    nodes: list[TopologyGraphNodeResponse] = Field(default_factory=list)
    edges: list[TopologyGraphEdgeResponse] = Field(default_factory=list)


class BroadcastDomainResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    broadcast_domain_id: UUID
    name: str
    vlan_id: int | None = None
    bridge_names: list[str] = Field(default_factory=list)
    device_ids: list[UUID] = Field(default_factory=list)
    interface_refs: list[str] = Field(default_factory=list)
    mac_count: int
    risk_score: float


class VlanPropagationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    propagation_id: UUID
    vlan_id: int
    source_device_id: UUID
    source_interface: str
    target_device_id: UUID | None = None
    target_interface: str | None = None
    tagged: bool
    native: bool
    evidence: list[str] = Field(default_factory=list)


class RiskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_id: UUID
    rule_id: str
    severity: str
    title: str
    summary: str
    confidence: float
    impacted_entity_ids: list[UUID] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class RecommendationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_id: UUID
    title: str
    summary: str
    action_type: str
    target_entity_ids: list[UUID] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class RemediationStepResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: UUID
    title: str
    routeros_commands: list[str] = Field(default_factory=list)
    validation_checks: list[str] = Field(default_factory=list)
    rollback_hints: list[str] = Field(default_factory=list)


class RemediationPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: UUID
    risk_ids: list[UUID] = Field(default_factory=list)
    recommendation_ids: list[UUID] = Field(default_factory=list)


class RemediationPlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: UUID
    snapshot_id: UUID
    summary: str
    targeted_risk_ids: list[UUID] = Field(default_factory=list)
    steps: list[RemediationStepResponse] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RawEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_address: str
    command: str
    collected_at: datetime
    payload: str
    duration_ms: int | None = None
    parser_name: str | None = None
    parser_version: str | None = None
    warning: str | None = None
