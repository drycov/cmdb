from __future__ import annotations

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address,IPv6Address, IPv4Interface, IPv4Network, IPv6Interface, IPv6Network
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LinkLayer(str, Enum):
    PHYSICAL = "physical"
    L2 = "l2"
    L3 = "l3"
    VLAN = "vlan"
    WIRELESS = "wireless"


class DeviceRole(str, Enum):
    UNKNOWN = "unknown"
    ACCESS_EDGE = "access_edge"
    DISTRIBUTION = "distribution"
    AGGREGATION = "aggregation"
    CORE = "core"
    TRANSIT = "transit"
    CPE = "cpe"
    ONU = "onu"
    CAMERA_EDGE = "camera_edge"
    WIRELESS_AP = "wireless_ap"
    RADIO_BACKHAUL = "radio_backhaul"
    MANAGEMENT_ROUTER = "management_router"


class InterfaceRole(str, Enum):
    UNKNOWN = "unknown"
    ACCESS = "access"
    TRUNK = "trunk"
    ROUTED = "routed"
    TRANSIT = "transit"
    LOOPBACK = "loopback"
    MGMT = "mgmt"
    WIRELESS = "wireless"


class EntityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False, populate_by_name=True)


class SnapshotMetadata(EntityModel):
    snapshot_id: UUID = Field(default_factory=uuid4)
    scope: str = "global"
    started_at: datetime
    completed_at: datetime | None = None
    collector_version: str = "legacy-bridge"
    parser_version: str = "legacy-bridge"
    status: str = "scheduled"
    tags: dict[str, str] = Field(default_factory=dict)


class InterfaceCounters(EntityModel):
    rx_bps: float | None = None
    tx_bps: float | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    rx_discards: int | None = None
    tx_discards: int | None = None
    mac_count: int | None = None


class Optic(EntityModel):
    optic_id: UUID = Field(default_factory=uuid4)
    interface_name: str
    vendor: str | None = None
    serial: str | None = None
    wavelength_nm: int | None = None
    temperature_c: float | None = None
    tx_power_dbm: float | None = None
    rx_power_dbm: float | None = None
    voltage_v: float | None = None
    current_ma: float | None = None
    health_score: float | None = None


class Interface(EntityModel):
    interface_id: UUID = Field(default_factory=uuid4)
    device_id: UUID
    name: str
    display_name: str | None = None
    mac_address: str | None = None
    admin_up: bool | None = None
    oper_up: bool | None = None
    mtu: int | None = None
    speed_mbps: int | None = None
    duplex: str | None = None
    comment: str | None = None
    bridge_name: str | None = None
    role: InterfaceRole = InterfaceRole.UNKNOWN
    pvid: int | None = None
    native_vlan: int | None = None
    tagged_vlans: list[int] = Field(default_factory=list)
    untagged_vlans: list[int] = Field(default_factory=list)
    connected_mac_count: int | None = None
    vendor_hints: list[str] = Field(default_factory=list)
    counters: InterfaceCounters | None = None
    optic: Optic | None = None


class Bridge(EntityModel):
    bridge_id: UUID = Field(default_factory=uuid4)
    device_id: UUID
    name: str
    protocol_mode: str | None = None
    vlan_filtering: bool | None = None
    igmp_snooping: bool | None = None
    priority: int | None = None
    root_bridge: bool | None = None
    port_names: list[str] = Field(default_factory=list)


class VLAN(EntityModel):
    vlan_id: int
    name: str | None = None
    bridge_name: str | None = None
    tagged_interfaces: list[str] = Field(default_factory=list)
    untagged_interfaces: list[str] = Field(default_factory=list)
    svi_interfaces: list[str] = Field(default_factory=list)
    local_significance: str | None = None


class Neighbor(EntityModel):
    neighbor_id: UUID = Field(default_factory=uuid4)
    device_id: UUID
    local_interface: str
    protocol: str
    remote_identity: str | None = None
    remote_interface: str | None = None
    remote_ip: IPv4Address | IPv6Address | None = None
    remote_mac: str | None = None
    remote_vendor: str | None = None
    capability: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class Route(EntityModel):
    route_id: UUID = Field(default_factory=uuid4)
    device_id: UUID
    destination: IPv4Network | IPv6Network | None = None
    gateway: str | None = None
    protocol: str | None = None
    distance: int | None = None
    is_default: bool = False
    dynamic: bool = False
    disabled: bool = False


class OSPFNeighbor(EntityModel):
    ospf_neighbor_id: UUID = Field(default_factory=uuid4)
    device_id: UUID
    router_id: str | None = None
    address: IPv4Address | None = None
    state: str | None = None
    interface_name: str | None = None
    dr_address: IPv4Address | None = None
    bdr_address: IPv4Address | None = None
    state_changes: int | None = None


class DeviceCapabilities(EntityModel):
    hardware_offload: bool | None = None
    switch_chip: str | None = None
    supports_vlan_filtering: bool | None = None
    supports_lldp: bool | None = None
    supports_optics_monitoring: bool | None = None
    supports_wireless: bool | None = None
    supports_ospf: bool | None = None


class Device(EntityModel):
    device_id: UUID = Field(default_factory=uuid4)
    identity: str
    management_ip: IPv4Address | None = None
    site_code: str | None = None
    role: DeviceRole = DeviceRole.UNKNOWN
    vendor: str = "MikroTik"
    model: str | None = None
    board_name: str | None = None
    serial: str | None = None
    ros_version: str | None = None
    platform: str | None = None
    architecture: str | None = None
    license_level: str | None = None
    uptime: str | None = None
    interface_count: int | None = None
    primary_mac: str | None = None
    capabilities: DeviceCapabilities = Field(default_factory=DeviceCapabilities)
    labels: dict[str, str] = Field(default_factory=dict)
    interfaces: list[Interface] = Field(default_factory=list)
    bridges: list[Bridge] = Field(default_factory=list)
    vlans: list[VLAN] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    ospf_neighbors: list[OSPFNeighbor] = Field(default_factory=list)
    neighbors: list[Neighbor] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class NetworkSegment(EntityModel):
    segment_id: UUID = Field(default_factory=uuid4)
    name: str
    cidr: IPv4Network | None = None
    vlan_ids: list[int] = Field(default_factory=list)
    device_ids: list[UUID] = Field(default_factory=list)


class BroadcastDomain(EntityModel):
    broadcast_domain_id: UUID = Field(default_factory=uuid4)
    name: str
    vlan_id: int | None = None
    bridge_names: list[str] = Field(default_factory=list)
    device_ids: list[UUID] = Field(default_factory=list)
    interface_refs: list[str] = Field(default_factory=list)
    mac_count: int = 0
    risk_score: float = 0.0


class TopologyLink(EntityModel):
    link_id: UUID = Field(default_factory=uuid4)
    layer: LinkLayer
    source_device_id: UUID
    source_interface: str
    target_device_id: UUID | None = None
    target_interface: str | None = None
    relation: str
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WirelessLink(EntityModel):
    wireless_link_id: UUID = Field(default_factory=uuid4)
    source_device_id: UUID
    source_interface: str
    remote_mac: str
    remote_name: str | None = None
    signal_dbm: float | None = None
    tx_ccq: float | None = None
    rx_ccq: float | None = None
    distance_km: float | None = None


class VLANPropagation(EntityModel):
    propagation_id: UUID = Field(default_factory=uuid4)
    vlan_id: int
    source_device_id: UUID
    source_interface: str
    target_device_id: UUID | None = None
    target_interface: str | None = None
    tagged: bool
    native: bool = False
    evidence: list[str] = Field(default_factory=list)


class Ring(EntityModel):
    ring_id: UUID = Field(default_factory=uuid4)
    node_device_ids: list[UUID] = Field(default_factory=list)
    edge_link_ids: list[UUID] = Field(default_factory=list)
    protocol: str | None = None
    blocked_edge_link_id: UUID | None = None
    risk_score: float = 0.0


class Recommendation(EntityModel):
    recommendation_id: UUID = Field(default_factory=uuid4)
    title: str
    summary: str
    action_type: str
    target_entity_ids: list[UUID] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class Risk(EntityModel):
    risk_id: UUID = Field(default_factory=uuid4)
    rule_id: str
    title: str
    summary: str
    severity: Severity
    confidence: float
    impacted_entity_ids: list[UUID] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    recommendation_ids: list[UUID] = Field(default_factory=list)


class RemediationStep(EntityModel):
    step_id: UUID = Field(default_factory=uuid4)
    title: str
    routeros_commands: list[str] = Field(default_factory=list)
    validation_checks: list[str] = Field(default_factory=list)
    rollback_hints: list[str] = Field(default_factory=list)


class RemediationPlan(EntityModel):
    plan_id: UUID = Field(default_factory=uuid4)
    snapshot_id: UUID
    summary: str
    targeted_risk_ids: list[UUID] = Field(default_factory=list)
    steps: list[RemediationStep] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class NetworkSnapshot(EntityModel):
    metadata: SnapshotMetadata
    devices: list[Device] = Field(default_factory=list)
    network_segments: list[NetworkSegment] = Field(default_factory=list)
    broadcast_domains: list[BroadcastDomain] = Field(default_factory=list)
    topology_links: list[TopologyLink] = Field(default_factory=list)
    wireless_links: list[WirelessLink] = Field(default_factory=list)
    vlan_propagations: list[VLANPropagation] = Field(default_factory=list)
    rings: list[Ring] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    remediation_plans: list[RemediationPlan] = Field(default_factory=list)
