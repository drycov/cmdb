"""Implementation details for platform_api orm."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

class SnapshotRecord(Base):
    """Represent snapshotrecord."""
    __tablename__ = "snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="global")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="scheduled")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collector_version: Mapped[str] = mapped_column(String(64), nullable=False, default="legacy-bridge")
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False, default="legacy-bridge")
    tags: Mapped[dict[str, str]] = mapped_column(JSON(), nullable=False, default=dict)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    link_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RawCommandPayloadRecord(Base):
    """Represent rawcommandpayloadrecord."""
    __tablename__ = "raw_command_payloads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_address: Mapped[str] = mapped_column(String(64), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parser_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    warning: Mapped[str | None] = mapped_column(Text, nullable=True)


class SnapshotDeviceRecord(Base):
    """Represent snapshotdevicerecord."""
    __tablename__ = "snapshot_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    identity: Mapped[str] = mapped_column(String(255), nullable=False)
    management_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    vendor: Mapped[str] = mapped_column(String(64), nullable=False, default="MikroTik")
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    board_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ros_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(128), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotInterfaceRecord(Base):
    """Represent snapshotinterfacerecord."""
    __tablename__ = "snapshot_interfaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    interface_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    admin_up: Mapped[int | None] = mapped_column(Integer, nullable=True)
    oper_up: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mtu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    speed_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duplex: Mapped[str | None] = mapped_column(String(32), nullable=True)
    bridge_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pvid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    native_vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotVlanRecord(Base):
    """Represent snapshotvlanrecord."""
    __tablename__ = "snapshot_vlans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    bridge_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotRouteRecord(Base):
    """Represent snapshotrouterecord."""
    __tablename__ = "snapshot_routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    route_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    destination: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway: Mapped[str | None] = mapped_column(String(255), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(64), nullable=True)
    distance: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_default: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dynamic: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disabled: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotBridgeRecord(Base):
    """Represent snapshotbridgerecord."""
    __tablename__ = "snapshot_bridges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    bridge_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    protocol_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vlan_filtering: Mapped[int | None] = mapped_column(Integer, nullable=True)
    igmp_snooping: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotNeighborRecord(Base):
    """Represent snapshotneighborrecord."""
    __tablename__ = "snapshot_neighbors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    neighbor_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    local_interface: Mapped[str] = mapped_column(String(255), nullable=False)
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    remote_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remote_interface: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remote_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_mac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotOspfNeighborRecord(Base):
    """Represent snapshotospfneighborrecord."""
    __tablename__ = "snapshot_ospf_neighbors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    ospf_neighbor_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    router_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    interface_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state_changes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotTopologyLinkRecord(Base):
    """Represent snapshottopologylinkrecord."""
    __tablename__ = "snapshot_topology_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    link_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    layer: Mapped[str] = mapped_column(String(32), nullable=False)
    source_device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    source_interface: Mapped[str] = mapped_column(String(255), nullable=False)
    target_device_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    target_interface: Mapped[str | None] = mapped_column(String(255), nullable=True)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotBroadcastDomainRecord(Base):
    """Represent snapshotbroadcastdomainrecord."""
    __tablename__ = "snapshot_broadcast_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    broadcast_domain_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    mac_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotVlanPropagationRecord(Base):
    """Represent snapshotvlanpropagationrecord."""
    __tablename__ = "snapshot_vlan_propagations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    propagation_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    source_device_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    source_interface: Mapped[str] = mapped_column(String(255), nullable=False)
    target_device_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    target_interface: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tagged: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    native: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotRiskRecord(Base):
    """Represent snapshotriskrecord."""
    __tablename__ = "snapshot_risks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    risk_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class SnapshotRecommendationRecord(Base):
    """Represent snapshotrecommendationrecord."""
    __tablename__ = "snapshot_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    recommendation_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)


class RemediationPlanRecord(Base):
    """Represent remediationplanrecord."""
    __tablename__ = "remediation_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON(), nullable=False, default=dict)
