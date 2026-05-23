"""Implementation details for platform_api repositories."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from mikrotik_audit.sot.domain import (
    BroadcastDomain,
    Bridge,
    Device,
    Interface,
    Neighbor,
    NetworkSnapshot,
    OSPFNeighbor,
    Recommendation,
    RemediationPlan,
    Risk,
    Route,
    SnapshotMetadata,
    TopologyLink,
    VLAN,
    VLANPropagation,
)
from mikrotik_audit.sot.pipeline import RawCommandPayload
from mikrotik_audit.sot.repositories import (
    DeviceRepository,
    EvidenceRepository,
    L2Repository,
    RecommendationRepository,
    RemediationRepository,
    RiskRepository,
    SnapshotRepository,
    TopologyRepository,
)

from .orm import (
    RawCommandPayloadRecord,
    SnapshotBridgeRecord,
    SnapshotBroadcastDomainRecord,
    SnapshotDeviceRecord,
    SnapshotInterfaceRecord,
    SnapshotNeighborRecord,
    SnapshotOspfNeighborRecord,
    SnapshotRecommendationRecord,
    SnapshotRecord,
    SnapshotRiskRecord,
    SnapshotRouteRecord,
    SnapshotTopologyLinkRecord,
    SnapshotVlanPropagationRecord,
    SnapshotVlanRecord,
    RemediationPlanRecord,
)


class SqlAlchemySnapshotRepository(SnapshotRepository):
    """Persist data through the sqlalchemysnapshotrepository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_snapshot(self, snapshot: NetworkSnapshot) -> None:
        metadata = snapshot.metadata
        self.session.add(
            SnapshotRecord(
                snapshot_id=str(metadata.snapshot_id),
                scope=metadata.scope,
                status=metadata.status,
                started_at=metadata.started_at,
                completed_at=metadata.completed_at,
                collector_version=metadata.collector_version,
                parser_version=metadata.parser_version,
                tags=metadata.tags,
                device_count=len(snapshot.devices),
                risk_count=len(snapshot.risks),
                link_count=len(snapshot.topology_links),
            )
        )
        await self.session.commit()

    async def get_snapshot(self, snapshot_id: UUID) -> NetworkSnapshot | None:
        record = await self.session.get(SnapshotRecord, str(snapshot_id))
        if record is None:
            return None
        return NetworkSnapshot(metadata=_metadata_from_record(record))

    async def mark_completed(self, snapshot_id: UUID) -> None:
        record = await self.session.get(SnapshotRecord, str(snapshot_id))
        if record is None:
            return
        record.status = "completed"
        if record.completed_at is None:
            from datetime import datetime, timezone

            record.completed_at = datetime.now(timezone.utc)
        await self.session.commit()

    async def update_snapshot_counts(self, snapshot: NetworkSnapshot) -> None:
        record = await self.session.get(SnapshotRecord, str(snapshot.metadata.snapshot_id))
        if record is None:
            return
        record.device_count = len(snapshot.devices)
        record.risk_count = len(snapshot.risks)
        record.link_count = len(snapshot.topology_links)
        record.status = snapshot.metadata.status
        record.completed_at = snapshot.metadata.completed_at
        await self.session.commit()

    async def list_snapshots(self) -> list[NetworkSnapshot]:
        result = await self.session.execute(select(SnapshotRecord).order_by(SnapshotRecord.started_at.desc()))
        return [NetworkSnapshot(metadata=_metadata_from_record(row)) for row in result.scalars()]


class SqlAlchemyEvidenceRepository(EvidenceRepository):
    """Persist data through the sqlalchemyevidencerepository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def append_raw_payloads(self, snapshot_id: UUID, payloads: list[RawCommandPayload]) -> None:
        if not payloads:
            return
        self.session.add_all(
            [
                RawCommandPayloadRecord(
                    snapshot_id=str(snapshot_id),
                    device_address=item.device_address,
                    command=item.command,
                    collected_at=item.collected_at,
                    payload=item.payload,
                    duration_ms=item.duration_ms,
                    parser_name=item.parser_name,
                    parser_version=item.parser_version,
                    warning=item.warning,
                )
                for item in payloads
            ]
        )
        await self.session.commit()

    async def list_raw_payloads(self, snapshot_id: UUID) -> list[RawCommandPayload]:
        result = await self.session.execute(
            select(RawCommandPayloadRecord).where(
                RawCommandPayloadRecord.snapshot_id == str(snapshot_id)
            )
        )
        return [
            RawCommandPayload(
                device_address=row.device_address,
                command=row.command,
                collected_at=row.collected_at,
                payload=row.payload,
                duration_ms=row.duration_ms,
                parser_name=row.parser_name,
                parser_version=row.parser_version,
                warning=row.warning,
            )
            for row in result.scalars()
        ]


class SqlAlchemyDeviceRepository(DeviceRepository):
    """Persist data through the sqlalchemydevicerepository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert_devices(self, snapshot_id: UUID, devices: list[Device]) -> None:
        await self.session.execute(
            delete(SnapshotDeviceRecord).where(SnapshotDeviceRecord.snapshot_id == str(snapshot_id))
        )
        await self.session.execute(
            delete(SnapshotInterfaceRecord).where(SnapshotInterfaceRecord.snapshot_id == str(snapshot_id))
        )
        await self.session.execute(
            delete(SnapshotVlanRecord).where(SnapshotVlanRecord.snapshot_id == str(snapshot_id))
        )
        await self.session.execute(
            delete(SnapshotRouteRecord).where(SnapshotRouteRecord.snapshot_id == str(snapshot_id))
        )
        await self.session.execute(
            delete(SnapshotBridgeRecord).where(SnapshotBridgeRecord.snapshot_id == str(snapshot_id))
        )
        await self.session.execute(
            delete(SnapshotNeighborRecord).where(SnapshotNeighborRecord.snapshot_id == str(snapshot_id))
        )
        await self.session.execute(
            delete(SnapshotOspfNeighborRecord).where(SnapshotOspfNeighborRecord.snapshot_id == str(snapshot_id))
        )
        self.session.add_all(
            [
                SnapshotDeviceRecord(
                    snapshot_id=str(snapshot_id),
                    device_id=str(device.device_id),
                    identity=device.identity,
                    management_ip=str(device.management_ip) if device.management_ip else None,
                    role=device.role.value,
                    vendor=device.vendor,
                    model=device.model,
                    board_name=device.board_name,
                    ros_version=device.ros_version,
                    platform=device.platform,
                    architecture=device.architecture,
                    payload=device.model_dump(mode="json"),
                )
                for device in devices
            ]
        )
        self.session.add_all(
            [
                SnapshotInterfaceRecord(
                    snapshot_id=str(snapshot_id),
                    device_id=str(device.device_id),
                    interface_id=str(interface.interface_id),
                    name=interface.name,
                    role=interface.role.value,
                    mac_address=interface.mac_address,
                    admin_up=_bool_to_int(interface.admin_up),
                    oper_up=_bool_to_int(interface.oper_up),
                    mtu=interface.mtu,
                    speed_mbps=interface.speed_mbps,
                    duplex=interface.duplex,
                    bridge_name=interface.bridge_name,
                    pvid=interface.pvid,
                    native_vlan=interface.native_vlan,
                    payload=interface.model_dump(mode="json"),
                )
                for device in devices
                for interface in device.interfaces
            ]
        )
        self.session.add_all(
            [
                SnapshotVlanRecord(
                    snapshot_id=str(snapshot_id),
                    device_id=str(device.device_id),
                    vlan_id=vlan.vlan_id,
                    name=vlan.name,
                    bridge_name=vlan.bridge_name,
                    payload=vlan.model_dump(mode="json"),
                )
                for device in devices
                for vlan in device.vlans
            ]
        )
        self.session.add_all(
            [
                SnapshotRouteRecord(
                    snapshot_id=str(snapshot_id),
                    device_id=str(device.device_id),
                    route_id=str(route.route_id),
                    destination=str(route.destination) if route.destination else None,
                    gateway=route.gateway,
                    protocol=route.protocol,
                    distance=route.distance,
                    is_default=_bool_to_int(route.is_default) or 0,
                    dynamic=_bool_to_int(route.dynamic) or 0,
                    disabled=_bool_to_int(route.disabled) or 0,
                    payload=route.model_dump(mode="json"),
                )
                for device in devices
                for route in device.routes
            ]
        )
        self.session.add_all(
            [
                SnapshotBridgeRecord(
                    snapshot_id=str(snapshot_id),
                    device_id=str(device.device_id),
                    bridge_id=str(bridge.bridge_id),
                    name=bridge.name,
                    protocol_mode=bridge.protocol_mode,
                    vlan_filtering=_bool_to_int(bridge.vlan_filtering),
                    igmp_snooping=_bool_to_int(bridge.igmp_snooping),
                    payload=bridge.model_dump(mode="json"),
                )
                for device in devices
                for bridge in device.bridges
            ]
        )
        self.session.add_all(
            [
                SnapshotNeighborRecord(
                    snapshot_id=str(snapshot_id),
                    device_id=str(device.device_id),
                    neighbor_id=str(neighbor.neighbor_id),
                    local_interface=neighbor.local_interface,
                    protocol=neighbor.protocol,
                    remote_identity=neighbor.remote_identity,
                    remote_interface=neighbor.remote_interface,
                    remote_ip=str(neighbor.remote_ip) if neighbor.remote_ip else None,
                    remote_mac=neighbor.remote_mac,
                    confidence=neighbor.confidence,
                    payload=neighbor.model_dump(mode="json"),
                )
                for device in devices
                for neighbor in device.neighbors
            ]
        )
        self.session.add_all(
            [
                SnapshotOspfNeighborRecord(
                    snapshot_id=str(snapshot_id),
                    device_id=str(device.device_id),
                    ospf_neighbor_id=str(neighbor.ospf_neighbor_id),
                    router_id=neighbor.router_id,
                    address=str(neighbor.address) if neighbor.address else None,
                    state=neighbor.state,
                    interface_name=neighbor.interface_name,
                    state_changes=neighbor.state_changes,
                    payload=neighbor.model_dump(mode="json"),
                )
                for device in devices
                for neighbor in device.ospf_neighbors
            ]
        )
        await self.session.commit()

    async def list_devices(self, snapshot_id: UUID) -> list[Device]:
        result = await self.session.execute(
            select(SnapshotDeviceRecord).where(SnapshotDeviceRecord.snapshot_id == str(snapshot_id))
        )
        records = result.scalars().all()
        return [Device.model_validate(record.payload) for record in records]

    async def get_device(self, snapshot_id: UUID, device_id: UUID) -> Device | None:
        device_record = await self.session.scalar(
            select(SnapshotDeviceRecord).where(
                SnapshotDeviceRecord.snapshot_id == str(snapshot_id),
                SnapshotDeviceRecord.device_id == str(device_id),
            )
        )
        if device_record is None:
            return None

        device = Device.model_validate(device_record.payload)

        interface_rows = await self.session.execute(
            select(SnapshotInterfaceRecord).where(
                SnapshotInterfaceRecord.snapshot_id == str(snapshot_id),
                SnapshotInterfaceRecord.device_id == str(device_id),
            )
        )
        vlan_rows = await self.session.execute(
            select(SnapshotVlanRecord).where(
                SnapshotVlanRecord.snapshot_id == str(snapshot_id),
                SnapshotVlanRecord.device_id == str(device_id),
            )
        )
        route_rows = await self.session.execute(
            select(SnapshotRouteRecord).where(
                SnapshotRouteRecord.snapshot_id == str(snapshot_id),
                SnapshotRouteRecord.device_id == str(device_id),
            )
        )
        bridge_rows = await self.session.execute(
            select(SnapshotBridgeRecord).where(
                SnapshotBridgeRecord.snapshot_id == str(snapshot_id),
                SnapshotBridgeRecord.device_id == str(device_id),
            )
        )
        neighbor_rows = await self.session.execute(
            select(SnapshotNeighborRecord).where(
                SnapshotNeighborRecord.snapshot_id == str(snapshot_id),
                SnapshotNeighborRecord.device_id == str(device_id),
            )
        )
        ospf_rows = await self.session.execute(
            select(SnapshotOspfNeighborRecord).where(
                SnapshotOspfNeighborRecord.snapshot_id == str(snapshot_id),
                SnapshotOspfNeighborRecord.device_id == str(device_id),
            )
        )

        device.interfaces = [Interface.model_validate(row.payload) for row in interface_rows.scalars()]
        device.vlans = [VLAN.model_validate(row.payload) for row in vlan_rows.scalars()]
        device.routes = [Route.model_validate(row.payload) for row in route_rows.scalars()]
        device.bridges = [Bridge.model_validate(row.payload) for row in bridge_rows.scalars()]
        device.neighbors = [Neighbor.model_validate(row.payload) for row in neighbor_rows.scalars()]
        device.ospf_neighbors = [OSPFNeighbor.model_validate(row.payload) for row in ospf_rows.scalars()]
        return device


class SqlAlchemyTopologyRepository(TopologyRepository):
    """Persist data through the sqlalchemytopologyrepository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_links(self, snapshot_id: UUID, links: list[TopologyLink]) -> None:
        await self.session.execute(
            delete(SnapshotTopologyLinkRecord).where(SnapshotTopologyLinkRecord.snapshot_id == str(snapshot_id))
        )
        self.session.add_all(
            [
                SnapshotTopologyLinkRecord(
                    snapshot_id=str(snapshot_id),
                    link_id=str(link.link_id),
                    layer=link.layer.value,
                    source_device_id=str(link.source_device_id),
                    source_interface=link.source_interface,
                    target_device_id=str(link.target_device_id) if link.target_device_id else None,
                    target_interface=link.target_interface,
                    relation=link.relation,
                    confidence=link.confidence,
                    payload=link.model_dump(mode="json"),
                )
                for link in links
            ]
        )
        await self.session.commit()

    async def list_links(self, snapshot_id: UUID) -> list[TopologyLink]:
        result = await self.session.execute(
            select(SnapshotTopologyLinkRecord).where(
                SnapshotTopologyLinkRecord.snapshot_id == str(snapshot_id)
            )
        )
        return [TopologyLink.model_validate(row.payload) for row in result.scalars()]


class SqlAlchemyL2Repository(L2Repository):
    """Persist data through the sqlalchemyl2repository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_broadcast_domains(self, snapshot_id: UUID, domains: list[BroadcastDomain]) -> None:
        await self.session.execute(
            delete(SnapshotBroadcastDomainRecord).where(
                SnapshotBroadcastDomainRecord.snapshot_id == str(snapshot_id)
            )
        )
        self.session.add_all(
            [
                SnapshotBroadcastDomainRecord(
                    snapshot_id=str(snapshot_id),
                    broadcast_domain_id=str(domain.broadcast_domain_id),
                    name=domain.name,
                    vlan_id=domain.vlan_id,
                    mac_count=domain.mac_count,
                    risk_score=domain.risk_score,
                    payload=domain.model_dump(mode="json"),
                )
                for domain in domains
            ]
        )
        await self.session.commit()

    async def list_broadcast_domains(self, snapshot_id: UUID) -> list[BroadcastDomain]:
        result = await self.session.execute(
            select(SnapshotBroadcastDomainRecord).where(
                SnapshotBroadcastDomainRecord.snapshot_id == str(snapshot_id)
            )
        )
        return [BroadcastDomain.model_validate(row.payload) for row in result.scalars()]

    async def replace_vlan_propagations(self, snapshot_id: UUID, propagations: list[VLANPropagation]) -> None:
        await self.session.execute(
            delete(SnapshotVlanPropagationRecord).where(
                SnapshotVlanPropagationRecord.snapshot_id == str(snapshot_id)
            )
        )
        self.session.add_all(
            [
                SnapshotVlanPropagationRecord(
                    snapshot_id=str(snapshot_id),
                    propagation_id=str(item.propagation_id),
                    vlan_id=item.vlan_id,
                    source_device_id=str(item.source_device_id),
                    source_interface=item.source_interface,
                    target_device_id=str(item.target_device_id) if item.target_device_id else None,
                    target_interface=item.target_interface,
                    tagged=_bool_to_int(item.tagged) or 0,
                    native=_bool_to_int(item.native) or 0,
                    payload=item.model_dump(mode="json"),
                )
                for item in propagations
            ]
        )
        await self.session.commit()

    async def list_vlan_propagations(self, snapshot_id: UUID) -> list[VLANPropagation]:
        result = await self.session.execute(
            select(SnapshotVlanPropagationRecord).where(
                SnapshotVlanPropagationRecord.snapshot_id == str(snapshot_id)
            )
        )
        return [VLANPropagation.model_validate(row.payload) for row in result.scalars()]


class SqlAlchemyRiskRepository(RiskRepository):
    """Persist data through the sqlalchemyriskrepository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_risks(self, snapshot_id: UUID, risks: list[Risk]) -> None:
        await self.session.execute(
            delete(SnapshotRiskRecord).where(SnapshotRiskRecord.snapshot_id == str(snapshot_id))
        )
        self.session.add_all(
            [
                SnapshotRiskRecord(
                    snapshot_id=str(snapshot_id),
                    risk_id=str(risk.risk_id),
                    rule_id=risk.rule_id,
                    severity=risk.severity.value,
                    title=risk.title,
                    confidence=risk.confidence,
                    payload=risk.model_dump(mode="json"),
                )
                for risk in risks
            ]
        )
        await self.session.commit()

    async def list_risks(self, snapshot_id: UUID) -> list[Risk]:
        result = await self.session.execute(
            select(SnapshotRiskRecord).where(
                SnapshotRiskRecord.snapshot_id == str(snapshot_id)
            )
        )
        return [Risk.model_validate(row.payload) for row in result.scalars()]


class SqlAlchemyRecommendationRepository(RecommendationRepository):
    """Persist data through the sqlalchemyrecommendationrepository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_recommendations(self, snapshot_id: UUID, recommendations: list[Recommendation]) -> None:
        await self.session.execute(
            delete(SnapshotRecommendationRecord).where(
                SnapshotRecommendationRecord.snapshot_id == str(snapshot_id)
            )
        )
        self.session.add_all(
            [
                SnapshotRecommendationRecord(
                    snapshot_id=str(snapshot_id),
                    recommendation_id=str(item.recommendation_id),
                    action_type=item.action_type,
                    title=item.title,
                    payload=item.model_dump(mode="json"),
                )
                for item in recommendations
            ]
        )
        await self.session.commit()

    async def list_recommendations(self, snapshot_id: UUID) -> list[Recommendation]:
        result = await self.session.execute(
            select(SnapshotRecommendationRecord).where(
                SnapshotRecommendationRecord.snapshot_id == str(snapshot_id)
            )
        )
        return [Recommendation.model_validate(row.payload) for row in result.scalars()]


class SqlAlchemyRemediationRepository(RemediationRepository):
    """Persist data through the sqlalchemyremediationrepository repository."""
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save_plan(self, plan: RemediationPlan) -> None:
        self.session.add(
            RemediationPlanRecord(
                plan_id=str(plan.plan_id),
                snapshot_id=str(plan.snapshot_id),
                summary=plan.summary,
                payload=plan.model_dump(mode="json"),
            )
        )
        await self.session.commit()

    async def list_plans(self, snapshot_id: UUID) -> list[RemediationPlan]:
        result = await self.session.execute(
            select(RemediationPlanRecord).where(
                RemediationPlanRecord.snapshot_id == str(snapshot_id)
            )
        )
        return [RemediationPlan.model_validate(row.payload) for row in result.scalars()]


def _metadata_from_record(record: SnapshotRecord) -> SnapshotMetadata:
    """Internal helper for metadata from record."""
    return SnapshotMetadata(
        snapshot_id=UUID(str(record.snapshot_id)),
        scope=record.scope,
        started_at=record.started_at,
        completed_at=record.completed_at,
        collector_version=record.collector_version,
        parser_version=record.parser_version,
        status=record.status,
        tags=record.tags or {},
    )


def _bool_to_int(value: bool | None) -> int | None:
    """Internal helper for bool to int."""
    if value is None:
        return None
    return 1 if value else 0
