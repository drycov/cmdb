from __future__ import annotations

from datetime import datetime, timezone

from app_runtime import build_app
from sot.adapters import device_from_audit_result
from sot.domain import (
    BroadcastDomain,
    LinkLayer,
    NetworkSnapshot,
    Recommendation,
    RemediationPlan,
    RemediationStep,
    Risk,
    Severity,
    SnapshotMetadata,
    TopologyLink,
    VLANPropagation,
)
from sot.pipeline import RawCommandPayload
from uuid import uuid4

from .repositories import (
    SqlAlchemyDeviceRepository,
    SqlAlchemyEvidenceRepository,
    SqlAlchemyL2Repository,
    SqlAlchemyRecommendationRepository,
    SqlAlchemyRemediationRepository,
    SqlAlchemyRiskRepository,
    SqlAlchemySnapshotRepository,
    SqlAlchemyTopologyRepository,
)
from .schemas import (
    BroadcastDomainResponse,
    BridgeResponse,
    DeviceDetailResponse,
    DeviceSummaryResponse,
    InterfaceResponse,
    NeighborResponse,
    OspfNeighborResponse,
    RawEvidenceResponse,
    RecommendationResponse,
    RemediationPlanRequest,
    RemediationPlanResponse,
    RemediationStepResponse,
    RiskResponse,
    RouteResponse,
    SnapshotCreateRequest,
    TopologyGraphEdgeResponse,
    TopologyGraphNodeResponse,
    TopologyGraphResponse,
    VlanResponse,
    VlanPropagationResponse,
)


class SnapshotService:
    def __init__(
        self,
        repository: SqlAlchemySnapshotRepository,
        device_repository: SqlAlchemyDeviceRepository,
        topology_repository: SqlAlchemyTopologyRepository,
        evidence_repository: SqlAlchemyEvidenceRepository,
        l2_repository: SqlAlchemyL2Repository,
        recommendation_repository: SqlAlchemyRecommendationRepository,
        remediation_repository: SqlAlchemyRemediationRepository,
        risk_repository: SqlAlchemyRiskRepository,
    ) -> None:
        self.repository = repository
        self.device_repository = device_repository
        self.topology_repository = topology_repository
        self.evidence_repository = evidence_repository
        self.l2_repository = l2_repository
        self.recommendation_repository = recommendation_repository
        self.remediation_repository = remediation_repository
        self.risk_repository = risk_repository

    async def create_snapshot(self, request: SnapshotCreateRequest) -> NetworkSnapshot:
        metadata = SnapshotMetadata(
            snapshot_id=uuid4(),
            scope=request.scope,
            started_at=datetime.now(timezone.utc),
            status="scheduled",
            collector_version="phase1-bootstrap",
            parser_version="phase1-bootstrap",
            tags=request.tags,
        )
        snapshot = NetworkSnapshot(metadata=metadata)
        await self.repository.create_snapshot(snapshot)
        if request.collect_now:
            try:
                snapshot = await self._collect_snapshot(snapshot, request)
                await self.device_repository.upsert_devices(snapshot.metadata.snapshot_id, snapshot.devices)
                snapshot.topology_links = self._materialize_topology_links(snapshot.devices)
                await self.topology_repository.replace_links(snapshot.metadata.snapshot_id, snapshot.topology_links)
                snapshot.broadcast_domains = self._materialize_broadcast_domains(snapshot.devices)
                snapshot.vlan_propagations = self._materialize_vlan_propagations(snapshot.devices, snapshot.topology_links)
                await self.l2_repository.replace_broadcast_domains(snapshot.metadata.snapshot_id, snapshot.broadcast_domains)
                await self.l2_repository.replace_vlan_propagations(snapshot.metadata.snapshot_id, snapshot.vlan_propagations)
                snapshot.risks = self._materialize_risks(snapshot)
                await self.risk_repository.replace_risks(snapshot.metadata.snapshot_id, snapshot.risks)
                snapshot.recommendations = self._materialize_recommendations(snapshot.risks)
                await self.recommendation_repository.replace_recommendations(
                    snapshot.metadata.snapshot_id,
                    snapshot.recommendations,
                )
            finally:
                await self.repository.update_snapshot_counts(snapshot)
        return snapshot

    async def list_snapshots(self) -> list[NetworkSnapshot]:
        return await self.repository.list_snapshots()

    async def get_snapshot(self, snapshot_id: str) -> NetworkSnapshot | None:
        from uuid import UUID

        return await self.repository.get_snapshot(UUID(snapshot_id))

    async def list_devices(self, snapshot_id: str) -> list[DeviceSummaryResponse]:
        from uuid import UUID

        devices = await self.device_repository.list_devices(UUID(snapshot_id))
        return [
            DeviceSummaryResponse(
                device_id=device.device_id,
                snapshot_id=UUID(snapshot_id),
                identity=device.identity,
                management_ip=str(device.management_ip) if device.management_ip else None,
                role=device.role.value,
                vendor=device.vendor,
                model=device.model,
                board_name=device.board_name,
                ros_version=device.ros_version,
                platform=device.platform,
                architecture=device.architecture,
            )
            for device in devices
        ]

    async def get_device_detail(self, snapshot_id: str, device_id: str) -> DeviceDetailResponse | None:
        from uuid import UUID

        device = await self.device_repository.get_device(UUID(snapshot_id), UUID(device_id))
        if device is None:
            return None

        return DeviceDetailResponse(
            device_id=device.device_id,
            snapshot_id=UUID(snapshot_id),
            identity=device.identity,
            management_ip=str(device.management_ip) if device.management_ip else None,
            role=device.role.value,
            vendor=device.vendor,
            model=device.model,
            board_name=device.board_name,
            ros_version=device.ros_version,
            platform=device.platform,
            architecture=device.architecture,
            interfaces=[
                InterfaceResponse(
                    interface_id=item.interface_id,
                    name=item.name,
                    role=item.role.value,
                    mac_address=item.mac_address,
                    admin_up=item.admin_up,
                    oper_up=item.oper_up,
                    mtu=item.mtu,
                    speed_mbps=item.speed_mbps,
                    duplex=item.duplex,
                    bridge_name=item.bridge_name,
                    pvid=item.pvid,
                    native_vlan=item.native_vlan,
                    tagged_vlans=item.tagged_vlans,
                    untagged_vlans=item.untagged_vlans,
                )
                for item in device.interfaces
            ],
            vlans=[
                VlanResponse(
                    vlan_id=item.vlan_id,
                    name=item.name,
                    bridge_name=item.bridge_name,
                    tagged_interfaces=item.tagged_interfaces,
                    untagged_interfaces=item.untagged_interfaces,
                    svi_interfaces=item.svi_interfaces,
                )
                for item in device.vlans
            ],
            routes=[
                RouteResponse(
                    route_id=item.route_id,
                    destination=str(item.destination) if item.destination else None,
                    gateway=item.gateway,
                    protocol=item.protocol,
                    distance=item.distance,
                    is_default=item.is_default,
                    dynamic=item.dynamic,
                    disabled=item.disabled,
                )
                for item in device.routes
            ],
            bridges=[
                BridgeResponse(
                    bridge_id=item.bridge_id,
                    name=item.name,
                    protocol_mode=item.protocol_mode,
                    vlan_filtering=item.vlan_filtering,
                    igmp_snooping=item.igmp_snooping,
                    port_names=item.port_names,
                )
                for item in device.bridges
            ],
            neighbors=[
                NeighborResponse(
                    neighbor_id=item.neighbor_id,
                    local_interface=item.local_interface,
                    protocol=item.protocol,
                    remote_identity=item.remote_identity,
                    remote_interface=item.remote_interface,
                    remote_ip=str(item.remote_ip) if item.remote_ip else None,
                    remote_mac=item.remote_mac,
                    confidence=item.confidence,
                )
                for item in device.neighbors
            ],
            ospf_neighbors=[
                OspfNeighborResponse(
                    ospf_neighbor_id=item.ospf_neighbor_id,
                    router_id=item.router_id,
                    address=str(item.address) if item.address else None,
                    state=item.state,
                    interface_name=item.interface_name,
                    dr_address=str(item.dr_address) if item.dr_address else None,
                    bdr_address=str(item.bdr_address) if item.bdr_address else None,
                    state_changes=item.state_changes,
                )
                for item in device.ospf_neighbors
            ],
        )

    async def get_topology_graph(self, snapshot_id: str) -> TopologyGraphResponse:
        from uuid import UUID

        snapshot_uuid = UUID(snapshot_id)
        devices = await self.device_repository.list_devices(snapshot_uuid)
        links = await self.topology_repository.list_links(snapshot_uuid)
        return TopologyGraphResponse(
            snapshot_id=snapshot_uuid,
            nodes=[
                TopologyGraphNodeResponse(
                    device_id=device.device_id,
                    identity=device.identity,
                    management_ip=str(device.management_ip) if device.management_ip else None,
                    role=device.role.value,
                    vendor=device.vendor,
                    model=device.model,
                )
                for device in devices
            ],
            edges=[
                TopologyGraphEdgeResponse(
                    link_id=link.link_id,
                    layer=link.layer.value,
                    source_device_id=link.source_device_id,
                    source_interface=link.source_interface,
                    target_device_id=link.target_device_id,
                    target_interface=link.target_interface,
                    relation=link.relation,
                    confidence=link.confidence,
                )
                for link in links
            ],
        )

    async def list_risks(self, snapshot_id: str) -> list[RiskResponse]:
        from uuid import UUID

        risks = await self.risk_repository.list_risks(UUID(snapshot_id))
        return [
            RiskResponse(
                risk_id=risk.risk_id,
                rule_id=risk.rule_id,
                severity=risk.severity.value,
                title=risk.title,
                summary=risk.summary,
                confidence=risk.confidence,
                impacted_entity_ids=risk.impacted_entity_ids,
                evidence=risk.evidence,
            )
            for risk in risks
        ]

    async def list_raw_evidence(self, snapshot_id: str) -> list[RawEvidenceResponse]:
        from uuid import UUID

        payloads = await self.evidence_repository.list_raw_payloads(UUID(snapshot_id))
        return [
            RawEvidenceResponse(
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

    async def list_recommendations(self, snapshot_id: str) -> list[RecommendationResponse]:
        from uuid import UUID

        recommendations = await self.recommendation_repository.list_recommendations(UUID(snapshot_id))
        return [
            RecommendationResponse(
                recommendation_id=item.recommendation_id,
                title=item.title,
                summary=item.summary,
                action_type=item.action_type,
                target_entity_ids=item.target_entity_ids,
                preconditions=item.preconditions,
                evidence=item.evidence,
            )
            for item in recommendations
        ]

    async def create_remediation_plan(self, request: RemediationPlanRequest) -> RemediationPlanResponse:
        risks = await self.risk_repository.list_risks(request.snapshot_id)
        recommendations = await self.recommendation_repository.list_recommendations(request.snapshot_id)

        selected_risks = [
            risk for risk in risks if not request.risk_ids or risk.risk_id in set(request.risk_ids)
        ]
        selected_recommendations = [
            item
            for item in recommendations
            if not request.recommendation_ids or item.recommendation_id in set(request.recommendation_ids)
        ]

        plan = RemediationPlan(
            snapshot_id=request.snapshot_id,
            summary=f"Bootstrap remediation plan for {len(selected_risks)} risks and {len(selected_recommendations)} recommendations.",
            targeted_risk_ids=[risk.risk_id for risk in selected_risks],
            steps=self._build_remediation_steps(selected_risks, selected_recommendations),
            warnings=[
                "Bootstrap plan uses rule templates and requires operator review before apply.",
                "No automatic pre-flight reachability validation is implemented yet.",
            ],
        )
        await self.remediation_repository.save_plan(plan)
        return RemediationPlanResponse(
            plan_id=plan.plan_id,
            snapshot_id=plan.snapshot_id,
            summary=plan.summary,
            targeted_risk_ids=plan.targeted_risk_ids,
            steps=[
                RemediationStepResponse(
                    step_id=step.step_id,
                    title=step.title,
                    routeros_commands=step.routeros_commands,
                    validation_checks=step.validation_checks,
                    rollback_hints=step.rollback_hints,
                )
                for step in plan.steps
            ],
            warnings=plan.warnings,
        )

    async def list_broadcast_domains(self, snapshot_id: str) -> list[BroadcastDomainResponse]:
        from uuid import UUID

        domains = await self.l2_repository.list_broadcast_domains(UUID(snapshot_id))
        return [
            BroadcastDomainResponse(
                broadcast_domain_id=item.broadcast_domain_id,
                name=item.name,
                vlan_id=item.vlan_id,
                bridge_names=item.bridge_names,
                device_ids=item.device_ids,
                interface_refs=item.interface_refs,
                mac_count=item.mac_count,
                risk_score=item.risk_score,
            )
            for item in domains
        ]

    async def list_vlan_propagations(self, snapshot_id: str) -> list[VlanPropagationResponse]:
        from uuid import UUID

        propagations = await self.l2_repository.list_vlan_propagations(UUID(snapshot_id))
        return [
            VlanPropagationResponse(
                propagation_id=item.propagation_id,
                vlan_id=item.vlan_id,
                source_device_id=item.source_device_id,
                source_interface=item.source_interface,
                target_device_id=item.target_device_id,
                target_interface=item.target_interface,
                tagged=item.tagged,
                native=item.native,
                evidence=item.evidence,
            )
            for item in propagations
        ]

    async def _collect_snapshot(
        self,
        snapshot: NetworkSnapshot,
        request: SnapshotCreateRequest,
    ) -> NetworkSnapshot:
        app = build_app()
        try:
            ips = list(request.ips or app.get_target_ips())
            if request.max_targets is not None and request.max_targets > 0:
                ips = ips[: request.max_targets]
            elif request.ips == [] and app.config.max_targets > 0:
                ips = ips[: app.config.max_targets]

            if not ips:
                snapshot.metadata.status = "empty"
                snapshot.metadata.completed_at = datetime.now(timezone.utc)
                return snapshot

            await app._ensure_phpipam_cache_ready()
            async for result in app._audit_stream(ips, show_progress=False):
                snapshot.devices.append(device_from_audit_result(result))
                await self.evidence_repository.append_raw_payloads(
                    snapshot.metadata.snapshot_id,
                    [
                        RawCommandPayload(
                            device_address=result.ip,
                            command="legacy.audit_result",
                            collected_at=datetime.now(timezone.utc),
                            payload=str(result.to_dict()),
                            parser_name="legacy-bootstrap",
                            parser_version="phase3-bootstrap",
                        )
                    ],
                )

            snapshot.metadata.status = "completed"
            snapshot.metadata.completed_at = datetime.now(timezone.utc)
            return snapshot
        except Exception:
            snapshot.metadata.status = "failed"
            snapshot.metadata.completed_at = datetime.now(timezone.utc)
            raise
        finally:
            await app.shutdown()

    def _materialize_topology_links(self, devices: list) -> list[TopologyLink]:
        devices_by_ip = {
            str(device.management_ip): device
            for device in devices
            if device.management_ip is not None
        }
        links: list[TopologyLink] = []
        seen: set[tuple[str, str, str, str]] = set()

        for device in devices:
            for neighbor in device.neighbors:
                target_device = (
                    devices_by_ip.get(str(neighbor.remote_ip))
                    if neighbor.remote_ip is not None
                    else None
                )
                key = (
                    str(device.device_id),
                    neighbor.local_interface,
                    str(target_device.device_id) if target_device else "",
                    neighbor.protocol,
                )
                if key in seen:
                    continue
                seen.add(key)
                links.append(
                    TopologyLink(
                        layer=LinkLayer.L2,
                        source_device_id=device.device_id,
                        source_interface=neighbor.local_interface,
                        target_device_id=target_device.device_id if target_device else None,
                        target_interface=neighbor.remote_interface,
                        relation=neighbor.protocol,
                        confidence=neighbor.confidence,
                        metadata={
                            "remote_identity": neighbor.remote_identity,
                            "remote_mac": neighbor.remote_mac,
                            "remote_ip": str(neighbor.remote_ip) if neighbor.remote_ip else None,
                        },
                    )
                )
        return links

    def _materialize_risks(self, snapshot: NetworkSnapshot) -> list[Risk]:
        risks: list[Risk] = []
        linked_device_ids = {
            link.source_device_id
            for link in snapshot.topology_links
            if link.target_device_id is not None
        } | {
            link.target_device_id
            for link in snapshot.topology_links
            if link.target_device_id is not None
        }

        for device in snapshot.devices:
            disabled_vlan_filtering = [
                bridge.name
                for bridge in device.bridges
                if bridge.vlan_filtering is False
            ]
            if disabled_vlan_filtering:
                risks.append(
                    Risk(
                        rule_id="bridge.vlan_filtering.disabled",
                        title="Bridge VLAN filtering disabled",
                        summary=(
                            f"Device {device.identity} has bridge VLAN filtering disabled on "
                            + ", ".join(disabled_vlan_filtering)
                        ),
                        severity=Severity.HIGH,
                        confidence=0.92,
                        impacted_entity_ids=[device.device_id],
                        evidence=disabled_vlan_filtering,
                    )
                )

            if device.interfaces and device.device_id not in linked_device_ids and not device.neighbors:
                risks.append(
                    Risk(
                        rule_id="topology.unresolved_device",
                        title="Device missing resolved topology links",
                        summary=f"Device {device.identity} has no resolved topology links in the current snapshot.",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        impacted_entity_ids=[device.device_id],
                        evidence=[item.name for item in device.interfaces[:5]],
                    )
                )

            unstable_neighbors = [item for item in device.ospf_neighbors if (item.state_changes or 0) >= 10]
            if unstable_neighbors:
                risks.append(
                    Risk(
                        rule_id="ospf.neighbor.unstable",
                        title="Unstable OSPF neighbors detected",
                        summary=f"Device {device.identity} has unstable OSPF adjacencies.",
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        impacted_entity_ids=[device.device_id],
                        evidence=[
                            f"{item.router_id or 'unknown'}:{item.interface_name or 'unknown'}:{item.state_changes or 0}"
                            for item in unstable_neighbors
                        ],
                    )
                )

        for domain in snapshot.broadcast_domains:
            if len(domain.device_ids) >= 4:
                risks.append(
                    Risk(
                        rule_id="l2.broadcast_domain.oversized",
                        title="Oversized broadcast domain detected",
                        summary=(
                            f"Broadcast domain {domain.name} spans {len(domain.device_ids)} devices."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        impacted_entity_ids=domain.device_ids,
                        evidence=domain.interface_refs[:10],
                    )
                )

            if domain.vlan_id in {1, 99, 100, 850} and len(domain.device_ids) >= 3:
                risks.append(
                    Risk(
                        rule_id="l2.management_vlan.propagated_wide",
                        title="Management-like VLAN propagated too wide",
                        summary=(
                            f"VLAN {domain.vlan_id} is present across {len(domain.device_ids)} devices in domain {domain.name}."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.72,
                        impacted_entity_ids=domain.device_ids,
                        evidence=domain.interface_refs[:10],
                    )
                )

        links_by_endpoint = {
            (str(link.source_device_id), link.source_interface, str(link.target_device_id), link.target_interface): link
            for link in snapshot.topology_links
            if link.target_device_id is not None and link.target_interface is not None
        }
        for propagation in snapshot.vlan_propagations:
            key = (
                str(propagation.source_device_id),
                propagation.source_interface,
                str(propagation.target_device_id),
                propagation.target_interface,
            )
            reverse_key = (
                str(propagation.target_device_id),
                propagation.target_interface or "",
                str(propagation.source_device_id),
                propagation.source_interface,
            )
            if propagation.target_device_id is None:
                continue
            if key in links_by_endpoint or reverse_key in links_by_endpoint:
                if not propagation.tagged and not propagation.native:
                    risks.append(
                        Risk(
                            rule_id="l2.trunk_access.inconsistent",
                            title="Trunk/access inconsistency on topology link",
                            summary=(
                                f"VLAN {propagation.vlan_id} appears propagated across {propagation.source_interface}"
                                f" -> {propagation.target_interface} without tagged or native semantics."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=0.68,
                            impacted_entity_ids=[
                                propagation.source_device_id,
                                propagation.target_device_id,
                            ],
                            evidence=propagation.evidence,
                        )
                    )

        return risks

    def _materialize_recommendations(self, risks: list[Risk]) -> list[Recommendation]:
        recommendations: list[Recommendation] = []
        seen_titles: set[str] = set()

        for risk in risks:
            if risk.rule_id == "bridge.vlan_filtering.disabled":
                title = "Enable bridge VLAN filtering with staged validation"
                if title not in seen_titles:
                    seen_titles.add(title)
                    recommendations.append(
                        Recommendation(
                            title=title,
                            summary="Enable `vlan-filtering=yes` only after validating bridge VLAN table completeness and management reachability.",
                            action_type="bridge_hardening",
                            target_entity_ids=risk.impacted_entity_ids,
                            preconditions=[
                                "Bridge VLAN membership exported and reviewed",
                                "Out-of-band or alternate management path confirmed",
                            ],
                            evidence=risk.evidence,
                        )
                    )
            elif risk.rule_id == "ospf.neighbor.unstable":
                title = "Stabilize OSPF adjacency before topology changes"
                if title not in seen_titles:
                    seen_titles.add(title)
                    recommendations.append(
                        Recommendation(
                            title=title,
                            summary="Investigate interface health, MTU, and DR/BDR consistency before making L2/L3 changes on unstable OSPF neighbors.",
                            action_type="ospf_stabilization",
                            target_entity_ids=risk.impacted_entity_ids,
                            preconditions=[
                                "OSPF neighbor state history reviewed",
                                "Interface errors and optics checked",
                            ],
                            evidence=risk.evidence,
                        )
                    )
            elif risk.rule_id in {"l2.management_vlan.propagated_wide", "l2.trunk_access.inconsistent"}:
                title = "Review VLAN propagation and trunk intent"
                if title not in seen_titles:
                    seen_titles.add(title)
                    recommendations.append(
                        Recommendation(
                            title=title,
                            summary="Validate allowed VLAN lists, native VLAN intent, and access/trunk semantics before migration or cleanup.",
                            action_type="vlan_normalization",
                            target_entity_ids=risk.impacted_entity_ids,
                            preconditions=[
                                "Topology graph and VLAN propagation overlay reviewed",
                                "Target ports classified as access/trunk with confidence",
                            ],
                            evidence=risk.evidence,
                        )
                    )

        return recommendations

    def _build_remediation_steps(
        self,
        risks: list[Risk],
        recommendations: list[Recommendation],
    ) -> list[RemediationStep]:
        steps: list[RemediationStep] = []

        for recommendation in recommendations:
            if recommendation.action_type == "bridge_hardening":
                steps.append(
                    RemediationStep(
                        title=recommendation.title,
                        routeros_commands=[
                            "/interface bridge set [find] vlan-filtering=yes",
                        ],
                        validation_checks=[
                            "Confirm management VLAN reachability after enabling filtering",
                            "Validate tagged/untagged membership on every bridge port",
                        ],
                        rollback_hints=[
                            "Disable vlan-filtering from safe access path if management is lost",
                        ],
                    )
                )
            elif recommendation.action_type == "ospf_stabilization":
                steps.append(
                    RemediationStep(
                        title=recommendation.title,
                        routeros_commands=[
                            "/routing ospf neighbor print detail",
                            "/interface ethernet monitor [find] once",
                        ],
                        validation_checks=[
                            "Neighbor state remains FULL over multiple polls",
                            "No packet loss or interface flap detected",
                        ],
                        rollback_hints=[
                            "Do not apply topology or routing changes until adjacency is stable",
                        ],
                    )
                )
            elif recommendation.action_type == "vlan_normalization":
                steps.append(
                    RemediationStep(
                        title=recommendation.title,
                        routeros_commands=[
                            "/interface bridge vlan print detail",
                            "/interface bridge port print detail",
                        ],
                        validation_checks=[
                            "Allowed VLANs match intended trunk/access design",
                            "Native VLAN and PVID are explicitly documented",
                        ],
                        rollback_hints=[
                            "Preserve current VLAN table export before any modification",
                        ],
                    )
                )

        if not steps and risks:
            steps.append(
                RemediationStep(
                    title="Manual review required",
                    routeros_commands=[],
                    validation_checks=["No automated remediation template matched selected risks."],
                    rollback_hints=["Keep current configuration snapshot for manual analysis."],
                )
            )

        return steps

    def _materialize_broadcast_domains(self, devices: list) -> list[BroadcastDomain]:
        by_vlan: dict[int, BroadcastDomain] = {}
        for device in devices:
            for vlan in device.vlans:
                domain = by_vlan.setdefault(
                    vlan.vlan_id,
                    BroadcastDomain(
                        name=f"vlan-{vlan.vlan_id}",
                        vlan_id=vlan.vlan_id,
                    ),
                )
                if device.device_id not in domain.device_ids:
                    domain.device_ids.append(device.device_id)
                if vlan.bridge_name and vlan.bridge_name not in domain.bridge_names:
                    domain.bridge_names.append(vlan.bridge_name)
                for iface in vlan.tagged_interfaces:
                    ref = f"{device.identity}:{iface}:tagged"
                    if ref not in domain.interface_refs:
                        domain.interface_refs.append(ref)
                for iface in vlan.untagged_interfaces:
                    ref = f"{device.identity}:{iface}:untagged"
                    if ref not in domain.interface_refs:
                        domain.interface_refs.append(ref)
                domain.mac_count += sum(
                    1
                    for iface in device.interfaces
                    if iface.name in set(vlan.tagged_interfaces + vlan.untagged_interfaces)
                    and iface.connected_mac_count not in (None, 0)
                )

        for domain in by_vlan.values():
            domain.risk_score = round(min(1.0, len(domain.device_ids) / 10.0), 2)
        return list(by_vlan.values())

    def _materialize_vlan_propagations(
        self,
        devices: list,
        links: list[TopologyLink],
    ) -> list[VLANPropagation]:
        interfaces_by_device = {
            device.device_id: {interface.name: interface for interface in device.interfaces}
            for device in devices
        }
        propagations: list[VLANPropagation] = []

        for link in links:
            if link.target_device_id is None or link.target_interface is None:
                continue
            source_iface = interfaces_by_device.get(link.source_device_id, {}).get(link.source_interface)
            target_iface = interfaces_by_device.get(link.target_device_id, {}).get(link.target_interface)
            if source_iface is None:
                continue

            vlan_ids = set(source_iface.tagged_vlans) | set(source_iface.untagged_vlans)
            if source_iface.pvid is not None:
                vlan_ids.add(source_iface.pvid)

            for vlan_id in sorted(vlan_ids):
                is_tagged = vlan_id in source_iface.tagged_vlans
                is_native = source_iface.native_vlan == vlan_id or (
                    source_iface.pvid == vlan_id and vlan_id in source_iface.untagged_vlans
                )
                evidence = [f"{link.relation}:{link.source_interface}->{link.target_interface}"]
                if target_iface is not None:
                    target_has_vlan = (
                        vlan_id in target_iface.tagged_vlans
                        or vlan_id in target_iface.untagged_vlans
                        or target_iface.pvid == vlan_id
                    )
                    evidence.append(f"target_has_vlan={str(target_has_vlan).lower()}")
                propagations.append(
                    VLANPropagation(
                        vlan_id=vlan_id,
                        source_device_id=link.source_device_id,
                        source_interface=link.source_interface,
                        target_device_id=link.target_device_id,
                        target_interface=link.target_interface,
                        tagged=is_tagged,
                        native=is_native,
                        evidence=evidence,
                    )
                )

        return propagations
