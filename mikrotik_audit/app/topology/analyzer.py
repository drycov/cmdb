from __future__ import annotations

import re
from dataclasses import asdict
from typing import Iterable

from models.device_info import DeviceInfo
from services.collector import MikroTikCollector
from services.ssh import SSHSession

from .models import TopologyAnalysisResult, TopologyDevice, TopologyLink


def _normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9a-f]", "", mac.lower()) if mac else ""


class TopologyAnalyzer:
    def __init__(self, collector: MikroTikCollector) -> None:
        self.collector = collector

    def analyze_session(self, session: SSHSession, ip: str, status: str) -> TopologyAnalysisResult:
        device_info = self.collector.collect_router_data(session)
        if device_info is None:
            return self._build_result_for_error(
                ip=ip,
                status=status,
                error="device_data_collection_failed",
            )

        result = TopologyAnalysisResult(
            device=self._device_from_info(ip=ip, info=device_info, status=status),
            status=status,
        )
        result.device.device_info = device_info
        return result

    def build_offline_result(self, ip: str, status: str, error: str) -> TopologyAnalysisResult:
        return TopologyAnalysisResult(
            device=TopologyDevice(
                ip=ip,
                status=status,
                error=error,
            ),
            status=status,
            error=error,
        )

    def _build_result_for_error(self, ip: str, status: str, error: str) -> TopologyAnalysisResult:
        return self.build_offline_result(ip=ip, status=status, error=error)

    def _device_from_info(self, ip: str, info: DeviceInfo, status: str) -> TopologyDevice:
        return TopologyDevice(
            ip=ip,
            status=status,
            identity=info.identity,
            primary_mac=info.mac_address,
            uplink_interface=info.uplink_interface,
            uplink_mac=info.uplink_mac,
            neighbor_identity=info.neighbor_identity,
            neighbor_address=info.neighbor_address,
            neighbor_interface=info.neighbor_interface,
            neighbor_mac=info.neighbor_mac,
            vlan_count=info.vlan_count,
            vlan_names=info.vlan_names,
            ospf_neighbor_count=info.ospf_neighbor_count,
            ospf_instances=info.ospf_instances,
            bridge_warning=info.bridge_warning,
            device_info=info,
            error="",
        )

    def infer_links(self, results: Iterable[TopologyAnalysisResult]) -> list[TopologyLink]:
        known_by_mac: dict[str, TopologyAnalysisResult] = {}
        known_by_ip: dict[str, TopologyAnalysisResult] = {}

        for result in results:
            info = result.device.device_info
            if info is None:
                continue
            for candidate_mac in (info.mac_address, info.uplink_mac):
                normalized = _normalize_mac(candidate_mac)
                if normalized:
                    known_by_mac[normalized] = result
            known_by_ip[result.device.ip] = result

        edges: list[TopologyLink] = []
        seen: set[tuple[str, str, str]] = set()

        for result in results:
            info = result.device.device_info
            if info is None:
                continue

            candidates: list[tuple[str, str, str, str, str]] = []
            if info.neighbor_address:
                candidates.append((
                    info.neighbor_address,
                    "address",
                    info.neighbor_interface,
                    info.neighbor_mac,
                    "mikrotik_neighbor",
                ))
            if info.uplink_mac:
                candidates.append((
                    info.uplink_mac,
                    "uplink_mac",
                    info.uplink_interface,
                    info.uplink_mac,
                    "uplink",
                ))

            for neighbor_value, match_type, source_interface, neighbor_mac, relation in candidates:
                if not neighbor_value:
                    continue

                target = None
                normalized = _normalize_mac(neighbor_value)
                if normalized and normalized in known_by_mac:
                    target = known_by_mac[normalized]
                elif neighbor_value in known_by_ip:
                    target = known_by_ip[neighbor_value]

                if target is None:
                    edge = TopologyLink(
                        source_ip=result.device.ip,
                        source_identity=result.device.identity,
                        source_interface=result.device.uplink_interface if match_type == "uplink_mac" else source_interface,
                        source_mac=result.device.primary_mac,
                        target_ip=neighbor_value if match_type == "address" else "",
                        target_identity="",
                        target_interface="",
                        target_mac=neighbor_mac if neighbor_mac else "",
                        relation=relation,
                        confidence=0.5,
                    )
                else:
                    target_info = target.device
                    edge = TopologyLink(
                        source_ip=result.device.ip,
                        source_identity=result.device.identity,
                        source_interface=result.device.uplink_interface if match_type == "uplink_mac" else source_interface,
                        source_mac=result.device.primary_mac,
                        target_ip=target_info.ip,
                        target_identity=target_info.identity,
                        target_interface=target_info.uplink_interface if relation == "uplink" else target_info.neighbor_interface,
                        target_mac=target_info.primary_mac,
                        relation=relation,
                        confidence=0.9,
                    )

                key = (
                    edge.source_ip,
                    edge.target_ip,
                    edge.relation,
                )
                if key in seen:
                    continue
                seen.add(key)
                edges.append(edge)

        return edges
