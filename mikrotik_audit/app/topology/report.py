"""Implementation details for app topology report."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .models import TopologyAnalysisResult, TopologyLink


topology_summary_headers = [
    "total_devices",
    "online",
    "ssh_ok",
    "fallback_ok",
    "auth_failed",
    "ssh_closed",
    "offline",
    "inferred_links",
]

topology_device_headers = [
    "ip",
    "identity",
    "status",
    "primary_mac",
    "uplink_interface",
    "uplink_mac",
    "neighbor_identity",
    "neighbor_address",
    "neighbor_interface",
    "neighbor_mac",
    "vlan_count",
    "vlan_names",
    "ospf_neighbor_count",
    "ospf_instances",
    "bridge_warning",
    "error",
]

topology_link_headers = [
    "source_ip",
    "source_identity",
    "source_interface",
    "source_mac",
    "target_ip",
    "target_identity",
    "target_interface",
    "target_mac",
    "relation",
    "confidence",
]

topology_vlan_headers = [
    "device_identity",
    "device_ip",
    "vlan_id",
    "vlan_hex",
    "bridge",
    "tagged_ports",
    "untagged_ports",
    "pvid_ports",
    "interfaces",
]


def to_json(results: list[TopologyAnalysisResult], links: list[TopologyLink]) -> str:
    """Handle to json."""
    payload = {
        "devices": [
            {
                **{
                    key: getattr(result.device, key, "")
                    for key in topology_device_headers
                },
                "device_info": asdict(result.device.device_info) if result.device.device_info else None,
                "edges": [asdict(edge) for edge in result.edges],
            }
            for result in results
        ],
        "links": [asdict(link) for link in links],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_markdown(results: list[TopologyAnalysisResult], links: list[TopologyLink]) -> str:
    """Handle to markdown."""
    lines: list[str] = []
    lines.append("# Topology Scan")
    lines.append("")
    lines.append("## Devices")
    for result in results:
        lines.append(f"- {result.device.ip} ({result.device.identity or 'unknown'}) status={result.status}")
        if result.error:
            lines.append(f"  - error: {result.error}")
        if result.device.uplink_interface:
            lines.append(
                f"  - uplink: {result.device.uplink_interface} -> {result.device.uplink_mac or 'unknown'}"
            )
        if result.device.neighbor_address or result.device.neighbor_mac:
            lines.append(
                f"  - neighbor: {result.device.neighbor_address or 'unknown'} {result.device.neighbor_mac or ''}"
            )
    if links:
        lines.append("")
        lines.append("## Inferred Links")
        for link in links:
            lines.append(
                f"- {link.source_ip}:{link.source_interface} -> {link.target_ip or 'unknown'}:{link.target_interface or 'unknown'} "
                f"({link.relation}, confidence={link.confidence})"
            )
    return "\n".join(lines)


def _build_device_row(result: TopologyAnalysisResult) -> dict[str, Any]:
    """Internal helper for build device row."""
    return {
        "ip": result.device.ip,
        "identity": result.device.identity,
        "status": result.device.status,
        "primary_mac": result.device.primary_mac,
        "uplink_interface": result.device.uplink_interface,
        "uplink_mac": result.device.uplink_mac,
        "neighbor_identity": result.device.neighbor_identity,
        "neighbor_address": result.device.neighbor_address,
        "neighbor_interface": result.device.neighbor_interface,
        "neighbor_mac": result.device.neighbor_mac,
        "vlan_count": result.device.vlan_count,
        "vlan_names": result.device.vlan_names,
        "ospf_neighbor_count": result.device.ospf_neighbor_count,
        "ospf_instances": result.device.ospf_instances,
        "bridge_warning": result.device.bridge_warning,
        "error": result.error,
    }


def _build_link_row(link: TopologyLink) -> dict[str, Any]:
    """Internal helper for build link row."""
    return {
        "source_ip": link.source_ip,
        "source_identity": link.source_identity,
        "source_interface": link.source_interface,
        "source_mac": link.source_mac,
        "target_ip": link.target_ip,
        "target_identity": link.target_identity,
        "target_interface": link.target_interface,
        "target_mac": link.target_mac,
        "relation": link.relation,
        "confidence": link.confidence,
    }


def _build_vlan_rows(results: list[TopologyAnalysisResult]) -> list[dict[str, Any]]:
    """Internal helper for build vlan rows."""
    rows: list[dict[str, Any]] = []
    for result in results:
        info = result.device.device_info
        if info is None:
            continue
        for vlan in info.vlan_table or []:
            rows.append(
                {
                    "device_identity": info.identity,
                    "device_ip": result.device.ip,
                    "vlan_id": vlan.get("vlan_id", ""),
                    "vlan_hex": vlan.get("vlan_hex", ""),
                    "bridge": vlan.get("bridge", ""),
                    "tagged_ports": ", ".join(vlan.get("tagged_ports", [])),
                    "untagged_ports": ", ".join(vlan.get("untagged_ports", [])),
                    "pvid_ports": ", ".join(vlan.get("pvid_ports", [])),
                    "interfaces": ", ".join(
                        f"{i.get('name', '')}@{i.get('interface', '')}" for i in vlan.get("vlan_interfaces", [])
                    ),
                }
            )
    return rows


def _build_summary_row(results: list[TopologyAnalysisResult], links: list[TopologyLink]) -> dict[str, Any]:
    """Internal helper for build summary row."""
    status_counts: dict[str, int] = {
        "online": 0,
        "ssh_ok": 0,
        "fallback_ok": 0,
        "auth_failed": 0,
        "ssh_closed": 0,
        "offline": 0,
    }
    for result in results:
        status = result.status.lower()
        if status.startswith("ssh_ok"):
            status_counts["ssh_ok"] += 1
            status_counts["online"] += 1
        elif status.startswith("fallback_ok"):
            status_counts["fallback_ok"] += 1
            status_counts["online"] += 1
        elif status == "auth_failed":
            status_counts["auth_failed"] += 1
        elif status == "ssh_closed":
            status_counts["ssh_closed"] += 1
        elif status == "offline":
            status_counts["offline"] += 1
        else:
            if status in status_counts:
                status_counts[status] += 1

    return {
        "total_devices": len(results),
        "online": status_counts["online"],
        "ssh_ok": status_counts["ssh_ok"],
        "fallback_ok": status_counts["fallback_ok"],
        "auth_failed": status_counts["auth_failed"],
        "ssh_closed": status_counts["ssh_closed"],
        "offline": status_counts["offline"],
        "inferred_links": len(links),
    }


def build_sections_from_topology(results: list[TopologyAnalysisResult], links: list[TopologyLink]) -> dict[str, tuple[list[str], list[dict[str, Any]]]]:
    """Build sections from topology."""
    return {
        "topology_summary": (
            topology_summary_headers,
            [_build_summary_row(results, links)],
        ),
        "topology_devices": (
            topology_device_headers,
            [_build_device_row(result) for result in results],
        ),
        "topology_links": (
            topology_link_headers,
            [_build_link_row(link) for link in links],
        ),
        "topology_vlans": (
            topology_vlan_headers,
            _build_vlan_rows(results),
        ),
    }
