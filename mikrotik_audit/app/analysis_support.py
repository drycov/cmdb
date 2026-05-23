"""Implementation details for app analysis_support."""

from __future__ import annotations

from typing import Iterable

from .models import AnalysisResult, DeviceModel, PortModel

SUMMARY_HEADERS = [
    "identity",
    "mgmt_ip",
    "model",
    "transit_detected",
    "radio_detected",
    "decision",
    "risks",
    "recommendations",
]
PORT_HEADERS = ["port", "role", "tagged_vlans", "untagged_vlans", "pvid", "comment", "confidence"]
PORT_HEADERS_WITH_IDENTITY = [
    "identity",
    *PORT_HEADERS,
]


def resolve_identity(device: DeviceModel) -> str:
    """Resolve identity."""
    for entry in device.raw_sections.get("/system identity", []):
        value = entry.get("name") or entry.get("raw")
        if value:
            return value
    return device.identity


def resolve_management_ip(device: DeviceModel) -> str | None:
    """Resolve management ip."""
    fallback_ip: str | None = None
    for entry in device.raw_sections.get("/ip address", []):
        raw_ip = entry.get("address") or entry.get("address=")
        if not raw_ip:
            continue

        address = raw_ip.split("/")[0]
        if fallback_ip is None:
            fallback_ip = address

        comment = str(entry.get("comment") or "").lower()
        interface = str(entry.get("interface") or "").lower()
        if "mgmt" in comment or "mgmt" in interface or interface.startswith("vlan"):
            return address

    return fallback_ip


def resolve_model(device: DeviceModel) -> str:
    """Resolve model."""
    for entry in device.raw_sections.get("/system resource", []):
        value = entry.get("model")
        if value:
            return value
    return device.model


def ensure_ethernet_ports(device: DeviceModel) -> None:
    """Handle ensure ethernet ports."""
    for entry in device.raw_sections.get("/interface ethernet", []):
        name = (
            entry.get("name")
            or entry.get("interface")
            or entry.get("default-name")
            or entry.get("default_name")
        )
        if not name:
            continue
        device.ports.setdefault(name, PortModel(name=name, comment=entry.get("comment")))


def detect_transit(result: AnalysisResult) -> None:
    """Detect transit."""
    if result.device.raw_sections.get("/interface eoip"):
        result.transit_detected = True
        if "EoIP present" not in result.risks:
            result.risks.append("EoIP present")


def finalize_decision(result: AnalysisResult) -> None:
    """Finalize decision."""
    trunk_ports = [port for port in result.device.ports.values() if port.role == "trunk"]
    hybrid_ports = [port for port in result.device.ports.values() if port.role == "hybrid"]

    if result.transit_detected:
        result.decision = "NEED_MANUAL_REVIEW"
        _append_recommendation(
            result,
            "Transit-like topology detected; verify the device manually before changes.",
        )
        return

    if hybrid_ports:
        result.decision = "NEED_MANUAL_REVIEW"
        _append_recommendation(
            result,
            "Hybrid ports detected; validate access/trunk intent manually.",
        )
        return

    if result.device.mgmt_ip and trunk_ports:
        result.decision = "SAFE_TO_REVIEW"
        _append_recommendation(
            result,
            "Offline analysis found a management IP and trunk candidates; confirm uplinks before rollout.",
        )
        return

    result.decision = "NEED_MANUAL_REVIEW"
    _append_recommendation(
        result,
        "Run full manual review; offline analyzer remains conservative for ambiguous configs.",
    )


def build_summary_row(result: AnalysisResult) -> dict[str, object]:
    """Build summary row."""
    device = result.device
    return {
        "identity": device.identity,
        "mgmt_ip": device.mgmt_ip,
        "model": device.model,
        "transit_detected": result.transit_detected,
        "radio_detected": result.radio_detected,
        "decision": result.decision,
        "risks": ", ".join(result.risks),
        "recommendations": ", ".join(result.recommendations),
    }


def build_port_rows(
    result: AnalysisResult,
    *,
    include_identity: bool = False,
) -> list[dict[str, object]]:
    """Build port rows."""
    rows: list[dict[str, object]] = []
    for port_name, port in result.device.ports.items():
        row: dict[str, object] = {
            "port": port_name,
            "role": port.role,
            "tagged_vlans": ",".join(str(value) for value in port.tagged_vlans),
            "untagged_vlans": ",".join(str(value) for value in port.untagged_vlans),
            "pvid": port.pvid,
            "comment": port.comment,
            "confidence": port.confidence,
        }
        if include_identity:
            row = {"identity": result.device.identity, **row}
        rows.append(row)
    return rows


def build_summary_rows(results: Iterable[AnalysisResult]) -> list[dict[str, object]]:
    """Build summary rows."""
    return [build_summary_row(result) for result in results]


def build_all_port_rows(results: Iterable[AnalysisResult]) -> list[dict[str, object]]:
    """Build all port rows."""
    rows: list[dict[str, object]] = []
    for result in results:
        rows.extend(build_port_rows(result, include_identity=True))
    return rows


def _append_recommendation(result: AnalysisResult, message: str) -> None:
    """Internal helper for append recommendation."""
    if message not in result.recommendations:
        result.recommendations.append(message)
