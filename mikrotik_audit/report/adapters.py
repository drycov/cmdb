from __future__ import annotations

from typing import Any, Iterable

from models import AuditResult

from services.export.common import (
    INVENTORY_HEADERS,
    ISSUE_HEADERS,
    PHPIPAM_MISMATCH_HEADERS,
    TOPOLOGY_HEADERS,
    VLAN_HEADERS,
)


def inventory_row(result: AuditResult) -> dict[str, Any]:
    return {h: getattr(result, h, "") for h in INVENTORY_HEADERS}


def raw_row(result: AuditResult) -> dict[str, Any]:
    return {h: getattr(result, h, "") for h in AuditResult.EXPORT_HEADERS}


def topology_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    if not any(
        [
            result.uplink_interface,
            result.uplink_mac,
            result.neighbor_identity,
            result.neighbor_address,
            result.neighbor_interface,
            result.neighbor_mac,
        ]
    ):
        return []

    return [{h: getattr(result, h, "") for h in TOPOLOGY_HEADERS}]


def mismatch_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    if (result.inventory_status or "OK") == "OK":
        return []

    return [{h: getattr(result, h, "") for h in PHPIPAM_MISMATCH_HEADERS}]


def issue_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    has_audit_issue = not (
        result.status.startswith("SSH_OK")
        or result.status.startswith("FALLBACK_OK")
    )
    has_inventory_issue = (result.inventory_severity or "").upper() in {"WARNING", "ERROR"}
    has_firmware_issue = bool(result.firmware_error)

    if not (has_audit_issue or has_inventory_issue or has_firmware_issue):
        return []

    return [{h: getattr(result, h, "") for h in ISSUE_HEADERS}]


def vlan_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for vlan in result.vlan_table or []:
        rows.append(
            {
                "device_identity": result.identity,
                "device_ip": result.ip,
                "vlan_id": vlan.get("vlan_id", ""),
                "vlan_hex": vlan.get("vlan_hex", ""),
                "bridge": vlan.get("bridge", ""),
                "tagged_ports": ", ".join(vlan.get("tagged_ports", [])),
                "untagged_ports": ", ".join(vlan.get("untagged_ports", [])),
                "pvid_ports": ", ".join(vlan.get("pvid_ports", [])),
                "interfaces": ", ".join(
                    f"{i.get('name', '')}@{i.get('interface', '')}"
                    for i in vlan.get("vlan_interfaces", [])
                ),
            }
        )

    return rows