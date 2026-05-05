from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

from constants.error_codes import FirmwareErrorCode
from constants.statuses import AuditStatus
from models import AuditResult


INVENTORY_HEADERS = [
    "ip", "identity", "status", "inventory_status", "inventory_severity",
    "phpipam_match_type", "phpipam_hostname", "phpipam_ip",
    "version", "board_name", "platform", "architecture",
    "ospf_instance_count", "ospf_neighbor_count",
    "bridge_count", "bridge_port_count",
    "scheduler_count", "dhcp_server_count", "dhcp_client_count",
    "ssh_port_value", "winbox_port_value",
    "firewall_filter_count", "firewall_nat_count",
    "route_count", "default_route_count",
    "vlan_count", "radius_count", "watchdog_enabled",
    "ping", "ssh_port", "auth_method",
    "firmware_target_version", "firmware_error", "phpipam_note",
]

TOPOLOGY_HEADERS = [
    "ip", "identity", "board_name", "mac_address",
    "uplink_interface", "uplink_mac",
    "neighbor_identity", "neighbor_address",
    "neighbor_interface", "neighbor_mac",
]

PHPIPAM_MISMATCH_HEADERS = [
    "ip", "identity", "inventory_status", "inventory_severity",
    "phpipam_match_type", "phpipam_hostname", "phpipam_ip",
    "phpipam_address_id", "phpipam_description", "phpipam_note",
    "status", "version", "board_name",
]

ISSUE_HEADERS = [
    "ip", "identity", "status", "inventory_status", "inventory_severity",
    "phpipam_match_type", "phpipam_hostname", "phpipam_ip",
    "version", "board_name", "firmware_error", "phpipam_note",
]

VLAN_HEADERS = [
    "device_identity", "device_ip", "vlan_id", "vlan_hex", "bridge",
    "tagged_ports", "untagged_ports", "pvid_ports", "interfaces",
]


def rows_by_headers(results: Iterable[AuditResult], headers: list[str]) -> list[dict[str, Any]]:
    return [{header: getattr(result, header, "") for header in headers} for result in results]


def build_topology_rows(results: Iterable[AuditResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for result in results:
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
            continue

        rows.append({header: getattr(result, header, "") for header in TOPOLOGY_HEADERS})

    return rows


def build_phpipam_mismatch_rows(results: Iterable[AuditResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for result in results:
        if (result.inventory_status or "OK") == "OK":
            continue

        rows.append({header: getattr(result, header, "") for header in PHPIPAM_MISMATCH_HEADERS})

    return rows


def build_issue_rows(results: Iterable[AuditResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for result in results:
        has_audit_issue = not (
            result.status.startswith(AuditStatus.SSH_OK.value)
            or result.status.startswith(AuditStatus.FALLBACK_OK.value)
        )
        has_inventory_issue = (result.inventory_severity or "").upper() in {"WARNING", "ERROR"}
        has_firmware_issue = bool(result.firmware_error)

        if has_audit_issue or has_inventory_issue or has_firmware_issue:
            rows.append({header: getattr(result, header, "") for header in ISSUE_HEADERS})

    return rows


def build_vlan_rows(results: Iterable[AuditResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for result in results:
        vlan_table = getattr(result, "vlan_table", []) or []

        for vlan in vlan_table:
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


def build_summary_rows(results: list[AuditResult]) -> list[tuple[str, Any]]:
    status_counts = Counter()
    flag_counts = Counter()
    firmware_error_counts = Counter()
    inventory_status_counts = Counter()
    inventory_severity_counts = Counter()
    inventory_match_counts = Counter()

    for result in results:
        if result.ping:
            flag_counts["alive"] += 1
        if result.radius_added:
            flag_counts["radius_added"] += 1
        if result.radius_recreated:
            flag_counts["radius_recreated"] += 1
        if result.radius_present_after:
            flag_counts["radius_present_after"] += 1
        if result.aaa_enabled:
            flag_counts["aaa_enabled"] += 1
        if result.aaa_present_after:
            flag_counts["aaa_present_after"] += 1
        if result.firmware_upload_needed:
            flag_counts["firmware_upload_needed"] += 1
        if result.firmware_uploaded:
            flag_counts["firmware_uploaded"] += 1
        if result.firmware_already_present:
            flag_counts["firmware_already_present"] += 1
        if result.firmware_reboot_sent:
            flag_counts["firmware_reboot_sent"] += 1

        if result.status.startswith(AuditStatus.SSH_OK.value):
            status_counts["ssh_ok"] += 1
        elif result.status.startswith(AuditStatus.FALLBACK_OK.value):
            status_counts["fallback_ok"] += 1
        elif result.status == AuditStatus.AUTH_FAILED.value:
            status_counts["auth_failed"] += 1
        elif result.status == AuditStatus.SSH_CLOSED.value:
            status_counts["ssh_closed"] += 1
        elif result.status == AuditStatus.OFFLINE.value:
            status_counts["offline"] += 1

        if result.firmware_error:
            firmware_error_counts[result.firmware_error] += 1
        if result.inventory_status:
            inventory_status_counts[result.inventory_status] += 1
        if result.inventory_severity:
            inventory_severity_counts[result.inventory_severity] += 1
        if result.phpipam_match_type:
            inventory_match_counts[result.phpipam_match_type] += 1

    total = len(results)
    alive = flag_counts["alive"]
    ok_inventory = inventory_status_counts["OK"]

    return [
        ("total_hosts", total),
        ("alive", alive),
        ("alive_percent", round((alive / total) * 100, 2) if total else 0),
        ("ssh_ok", status_counts["ssh_ok"]),
        ("fallback_ok", status_counts["fallback_ok"]),
        ("auth_failed", status_counts["auth_failed"]),
        ("ssh_closed", status_counts["ssh_closed"]),
        ("offline", status_counts["offline"]),
        ("radius_added", flag_counts["radius_added"]),
        ("radius_recreated", flag_counts["radius_recreated"]),
        ("radius_present_after", flag_counts["radius_present_after"]),
        ("aaa_enabled", flag_counts["aaa_enabled"]),
        ("aaa_present_after", flag_counts["aaa_present_after"]),
        ("firmware_upload_needed", flag_counts["firmware_upload_needed"]),
        ("firmware_uploaded", flag_counts["firmware_uploaded"]),
        ("firmware_already_present", flag_counts["firmware_already_present"]),
        ("firmware_reboot_sent", flag_counts["firmware_reboot_sent"]),
        ("firmware_same_version", firmware_error_counts[FirmwareErrorCode.SAME_VERSION.value]),
        ("firmware_upload_failed", firmware_error_counts[FirmwareErrorCode.UPLOAD_FAILED.value]),
        ("firmware_local_not_found", firmware_error_counts[FirmwareErrorCode.LOCAL_FIRMWARE_NOT_FOUND.value]),
        ("inventory_ok", ok_inventory),
        ("inventory_compliance_percent", round((ok_inventory / total) * 100, 2) if total else 0),
        ("inventory_hostname_mismatch", inventory_status_counts["HOSTNAME_MISMATCH"]),
        ("inventory_hostname_partial_match", inventory_status_counts["HOSTNAME_PARTIAL_MATCH"]),
        ("inventory_hostname_incomplete", inventory_status_counts["HOSTNAME_INCOMPLETE"]),
        ("inventory_not_found", inventory_status_counts["NOT_FOUND"]),
        ("inventory_duplicate", inventory_status_counts["DUPLICATE"]),
        ("severity_info", inventory_severity_counts["INFO"]),
        ("severity_warning", inventory_severity_counts["WARNING"]),
        ("severity_error", inventory_severity_counts["ERROR"]),
        ("match_ip", inventory_match_counts["ip"]),
        ("match_hostname", inventory_match_counts["hostname"]),
        ("match_partial_hostname", inventory_match_counts["partial_hostname"]),
        ("match_not_found", inventory_match_counts["not_found"]),
    ]


def build_report_sections(results: list[AuditResult], *, inventory_file: str, output_xlsx: str) -> list[tuple[str, list[tuple[str, Any]]]]:
    summary = dict(build_summary_rows(results))

    return [
        (
            "report",
            [
                ("generated_at_utc", datetime.now(timezone.utc).isoformat()),
                ("inventory_file", inventory_file),
                ("output_xlsx", output_xlsx),
                ("total_hosts", summary["total_hosts"]),
                ("alive_percent", summary["alive_percent"]),
                ("inventory_compliance_percent", summary["inventory_compliance_percent"]),
            ],
        ),
        (
            "audit",
            [
                ("alive", summary["alive"]),
                ("ssh_ok", summary["ssh_ok"]),
                ("fallback_ok", summary["fallback_ok"]),
                ("auth_failed", summary["auth_failed"]),
                ("ssh_closed", summary["ssh_closed"]),
                ("offline", summary["offline"]),
            ],
        ),
        (
            "inventory",
            [
                ("inventory_ok", summary["inventory_ok"]),
                ("inventory_hostname_mismatch", summary["inventory_hostname_mismatch"]),
                ("inventory_hostname_partial_match", summary["inventory_hostname_partial_match"]),
                ("inventory_hostname_incomplete", summary["inventory_hostname_incomplete"]),
                ("inventory_not_found", summary["inventory_not_found"]),
                ("inventory_duplicate", summary["inventory_duplicate"]),
                ("severity_info", summary["severity_info"]),
                ("severity_warning", summary["severity_warning"]),
                ("severity_error", summary["severity_error"]),
                ("match_ip", summary["match_ip"]),
                ("match_hostname", summary["match_hostname"]),
                ("match_partial_hostname", summary["match_partial_hostname"]),
                ("match_not_found", summary["match_not_found"]),
            ],
        ),
    ]