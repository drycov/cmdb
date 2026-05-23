"""Implementation details for sot adapters."""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address

from mikrotik_audit.models.audit_result import AuditResult
from mikrotik_audit.models.device_info import DeviceInfo

from .domain import (
    Bridge,
    Device,
    DeviceCapabilities,
    DeviceRole,
    Interface,
    InterfaceRole,
    Neighbor,
    OSPFNeighbor,
    Route,
    VLAN,
)


def _safe_int(value: object) -> int | None:
    """Internal helper for safe int."""
    try:
        if value in ("", None):
            return None
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _bool_from_routeros(value: object) -> bool | None:
    """Internal helper for bool from routeros."""
    if value in ("", None):
        return None
    normalized = str(value).strip().lower()
    if normalized in {"yes", "true", "on", "enabled"}:
        return True
    if normalized in {"no", "false", "off", "disabled"}:
        return False
    return None


def _safe_ipv4_address(value: object) -> IPv4Address | None:
    """
    RouterOS neighbor tables may contain IPv6 link-local addresses (fe80::/10).
    Current domain models are IPv4-only for several fields, therefore IPv6 and
    malformed values must not break the whole snapshot collection.
    """
    if value in ("", None):
        return None
    try:
        parsed = ip_address(str(value).strip())
    except ValueError:
        return None
    if isinstance(parsed, IPv4Address):
        return parsed
    return None



def device_from_device_info(info: DeviceInfo, *, management_ip: str | None = None) -> Device:
    """Handle device from device info."""
    device = Device(
        identity=info.identity or management_ip or "unknown-device",
        management_ip=_safe_ipv4_address(management_ip),
        role=DeviceRole.UNKNOWN,
        model=info.board_name or None,
        board_name=info.board_name or None,
        ros_version=info.version or None,
        platform=info.platform or None,
        architecture=info.architecture or None,
        license_level=info.license or None,
        uptime=info.uptime or None,
        interface_count=_safe_int(info.interface_count),
        primary_mac=info.mac_address or None,
        capabilities=DeviceCapabilities(
            hardware_offload=_safe_int(info.bridge_hw_offload_ports) not in (None, 0),
            supports_vlan_filtering=_bool_from_routeros(info.bridge_vlan_filtering.split(":")[-1] if info.bridge_vlan_filtering else ""),
            supports_ospf=_safe_int(info.ospf_neighbor_count) not in (None, 0),
        ),
    )

    if info.uplink_interface or info.neighbor_address or info.neighbor_mac:
        device.neighbors.append(
            Neighbor(
                device_id=device.device_id,
                local_interface=info.uplink_interface or "unknown",
                protocol="legacy-neighbor",
                remote_identity=info.neighbor_identity or None,
                remote_interface=info.neighbor_interface or None,
                remote_ip=_safe_ipv4_address(info.neighbor_address),
                remote_mac=info.neighbor_mac or None,
                confidence=0.5,
            )
        )

    for bridge_name in [item.strip() for item in info.bridge_names.split(",") if item.strip()]:
        device.bridges.append(
            Bridge(
                device_id=device.device_id,
                name=bridge_name,
                protocol_mode=_extract_named_value(info.bridge_protocol_modes, bridge_name),
                vlan_filtering=_bool_from_routeros(_extract_named_value(info.bridge_vlan_filtering, bridge_name)),
                igmp_snooping=_bool_from_routeros(_extract_named_value(info.bridge_igmp_snooping, bridge_name)),
            )
        )

    for vlan_row in info.vlan_table:
        vlan_id = _safe_int(vlan_row.get("vlan_id"))
        if vlan_id is None:
            continue
        device.vlans.append(
            VLAN(
                vlan_id=vlan_id,
                bridge_name=str(vlan_row.get("bridge", "") or "") or None,
                tagged_interfaces=list(vlan_row.get("tagged_ports", []) or []),
                untagged_interfaces=list(vlan_row.get("untagged_ports", []) or []),
                svi_interfaces=[
                    str(item.get("name", ""))
                    for item in vlan_row.get("vlan_interfaces", []) or []
                    if item.get("name")
                ],
            )
        )

        for interface_name in vlan_row.get("tagged_ports", []) or []:
            _upsert_interface(device, interface_name, tagged_vlan=vlan_id, role=InterfaceRole.TRUNK)
        for interface_name in vlan_row.get("untagged_ports", []) or []:
            _upsert_interface(device, interface_name, untagged_vlan=vlan_id, role=InterfaceRole.ACCESS)
        for interface_name in vlan_row.get("pvid_ports", []) or []:
            _upsert_interface(device, interface_name, pvid=vlan_id)

    for route_row in info.routes:
        device.routes.append(
            Route(
                device_id=device.device_id,
                destination=None,
                gateway=str(route_row.get("gateway", "") or "") or None,
                protocol=str(route_row.get("routing_table", "") or route_row.get("belongs_to", "") or "") or None,
                is_default=str(route_row.get("dst_address", "") or route_row.get("dst-address", "")) == "0.0.0.0/0",
                dynamic=_bool_from_routeros(route_row.get("dynamic")) is True,
                disabled=_bool_from_routeros(route_row.get("disabled")) is True,
            )
        )

    for neighbor_row in info.ospf_neighbor_details:
        device.ospf_neighbors.append(
            OSPFNeighbor(
                device_id=device.device_id,
                router_id=str(neighbor_row.get("router_id", "") or "") or None,
                address=_safe_ipv4_address(neighbor_row.get("address")),
                state=str(neighbor_row.get("state", "") or "") or None,
                interface_name=str(neighbor_row.get("interface", "") or "") or None,
                dr_address=_safe_ipv4_address(neighbor_row.get("dr")),
                bdr_address=_safe_ipv4_address(neighbor_row.get("bdr")),
                state_changes=_safe_int(neighbor_row.get("state_changes")),
            )
        )

    return device


def device_from_audit_result(result: AuditResult) -> Device:
    """Handle device from audit result."""
    return device_from_device_info(result.to_device_info(), management_ip=result.ip)


def _extract_named_value(serialized: str, name: str) -> str | None:
    """Internal helper for extract named value."""
    for item in serialized.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            continue
        item_name, item_value = item.split(":", 1)
        if item_name.strip() == name:
            return item_value.strip()
    return None


def _upsert_interface(
    device: Device,
    interface_name: str,
    *,
    role: InterfaceRole | None = None,
    tagged_vlan: int | None = None,
    untagged_vlan: int | None = None,
    pvid: int | None = None,
) -> None:
    """Internal helper for upsert interface."""
    existing = next((item for item in device.interfaces if item.name == interface_name), None)
    if existing is None:
        existing = Interface(device_id=device.device_id, name=interface_name)
        device.interfaces.append(existing)

    if role is not None and existing.role == InterfaceRole.UNKNOWN:
        existing.role = role
    if tagged_vlan is not None and tagged_vlan not in existing.tagged_vlans:
        existing.tagged_vlans.append(tagged_vlan)
    if untagged_vlan is not None and untagged_vlan not in existing.untagged_vlans:
        existing.untagged_vlans.append(untagged_vlan)
    if pvid is not None and existing.pvid is None:
        existing.pvid = pvid
