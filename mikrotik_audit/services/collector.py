"""Implementation details for services collector."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from mikrotik_audit.commands.mikrotik import MikroTikCommands
from mikrotik_audit.models import DeviceInfo
from mikrotik_audit.services.ssh import SSHSession
from mikrotik_audit.utils import (
    parse_colon_output,
    parse_detail_blocks,
    parse_interface_brief,
    safe_int,
)


class MikroTikCollector:
    """Represent mikrotikcollector."""
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    @staticmethod
    def _parse_count(raw: str | None) -> str:
        if not raw:
            return ""

        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        return lines[-1] if lines else ""

    @staticmethod
    def _get(item: dict[str, Any], *keys: str) -> str:
        for key in keys:
            value = item.get(key)
            if value not in ("", None):
                return str(value).strip()
        return ""

    @staticmethod
    def _join_nonempty(*values: str) -> str:
        items = [value.strip() for value in values if value and value.strip()]
        return ", ".join(dict.fromkeys(items))

    @staticmethod
    def _normalize_ntp_enabled(ntp_client: dict[str, str]) -> str:
        enabled = str(ntp_client.get("enabled", "")).strip().lower()
        if enabled:
            return enabled

        mode = str(ntp_client.get("mode", "")).strip().lower()
        if not mode:
            return ""
        if mode in {"disabled", "off", "no"}:
            return "no"
        return "yes"

    @staticmethod
    def _join_values(
        blocks: list[dict[str, str]],
        *keys: str,
        limit: int = 30,
    ) -> str:
        values: list[str] = []

        for block in blocks:
            for key in keys:
                value = str(block.get(key, "")).strip()
                if value:
                    values.append(value)
                    break

        if len(values) > limit:
            return ", ".join(values[:limit]) + f", ... +{len(values) - limit}"

        return ", ".join(values)

    @staticmethod
    def _find_service_port(
        blocks: list[dict[str, str]],
        service_name: str,
    ) -> str:
        target = service_name.strip().lower()

        for block in blocks:
            if str(block.get("name", "")).strip().lower() != target:
                continue

            disabled = str(block.get("disabled", "")).strip().lower()
            port = str(block.get("port", "")).strip()

            if disabled in {"true", "yes", "1"}:
                return f"disabled:{port}" if port else "disabled"

            return port

        return ""

    @staticmethod
    def _find_primary_mac(interfaces: list[dict[str, object]]) -> str:
        for item in interfaces:
            if item.get("running") and item.get("mac_address"):
                return str(item["mac_address"])

        for item in interfaces:
            if item.get("mac_address"):
                return str(item["mac_address"])

        return ""

    @staticmethod
    def _find_neighbor(neighbor_blocks: list[dict[str, str]]) -> dict[str, str]:
        for item in neighbor_blocks:
            if item.get("interface"):
                return item
        return {}

    @staticmethod
    def _find_uplink_interface(
        interfaces: list[dict[str, object]],
        neighbor: dict[str, str],
    ) -> tuple[str, str]:
        if neighbor:
            iface = neighbor.get("interface", "")
            for item in interfaces:
                if item.get("name") == iface:
                    return str(item.get("name", "")), str(item.get("mac_address", ""))
            if iface:
                return iface, ""

        for item in interfaces:
            comment = str(item.get("comment", "")).lower()
            name = str(item.get("name", "")).lower()

            if "uplink" in comment or "uplink" in name or name.startswith("sfp"):
                return str(item.get("name", "")), str(item.get("mac_address", ""))

        for item in interfaces:
            if item.get("running") and not item.get("slave"):
                return str(item.get("name", "")), str(item.get("mac_address", ""))

        for item in interfaces:
            if item.get("running"):
                return str(item.get("name", "")), str(item.get("mac_address", ""))

        return "", ""

    @staticmethod
    def _summarize_ospf_neighbors(blocks: list[dict[str, str]]) -> dict[str, str]:
        states = Counter()
        unstable = 0
        dr = ""
        bdr = ""

        for item in blocks:
            state = str(item.get("state", "")).strip().lower()
            states[state or "unknown"] += 1

            changes = safe_int(item.get("state_changes", "0")) or 0
            if changes >= 10:
                unstable += 1

            if not dr:
                dr = str(item.get("dr", "")).strip()
            if not bdr:
                bdr = str(item.get("bdr", "")).strip()

        return {
            "ospf_full_neighbors": str(states.get("full", 0)),
            "ospf_twoway_neighbors": str(states.get("twoway", 0)),
            "ospf_other_neighbors": str(
                sum(count for state, count in states.items() if state not in {"full", "twoway"})
            ),
            "ospf_unstable_neighbors": str(unstable),
            "ospf_dr": dr,
            "ospf_bdr": bdr,
        }

    @staticmethod
    def _summarize_bridge(blocks: list[dict[str, str]]) -> dict[str, str]:
        if not blocks:
            return {
                "bridge_protocol_modes": "",
                "bridge_vlan_filtering": "",
                "bridge_igmp_snooping": "",
                "bridge_warning": "",
            }

        protocol_modes = []
        vlan_filtering = []
        igmp_snooping = []
        warnings = []

        for item in blocks:
            name = item.get("name", "")
            protocol = item.get("protocol_mode", "")
            vlan = item.get("vlan_filtering", "")
            igmp = item.get("igmp_snooping", "")

            if protocol:
                protocol_modes.append(f"{name}:{protocol}" if name else protocol)
            if vlan:
                vlan_filtering.append(f"{name}:{vlan}" if name else vlan)
            if igmp:
                igmp_snooping.append(f"{name}:{igmp}" if name else igmp)

            if protocol == "none":
                warnings.append(f"{name}:STP_DISABLED" if name else "STP_DISABLED")

        return {
            "bridge_protocol_modes": ", ".join(protocol_modes),
            "bridge_vlan_filtering": ", ".join(vlan_filtering),
            "bridge_igmp_snooping": ", ".join(igmp_snooping),
            "bridge_warning": ", ".join(warnings),
        }


    @staticmethod
    def _split_ports(value: str) -> list[str]:
        if not value:
            return []

        return [
            item.strip()
            for item in value.replace(",", " ").split()
            if item.strip()
        ]


    @staticmethod
    def _split_vlan_ids(value: str) -> list[str]:
        if not value:
            return []

        result: list[str] = []

        for part in value.replace(",", " ").split():
            part = part.strip()

            if "-" in part:
                start, end = part.split("-", 1)
                if start.isdigit() and end.isdigit():
                    result.extend(str(vlan_id) for vlan_id in range(int(start), int(end) + 1))
                continue

            if part:
                result.append(part)

        return result


    @staticmethod
    def _vlan_hex(vlan_id: str) -> str:
        try:
            return f"0x{int(vlan_id):04X}"
        except Exception:
            return ""


    @classmethod
    def _build_vlan_table(
        cls,
        *,
        identity: str,
        vlan_blocks: list[dict[str, str]],
        bridge_vlan_blocks: list[dict[str, str]],
        bridge_port_blocks: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        vlan_interfaces_by_id: dict[str, list[dict[str, str]]] = {}

        for item in vlan_blocks:
            vlan_id = item.get("vlan_id", "")
            if not vlan_id:
                continue

            vlan_interfaces_by_id.setdefault(vlan_id, []).append(
                {
                    "name": item.get("name", ""),
                    "interface": item.get("interface", ""),
                    "mtu": item.get("mtu", ""),
                    "mac_address": item.get("mac_address", ""),
                    "comment": item.get("comment", ""),
                }
            )

        pvid_ports_by_vlan: dict[str, list[str]] = {}

        for item in bridge_port_blocks:
            pvid = item.get("pvid", "")
            interface = item.get("interface", "")

            if pvid and interface:
                pvid_ports_by_vlan.setdefault(pvid, []).append(interface)

        rows_by_vlan: dict[str, dict[str, Any]] = {}

        for item in bridge_vlan_blocks:
            bridge = item.get("bridge", "")
            vlan_ids = cls._split_vlan_ids(item.get("vlan_ids", ""))
            tagged_ports = cls._split_ports(item.get("tagged", ""))
            untagged_ports = cls._split_ports(item.get("untagged", ""))

            for vlan_id in vlan_ids:
                rows_by_vlan[vlan_id] = {
                    "device_identity": identity,
                    "vlan_id": vlan_id,
                    "vlan_hex": cls._vlan_hex(vlan_id),
                    "bridge": bridge,
                    "vlan_interfaces": vlan_interfaces_by_id.get(vlan_id, []),
                    "tagged_ports": tagged_ports,
                    "untagged_ports": untagged_ports,
                    "pvid_ports": pvid_ports_by_vlan.get(vlan_id, []),
                    "source": {
                        "interface_vlan": bool(vlan_interfaces_by_id.get(vlan_id)),
                        "bridge_vlan": True,
                        "bridge_port": bool(pvid_ports_by_vlan.get(vlan_id)),
                    },
                }

        for vlan_id, vlan_interfaces in vlan_interfaces_by_id.items():
            if vlan_id in rows_by_vlan:
                continue

            rows_by_vlan[vlan_id] = {
                "device_identity": identity,
                "vlan_id": vlan_id,
                "vlan_hex": cls._vlan_hex(vlan_id),
                "bridge": "",
                "vlan_interfaces": vlan_interfaces,
                "tagged_ports": [],
                "untagged_ports": [],
                "pvid_ports": pvid_ports_by_vlan.get(vlan_id, []),
                "source": {
                    "interface_vlan": True,
                    "bridge_vlan": False,
                    "bridge_port": bool(pvid_ports_by_vlan.get(vlan_id)),
                },
            }

        return sorted(rows_by_vlan.values(), key=lambda row: int(row["vlan_id"]))


    @staticmethod
    def _summarize_bridge_ports(blocks: list[dict[str, str]]) -> dict[str, str]:
        hw = 0
        restricted = []
        access_ports = []
        trunk_like_ports = []

        for item in blocks:
            iface = item.get("interface", "")
            if item.get("hw") in {"yes", "true"} or "H" in item.get("flags", ""):
                hw += 1

            if item.get("restricted_role") == "yes":
                restricted.append(iface)

            pvid = item.get("pvid", "")
            frame_types = item.get("frame_types", "")

            if pvid and pvid != "1":
                access_ports.append(f"{iface}:pvid={pvid}")

            if frame_types in {"admit-only-vlan-tagged", "admit-all"}:
                trunk_like_ports.append(f"{iface}:{frame_types}")

        return {
            "bridge_hw_offload_ports": str(hw),
            "bridge_restricted_role_ports": ", ".join(restricted),
            "bridge_access_ports": ", ".join(access_ports),
            "bridge_trunk_like_ports": ", ".join(trunk_like_ports),
        }

    @staticmethod
    def _summarize_routes(blocks: list[dict[str, str]]) -> dict[str, str]:
        default_routes = 0
        disabled = 0
        dynamic = 0
        static = 0

        for item in blocks:
            dst = (
                item.get("dst_address")
                or item.get("dst-address")
                or item.get("dst")
                or ""
            )

            flags = item.get("flags", "")

            if str(dst).strip() == "0.0.0.0/0":
                default_routes += 1
            if item.get("disabled") == "yes" or "X" in flags:
                disabled += 1
            if item.get("dynamic") == "yes" or "D" in flags:
                dynamic += 1
            if item.get("static") == "yes" or "S" in flags:
                static += 1

        return {
            "default_route_count": str(default_routes),
            "disabled_route_count": str(disabled),
            "dynamic_route_count": str(dynamic),
            "static_route_count": str(static),
        }

    @staticmethod
    def _summarize_firewall(blocks: list[dict[str, str]]) -> dict[str, str]:
        disabled = 0
        drops = 0
        accepts = 0

        for item in blocks:
            action = item.get("action", "").lower()
            flags = item.get("flags", "")

            if item.get("disabled") == "yes" or "X" in flags:
                disabled += 1
            if action == "drop":
                drops += 1
            if action == "accept":
                accepts += 1

        return {
            "firewall_filter_disabled_count": str(disabled),
            "firewall_filter_drop_count": str(drops),
            "firewall_filter_accept_count": str(accepts),
        }

    def collect_router_data(self, session: SSHSession) -> DeviceInfo | None:
        self.logger.debug(
            "Router data collection started ip=%s user=%s",
            session.ip,
            session.credentials.username,
        )

        resource_out = session.exec(MikroTikCommands.SYSTEM_RESOURCE)
        if resource_out is None:
            self.logger.debug(
                "Resource collection failed ip=%s user=%s",
                session.ip,
                session.credentials.username,
            )
            return None

        identity_out = session.exec(MikroTikCommands.SYSTEM_IDENTITY)
        routerboard_out = session.exec(MikroTikCommands.SYSTEM_ROUTERBOARD)
        license_out = session.exec(MikroTikCommands.SYSTEM_LICENSE)
        package_out = session.exec(MikroTikCommands.SYSTEM_PACKAGE)
        interfaces_out = session.exec(MikroTikCommands.INTERFACE_COUNT)

        interface_brief_out = session.exec(MikroTikCommands.INTERFACE_MAC_COMMENT_BRIEF)
        neighbor_out = session.exec(MikroTikCommands.IP_NEIGHBOR_DETAIL)
        ospf_instance_out = session.exec(MikroTikCommands.ROUTING_OSPF_INSTANCE_DETAIL)
        ospf_neighbor_out = session.exec(MikroTikCommands.ROUTING_OSPF_NEIGHBOR_DETAIL)
        bridge_out = session.exec(MikroTikCommands.BRIDGE_DETAIL)
        bridge_port_out = session.exec(MikroTikCommands.BRIDGE_PORT_DETAIL)
        scheduler_out = session.exec(MikroTikCommands.SYSTEM_SCHEDULER_DETAIL)
        dhcp_server_out = session.exec(MikroTikCommands.DHCP_SERVER_DETAIL)
        dhcp_client_out = session.exec(MikroTikCommands.DHCP_CLIENT_DETAIL)
        service_out = session.exec(MikroTikCommands.IP_SERVICE_DETAIL)
        firewall_filter_out = session.exec(MikroTikCommands.FIREWALL_FILTER_DETAIL)
        firewall_nat_out = session.exec(MikroTikCommands.FIREWALL_NAT_DETAIL)
        ip_address_out = session.exec(MikroTikCommands.IP_ADDRESS_DETAIL)
        route_out = session.exec(MikroTikCommands.IP_ROUTE_DETAIL)
        vlan_out = session.exec(MikroTikCommands.VLAN_DETAIL)
        radius_out = session.exec(MikroTikCommands.RADIUS_DETAIL)
        ntp_client_out = (
            session.exec(
                MikroTikCommands.SYSTEM_NTP_CLIENT_DETAIL,
                warn_on_error=False,
            )
            or session.exec(
                MikroTikCommands.SYSTEM_NTP_CLIENT,
                warn_on_error=False,
            )
            or ""
        )
        ntp_servers_out = (
            session.exec(
                MikroTikCommands.SYSTEM_NTP_CLIENT_SERVERS_DETAIL,
                warn_on_error=False,
            )
            or session.exec(
                MikroTikCommands.SYSTEM_NTP_CLIENT_SERVERS,
                warn_on_error=False,
            )
            or ""
        )
        watchdog_out = session.exec(MikroTikCommands.WATCHDOG_PRINT)

        resource = parse_colon_output(resource_out)
        identity = parse_colon_output(identity_out or "")
        routerboard = parse_colon_output(routerboard_out or "")
        license_data = parse_colon_output(license_out or "")
        ntp_client = parse_colon_output(ntp_client_out or "")
        watchdog = parse_colon_output(watchdog_out or "")

        interface_count = self._parse_count(interfaces_out)

        interfaces = parse_interface_brief(interface_brief_out or "")
        neighbor_blocks = parse_detail_blocks(neighbor_out or "")
        package_blocks = parse_detail_blocks(package_out or "")
        ospf_instance_blocks = parse_detail_blocks(ospf_instance_out or "")
        ospf_neighbor_blocks = parse_detail_blocks(ospf_neighbor_out or "")
        bridge_blocks = parse_detail_blocks(bridge_out or "")
        bridge_port_blocks = parse_detail_blocks(bridge_port_out or "")
        scheduler_blocks = parse_detail_blocks(scheduler_out or "")
        dhcp_server_blocks = parse_detail_blocks(dhcp_server_out or "")
        dhcp_client_blocks = parse_detail_blocks(dhcp_client_out or "")
        service_blocks = parse_detail_blocks(service_out or "")
        firewall_filter_blocks = parse_detail_blocks(firewall_filter_out or "")
        firewall_nat_blocks = parse_detail_blocks(firewall_nat_out or "")
        ip_address_blocks = parse_detail_blocks(ip_address_out or "")
        route_blocks = parse_detail_blocks(route_out or "")
        vlan_blocks = parse_detail_blocks(vlan_out or "")
        radius_blocks = parse_detail_blocks(radius_out or "")
        ntp_server_blocks = parse_detail_blocks(ntp_servers_out or "")
        ntp_servers_value = self._join_values(
            ntp_server_blocks,
            "address",
            "server",
            "host",
        )
        if not ntp_servers_value:
            ntp_servers_value = self._join_nonempty(
                str(ntp_client.get("primary_ntp", "")),
                str(ntp_client.get("secondary_ntp", "")),
                str(ntp_client.get("server_dns_names", "")),
                str(ntp_client.get("servers", "")),
            )

        primary_mac = self._find_primary_mac(interfaces)
        neighbor = self._find_neighbor(neighbor_blocks)
        uplink_interface, uplink_mac = self._find_uplink_interface(interfaces, neighbor)

        ospf_summary = self._summarize_ospf_neighbors(ospf_neighbor_blocks)
        bridge_summary = self._summarize_bridge(bridge_blocks)
        bridge_port_summary = self._summarize_bridge_ports(bridge_port_blocks)
        route_summary = self._summarize_routes(route_blocks)
        firewall_summary = self._summarize_firewall(firewall_filter_blocks)
        bridge_vlan_out = session.exec(MikroTikCommands.BRIDGE_VLAN_DETAIL)
        bridge_vlan_blocks = parse_detail_blocks(bridge_vlan_out or "")

        vlan_table = self._build_vlan_table(
    identity=identity.get("name", ""),
    vlan_blocks=vlan_blocks,
    bridge_vlan_blocks=bridge_vlan_blocks,
    bridge_port_blocks=bridge_port_blocks,
)

        result = DeviceInfo(
            identity=identity.get("name", ""),
            version=resource.get("version", ""),
            uptime=resource.get("uptime", ""),
            cpu_load=resource.get("cpu_load", ""),
            board_name=resource.get("board_name", ""),
            platform=resource.get("platform", ""),
            architecture=resource.get("architecture_name", ""),
            total_memory=resource.get("total_memory", ""),
            free_memory=resource.get("free_memory", ""),
            total_hdd=resource.get("total_hdd_space", ""),
            free_hdd=resource.get("free_hdd_space", ""),
            license=license_data.get("software_id", "") or license_data.get("level", ""),
            current_firmware=routerboard.get("current_firmware", ""),
            upgrade_firmware=routerboard.get("upgrade_firmware", ""),
            interface_count=interface_count,
            mac_address=primary_mac,
            uplink_interface=uplink_interface,
            uplink_mac=uplink_mac,
            neighbor_identity=neighbor.get("identity", ""),
            neighbor_address=neighbor.get("address", ""),
            neighbor_interface=neighbor.get("interface", ""),
            neighbor_mac=neighbor.get("mac_address", ""),
            installed_packages=self._join_values(package_blocks, "name"),
            ospf_instance_count=str(len(ospf_instance_blocks)),
            ospf_neighbor_count=str(len(ospf_neighbor_blocks)),
            ospf_instances=self._join_values(ospf_instance_blocks, "name"),
            ospf_instance_details=ospf_instance_blocks,
            bridge_count=str(len(bridge_blocks)),
            bridge_port_count=str(len(bridge_port_blocks)),
            bridge_names=self._join_values(bridge_blocks, "name"),
            scheduler_count=str(len(scheduler_blocks)),
            scheduler_names=self._join_values(scheduler_blocks, "name"),
            dhcp_server_count=str(len(dhcp_server_blocks)),
            dhcp_client_count=str(len(dhcp_client_blocks)),
            ssh_port_value=self._find_service_port(service_blocks, "ssh"),
            winbox_port_value=self._find_service_port(service_blocks, "winbox"),
            firewall_filter_count=str(len(firewall_filter_blocks)),
            firewall_nat_count=str(len(firewall_nat_blocks)),
            route_count=str(len(route_blocks)),
            routes=route_blocks,
            ip_addresses=ip_address_blocks,
            vlan_count=str(len(vlan_blocks)),
            vlan_names=self._join_values(vlan_blocks, "name"),
            ospf_neighbor_details=ospf_neighbor_blocks,
            radius_count=str(len(radius_blocks)),
            ntp_enabled=self._normalize_ntp_enabled(ntp_client),
            ntp_servers=ntp_servers_value,
            watchdog_enabled=str(
                watchdog.get("watchdog_timer", "")
                or watchdog.get("automatic_supout", "")
            ),
            watchdog_automatic_supout=str(watchdog.get("automatic_supout", "")),
            watchdog_ping_start_after_boot=str(
                watchdog.get("ping_start_after_boot", "")
            ),
            watchdog_ping_timeout=str(watchdog.get("ping_timeout", "")),
            watchdog_timer=str(watchdog.get("watchdog_timer", "")),
            vlan_table=vlan_table,

            # Новые расширенные поля.
            **ospf_summary,
            **bridge_summary,
            **bridge_port_summary,
            **route_summary,
            **firewall_summary,
        )

        self.logger.debug(
            "Router data collection finished ip=%s identity=%s version=%s board=%s arch=%s "
            "uplink=%s neighbor=%s ospf_full=%s ospf_twoway=%s bridge_warning=%s",
            session.ip,
            result.identity,
            result.version,
            result.board_name,
            result.architecture,
            result.uplink_interface,
            result.neighbor_identity,
            getattr(result, "ospf_full_neighbors", ""),
            getattr(result, "ospf_twoway_neighbors", ""),
            getattr(result, "bridge_warning", ""),
        )

        return result
