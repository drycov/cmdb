from __future__ import annotations

import logging

from commands.mikrotik import MikroTikCommands
from models import DeviceInfo
from services.ssh import SSHSession
from utils import parse_colon_output, parse_detail_blocks, parse_interface_brief


class MikroTikCollector:
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    @staticmethod
    def _parse_count(raw: str | None) -> str:
        if not raw:
            return ""

        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        if not lines:
            return ""

        return lines[-1]

    @staticmethod
    def _join_names(
        blocks: list[dict[str, str]],
        *keys: str,
    ) -> str:
        names: list[str] = []

        for block in blocks:
            for key in keys:
                value = str(block.get(key, "")).strip()
                if value:
                    names.append(value)
                    break

        return ", ".join(names)

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
                return str(item.get("mac_address", ""))
        for item in interfaces:
            if item.get("mac_address"):
                return str(item.get("mac_address", ""))
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
        # 1. По соседу
        if neighbor:
            iface = neighbor.get("interface", "")
            for item in interfaces:
                if item.get("name") == iface:
                    return str(item.get("name", "")), str(item.get("mac_address", ""))
            if iface:
                return iface, ""

        # 2. По комментарию uplink
        for item in interfaces:
            comment = str(item.get("comment", "")).lower()
            if "uplink" in comment:
                return str(item.get("name", "")), str(item.get("mac_address", ""))

        # 3. Первый running non-slave
        for item in interfaces:
            if item.get("running") and not item.get("slave"):
                return str(item.get("name", "")), str(item.get("mac_address", ""))

        # 4. Первый running
        for item in interfaces:
            if item.get("running"):
                return str(item.get("name", "")), str(item.get("mac_address", ""))

        return "", ""

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
        route_out = session.exec(MikroTikCommands.IP_ROUTE_DETAIL)
        vlan_out = session.exec(MikroTikCommands.VLAN_DETAIL)
        radius_out = session.exec(MikroTikCommands.RADIUS_DETAIL)
        watchdog_out = session.exec(MikroTikCommands.WATCHDOG_PRINT)

        resource = parse_colon_output(resource_out)
        identity = parse_colon_output(identity_out or "")
        routerboard = parse_colon_output(routerboard_out or "")
        license_data = parse_colon_output(license_out or "")
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
        route_blocks = parse_detail_blocks(route_out or "")
        vlan_blocks = parse_detail_blocks(vlan_out or "")
        radius_blocks = parse_detail_blocks(radius_out or "")

        primary_mac = self._find_primary_mac(interfaces)
        neighbor = self._find_neighbor(neighbor_blocks)
        uplink_interface, uplink_mac = self._find_uplink_interface(interfaces, neighbor)

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
            installed_packages=self._join_names(package_blocks, "name"),
            ospf_instance_count=str(len(ospf_instance_blocks)),
            ospf_neighbor_count=str(len(ospf_neighbor_blocks)),
            ospf_instances=self._join_names(ospf_instance_blocks, "name"),
            bridge_count=str(len(bridge_blocks)),
            bridge_port_count=str(len(bridge_port_blocks)),
            bridge_names=self._join_names(bridge_blocks, "name"),
            scheduler_count=str(len(scheduler_blocks)),
            scheduler_names=self._join_names(scheduler_blocks, "name"),
            dhcp_server_count=str(len(dhcp_server_blocks)),
            dhcp_client_count=str(len(dhcp_client_blocks)),
            ssh_port_value=self._find_service_port(service_blocks, "ssh"),
            winbox_port_value=self._find_service_port(service_blocks, "winbox"),
            firewall_filter_count=str(len(firewall_filter_blocks)),
            firewall_nat_count=str(len(firewall_nat_blocks)),
            route_count=str(len(route_blocks)),
            default_route_count=str(
                sum(
                    1
                    for item in route_blocks
                    if str(
                        item.get("dst_address")
                        or item.get("dst-address")
                        or item.get("dst")
                        or ""
                    ).strip() == "0.0.0.0/0"
                )
            ),
            vlan_count=str(len(vlan_blocks)),
            vlan_names=self._join_names(vlan_blocks, "name"),
            radius_count=str(len(radius_blocks)),
            watchdog_enabled=str(watchdog.get("watchdog_timer", "") or watchdog.get("automatic_supout", "")),
        )

        self.logger.debug(
            "Router data collection finished ip=%s identity=%s version=%s board=%s arch=%s uplink=%s neighbor=%s",
            session.ip,
            result.identity,
            result.version,
            result.board_name,
            result.architecture,
            result.uplink_interface,
            result.neighbor_identity,
        )

        return result
