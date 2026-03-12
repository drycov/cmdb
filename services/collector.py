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
        interfaces_out = session.exec(MikroTikCommands.INTERFACE_COUNT)

        interface_brief_out = session.exec(MikroTikCommands.INTERFACE_MAC_COMMENT_BRIEF)
        neighbor_out = session.exec(MikroTikCommands.IP_NEIGHBOR_DETAIL)

        resource = parse_colon_output(resource_out)
        identity = parse_colon_output(identity_out or "")
        routerboard = parse_colon_output(routerboard_out or "")
        license_data = parse_colon_output(license_out or "")

        interface_count = self._parse_count(interfaces_out)

        interfaces = parse_interface_brief(interface_brief_out or "")
        neighbor_blocks = parse_detail_blocks(neighbor_out or "")

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