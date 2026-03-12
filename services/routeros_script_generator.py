from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

from config import AppConfig
from models import AuditResult


class RouterOSScriptGenerator:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.inventory = self._load_inventory(config.inventory_path)
        self.output_dir = Path(config.log_dir) / "scripts"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _has_target_instance(self, result: AuditResult, instance_name: str) -> bool:
        instances = getattr(result, "ospf_instances", None)
        if not instances:
            return False

        for item in instances:
            if isinstance(item, str):
                if item.strip() == instance_name:
                    return True
                continue

            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                disabled = str(item.get("disabled", "false")).strip().lower()
                if name == instance_name and disabled not in {"true", "yes", "1"}:
                    return True

        return False

    def _has_correct_default_route(
        self,
        result: AuditResult,
        expected_gateway: str,
    ) -> bool:
        routes = getattr(result, "routes", None)
        if not routes:
            return False

        for route in routes:
            if not isinstance(route, dict):
                continue

            dst = str(
                route.get("dst")
                or route.get("dst-address")
                or route.get("dst_address")
                or ""
            ).strip()
            gateway = str(route.get("gateway", "")).strip()
            active = str(route.get("active", "true")).strip().lower()

            if dst == "0.0.0.0/0" and gateway == expected_gateway:
                if active in {"true", "yes", "1", ""}:
                    return True

        return False

    def _has_correct_interface_prefix(
        self,
        result: AuditResult,
        interface_name: str,
        expected_prefix: int,
        device_ip: str,
    ) -> bool:
        ip_addresses = getattr(result, "ip_addresses", None)
        if not ip_addresses:
            return False

        for item in ip_addresses:
            if not isinstance(item, dict):
                continue

            iface = str(item.get("interface", "")).strip()
            address = str(item.get("address", "")).strip()

            if iface != interface_name or "/" not in address:
                continue

            try:
                ipif = ipaddress.ip_interface(address)
            except ValueError:
                continue

            if str(ipif.ip) == device_ip and ipif.network.prefixlen == expected_prefix:
                return True

        return False

    def generate_for_result(self, result: AuditResult) -> Path | None:
        if not self._should_generate(result):
            return None

        vlan, matched_network = self._find_vlan_and_network_for_ip(result.ip)
        if vlan is None or matched_network is None:
            return None

        if self._is_ignored_ip(result.ip, vlan, matched_network):
            return None

        instance_name = str(vlan["ospf"]["instance"]).strip()
        expected_gateway = str(matched_network["gateway"]).strip()
        expected_prefix = ipaddress.ip_network(
            matched_network["subnet"],
            strict=False,
        ).prefixlen

        has_instance = self._has_target_instance(result, instance_name)
        has_default_route = self._has_correct_default_route(result, expected_gateway)
        has_correct_prefix = self._has_correct_interface_prefix(
            result=result,
            interface_name=str(vlan["name"]).strip(),
            expected_prefix=expected_prefix,
            device_ip=result.ip,
        )

        if has_instance and has_default_route and has_correct_prefix:
            return None

        script = self._build_hexs_722_ospf_script(
            vlan=vlan,
            matched_network=matched_network,
            device_ip=result.ip,
            need_mask_fix=not has_correct_prefix,
            need_default_route_fix=not has_default_route,
            need_instance_create=not has_instance,
        )

        if not script.strip():
            return None

        file_path = self._build_output_path(result.ip, vlan["name"])
        file_path.write_text(script, encoding="utf-8", newline="\n")
        return file_path

    def _should_generate(self, result: AuditResult) -> bool:
        board_name = (getattr(result, "board_name", "") or "").strip()
        version = self._extract_version(result)
        return board_name == "hEX S" and version.startswith("7.22")

    @staticmethod
    def _extract_version(result: AuditResult) -> str:
        for attr in ("version", "current_firmware", "firmware", "routeros_version"):
            value = getattr(result, attr, None)
            if value:
                return str(value).strip()
        return ""

    @staticmethod
    def _load_inventory(path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Inventory file not found: {path.resolve()}")

        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        if not isinstance(data, dict):
            raise ValueError("Inventory root must be a mapping/dict")

        return data

    def _find_vlan_and_network_for_ip(
        self,
        ip: str,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        device_ip = ipaddress.ip_address(ip)

        for vlan in self.inventory.get("vlans", []):
            if not isinstance(vlan, dict):
                continue

            for network in vlan.get("networks", []):
                if not isinstance(network, dict):
                    continue

                subnet_raw = network.get("subnet")
                if not subnet_raw:
                    continue

                subnet = ipaddress.ip_network(subnet_raw, strict=False)
                if device_ip in subnet:
                    return vlan, network

        return None, None

    def _is_ignored_ip(
        self,
        ip: str,
        vlan: dict[str, Any],
        network: dict[str, Any],
    ) -> bool:
        target_ip = str(ipaddress.ip_address(ip))
        ignored = self._normalize_ip_set(vlan.get("ignored_ips", []))
        ignored |= self._normalize_ip_set(network.get("ignored_ips", []))
        return target_ip in ignored

    @staticmethod
    def _normalize_ip_set(values: list[Any]) -> set[str]:
        result: set[str] = set()
        if not isinstance(values, list):
            return result

        for value in values:
            try:
                result.add(str(ipaddress.ip_address(str(value).strip())))
            except ValueError:
                continue
        return result

    def _build_output_path(self, ip: str, vlan_name: str) -> Path:
        safe_vlan_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", vlan_name.strip())
        safe_ip = ip.replace(".", "_")
        return self.output_dir / f"{safe_ip}__{safe_vlan_name}.rsc"

    @staticmethod
    def _build_hexs_722_ospf_script(
        vlan: dict[str, Any],
        matched_network: dict[str, Any],
        device_ip: str,
        need_mask_fix: bool,
        need_default_route_fix: bool,
        need_instance_create: bool,
    ) -> str:
        vlan_id = vlan["id"]
        iface_name = vlan["name"]

        ospf = vlan["ospf"]
        routing_id_name = ospf["routing_id"]
        instance_name = ospf["instance"]
        area_name = ospf["area"]
        area_id = ospf["area_id"]

        target_subnet = matched_network["subnet"]
        expected_gateway = matched_network["gateway"]
        target_prefix = ipaddress.ip_network(target_subnet, strict=False).prefixlen

        networks = vlan.get("networks", [])
        in_filter_rules = "\n".join(
            f'/routing filter rule add chain=in-net disabled=no rule="if (dst in {net["subnet"]}) {{accept}}"'
            for net in networks
            if isinstance(net, dict) and net.get("subnet")
        )

        blocks: list[str] = []

        if need_mask_fix:
            blocks.append(
                f"""# Align prefix on target management interface only if current prefix differs
:foreach i in=[/ip address find where interface="{iface_name}"] do={{
    :local addr [/ip address get $i address]
    :local slashPos [:find $addr "/"]
    :if ($slashPos != nil) do={{
        :local iponly [:pick $addr 0 $slashPos]
        :local currentPrefix [:pick $addr ($slashPos + 1) [:len $addr]]
        :if ($currentPrefix != "{target_prefix}") do={{
            /ip address set $i address=($iponly . "/{target_prefix}")
        }}
    }}
}}"""
            )

        if need_default_route_fix:
            blocks.append(
                f"""# Ensure correct default route
:foreach r in=[/ip route find where dst-address="0.0.0.0/0"] do={{
    :local gw [/ip route get $r gateway]
    :if ($gw != "{expected_gateway}") do={{
        /ip route remove $r
    }}
}}

:if ([:len [/ip route find where dst-address="0.0.0.0/0" and gateway="{expected_gateway}"]] = 0) do={{
    /ip route add disabled=no dst-address=0.0.0.0/0 gateway={expected_gateway}
}}"""
            )

        if need_instance_create:
            blocks.append(
                f"""# Remove legacy routing config
/routing bgp template remove [find name="default"]
/routing ospf area remove [find name="backbone-v2"]
/routing ospf instance remove [find name="default-v2"]
/routing bfd configuration remove [find where interfaces="all" and min-rx=200ms and min-tx=200ms and multiplier=5]

# Cleanup target config if already exists
/routing id remove [find name="{routing_id_name}"]
/routing ospf area remove [find name="{area_name}"]
/routing ospf instance remove [find name="{instance_name}"]
/routing filter rule remove [find chain="in-net"]
/routing filter rule remove [find chain="out-net"]
/routing ospf interface-template remove [find interfaces="{iface_name}"]

# Create new routing/OSPF config
/routing id add disabled=no id={device_ip} name={routing_id_name} select-dynamic-id=only-vrf select-from-vrf=main
/routing ospf instance add disabled=no in-filter-chain=in-net name={instance_name} out-filter-chain=out-net router-id={routing_id_name}
/routing ospf area add area-id={area_id} disabled=no instance={instance_name} name={area_name} type=stub

{in_filter_rules}
/routing filter rule add chain=in-net disabled=no rule="reject"
/routing filter rule add chain=out-net disabled=no rule="accept"

/routing ospf interface-template add area={area_name} disabled=no interfaces={iface_name}"""
            )

        if not blocks:
            return ""

        body = "\n\n".join(blocks)

        return f"""# ============================================================
# Auto-generated RouterOS migration script
# Device IP: {device_ip}
# VLAN ID: {vlan_id}
# Interface: {iface_name}
# Matched subnet: {target_subnet}
# Expected gateway: {expected_gateway}
# Target prefix: /{target_prefix}
# ============================================================

{body}
"""