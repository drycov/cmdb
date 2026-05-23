"""Implementation details for services routeros_script_generator."""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from mikrotik_audit.commands.mikrotik import MikroTikCommands
from mikrotik_audit.config import AppConfig, load_yaml_file, normalize_inventory_data
from mikrotik_audit.models import AuditResult, Credentials
from mikrotik_audit.services.collector import MikroTikCollector
from mikrotik_audit.services.ssh import SSHService


@dataclass(slots=True)
class GatewayTemplate:
    """Represent gatewaytemplate."""
    vlan_id: str
    gateway_interface: str
    target_interface: str
    address: str
    network: str
    source_identity: str
    bridge: str
    tagged_ports: str
    untagged_ports: str
    pvid_ports: str


@dataclass(slots=True)
class GenerationPlan:
    """Represent generationplan."""
    result: AuditResult
    vlan: dict[str, Any]
    matched_network: dict[str, Any]
    gateway_result: AuditResult | None
    gateway_templates: list[GatewayTemplate]
    need_mask_fix: bool
    need_default_route_fix: bool
    need_instance_create: bool
    scheduler_script: str
    ntp_script: str
    clock_script: str


class RouterOSScriptGenerator:
    """Represent routerosscriptgenerator."""
    def __init__(
        self,
        config: AppConfig,
        ssh: SSHService | None = None,
        collector: MikroTikCollector | None = None,
        logger: logging.Logger | None = None,
        gateway_credentials: Credentials | None = None,
    ) -> None:
        self.config = config
        self.ssh = ssh
        self.collector = collector
        self.logger = logger
        self.gateway_credentials = gateway_credentials
        self.inventory = self._load_inventory(config.inventory_path)
        self._gateway_results_by_ip: dict[str, AuditResult | None] = {}
        self.output_dir = Path(config.log_dir) / "scripts"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_for_result(
        self,
        result: AuditResult,
        scanned_results: Iterable[AuditResult] | None = None,
    ) -> Path | None:
        plan = self._build_plan(
            result=result,
            scanned_results=scanned_results or [],
        )
        if plan is None:
            return None

        script = self._render_script(plan)
        if not script.strip():
            return None

        file_path = self._build_output_path(plan.result.ip, str(plan.vlan["name"]))
        file_path.write_text(script, encoding="utf-8", newline="\n")
        return file_path

    def _build_plan(
        self,
        *,
        result: AuditResult,
        scanned_results: Iterable[AuditResult],
    ) -> GenerationPlan | None:
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

        need_instance_create = not self._has_target_instance(result, instance_name)
        need_default_route_fix = not self._has_correct_default_route(result, expected_gateway)
        need_mask_fix = not self._has_correct_interface_prefix(
            result=result,
            interface_name=str(vlan["name"]).strip(),
            expected_prefix=expected_prefix,
            device_ip=result.ip,
        )

        gateway_result = self._resolve_gateway_result(
            gateway_ip=expected_gateway,
            scanned_results=scanned_results,
        )
        gateway_templates = self._extract_gateway_templates(
            result=result,
            vlan=vlan,
            matched_network=matched_network,
            gateway_result=gateway_result,
        )

        scheduler_script = self._build_scheduler_script(result)
        ntp_script = self._build_ntp_script()
        clock_script = self._build_clock_script()

        has_extra_changes = any(
            [
                gateway_templates,
                scheduler_script,
                ntp_script,
                clock_script,
            ]
        )
        if not any([need_instance_create, need_default_route_fix, need_mask_fix, has_extra_changes]):
            return None

        return GenerationPlan(
            result=result,
            vlan=vlan,
            matched_network=matched_network,
            gateway_result=gateway_result,
            gateway_templates=gateway_templates,
            need_mask_fix=need_mask_fix,
            need_default_route_fix=need_default_route_fix,
            need_instance_create=need_instance_create,
            scheduler_script=scheduler_script,
            ntp_script=ntp_script,
            clock_script=clock_script,
        )

    def _render_script(self, plan: GenerationPlan) -> str:
        gateway_context = self._build_gateway_context(plan)
        summary_block = self._build_summary_block(plan)
        template_block = self._build_template_summary(plan.gateway_templates)
        remediation_blocks = self._build_remediation_blocks(plan)

        if not remediation_blocks:
            return ""

        vlan_id = str(plan.vlan["id"])
        iface_name = str(plan.vlan["name"])
        matched_subnet = str(plan.matched_network["subnet"])
        expected_gateway = str(plan.matched_network["gateway"])
        target_prefix = ipaddress.ip_network(matched_subnet, strict=False).prefixlen

        context = "\n".join(gateway_context)
        if context:
            context += "\n"

        template_summary = "\n".join(template_block)
        if template_summary:
            template_summary += "\n"

        body = "\n\n".join(remediation_blocks)
        return f"""# ============================================================
# Auto-generated RouterOS migration script
# Device IP: {plan.result.ip}
# VLAN ID: {vlan_id}
# Interface: {iface_name}
# Matched subnet: {matched_subnet}
# Expected gateway: {expected_gateway}
# Target prefix: /{target_prefix}
{context}# Data source: scanned target result
{summary_block}
{template_summary}# Interface-template networks pulled from gateway VLAN addresses
# ============================================================

{body}
"""

    def _build_remediation_blocks(self, plan: GenerationPlan) -> list[str]:
        blocks: list[str] = []

        if plan.need_mask_fix:
            blocks.append(self._render_mask_fix_block(plan))

        if plan.need_default_route_fix:
            blocks.append(self._render_default_route_block(plan))

        if plan.gateway_templates and not plan.need_instance_create:
            blocks.append(self._render_incremental_camera_block(plan))

        if plan.need_instance_create:
            blocks.append(self._render_ospf_rebuild_block(plan))

        if plan.scheduler_script:
            blocks.append(plan.scheduler_script)

        if plan.ntp_script:
            blocks.append(plan.ntp_script)

        if plan.clock_script:
            blocks.append(plan.clock_script)

        return [block for block in blocks if block.strip()]

    def _render_mask_fix_block(self, plan: GenerationPlan) -> str:
        iface_name = str(plan.vlan["name"]).strip()
        target_prefix = ipaddress.ip_network(
            str(plan.matched_network["subnet"]),
            strict=False,
        ).prefixlen
        return f"""# Align prefix on target management interface only if current prefix differs
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

    def _render_default_route_block(self, plan: GenerationPlan) -> str:
        expected_gateway = str(plan.matched_network["gateway"]).strip()
        return f"""# Ensure correct default route
:foreach r in=[/ip route find where dst-address="0.0.0.0/0"] do={{
    :local gw [/ip route get $r gateway]
    :if ($gw != "{expected_gateway}") do={{
        /ip route remove $r
    }}
}}

:if ([:len [/ip route find where dst-address="0.0.0.0/0" and gateway="{expected_gateway}"]] = 0) do={{
    /ip route add disabled=no dst-address=0.0.0.0/0 gateway={expected_gateway}
}}"""

    def _render_incremental_camera_block(self, plan: GenerationPlan) -> str:
        area_name = str(plan.vlan["ospf"]["area"]).strip()
        ip_lines = [
            (
                f':if ([:len [/ip address find where interface="{item.target_interface}" and address="{item.address}"]] = 0) do={{ '
                f'/ip address add address={item.address} interface={item.target_interface} '
                "}"
            )
            for item in plan.gateway_templates
            if item.address and item.target_interface
        ]
        ospf_lines = [
            (
                f':if ([:len [/routing ospf interface-template find where area="{area_name}" and networks={item.network}]] = 0) do={{ '
                f'/routing ospf interface-template add area={area_name} disabled=no networks={item.network} '
                "}"
            )
            for item in plan.gateway_templates
            if item.network
        ]
        return "\n".join(
            [
                "# Add gateway-derived camera IP addresses on target untagged interfaces",
                *ip_lines,
                "",
                "# Add gateway-derived OSPF interface-template networks that are missing",
                *ospf_lines,
            ]
        ).strip()

    def _render_ospf_rebuild_block(self, plan: GenerationPlan) -> str:
        ospf = plan.vlan["ospf"]
        iface_name = str(plan.vlan["name"]).strip()
        routing_id_name = str(ospf["routing_id"]).strip()
        instance_name = str(ospf["instance"]).strip()
        area_name = str(ospf["area"]).strip()
        area_id = str(ospf["area_id"]).strip()
        camera_ip_lines = "\n".join(
            f"/ip address add address={item.address} interface={item.target_interface}"
            for item in plan.gateway_templates
            if item.address and item.target_interface
        )
        if camera_ip_lines:
            camera_ip_lines += "\n"

        filter_rules = "\n".join(
            f'/routing filter rule add chain=in-net disabled=no rule="if (dst in {net["subnet"]}) {{accept}}"'
            for net in plan.vlan.get("networks", [])
            if isinstance(net, dict) and net.get("subnet")
        )
        camera_template_lines = "\n".join(
            f"/routing ospf interface-template add area={area_name} disabled=no networks={item.network}"
            for item in plan.gateway_templates
            if item.network
        )
        if camera_template_lines:
            camera_template_lines = camera_template_lines + "\n"

        return f"""# Remove legacy routing config
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
/routing id add disabled=no id={plan.result.ip} name={routing_id_name} select-dynamic-id=only-vrf select-from-vrf=main
/routing ospf instance add disabled=no in-filter-chain=in-net name={instance_name} out-filter-chain=out-net router-id={routing_id_name}
/routing ospf area add area-id={area_id} disabled=no instance={instance_name} name={area_name} type=stub

{filter_rules}
/routing filter rule add chain=in-net disabled=no rule="reject"
/routing filter rule add chain=out-net disabled=no rule="accept"

/routing ospf interface-template add area={area_name} disabled=no interfaces={iface_name}
{camera_ip_lines}{camera_template_lines}""".rstrip()

    def _build_summary_block(self, plan: GenerationPlan) -> str:
        lines = [
            f"# Planned changes: prefix_fix={'yes' if plan.need_mask_fix else 'no'}",
            f"# Planned changes: default_route_fix={'yes' if plan.need_default_route_fix else 'no'}",
            f"# Planned changes: ospf_rebuild={'yes' if plan.need_instance_create else 'no'}",
            f"# Planned changes: camera_ip_add={'yes' if any(item.address and item.target_interface for item in plan.gateway_templates) else 'no'}",
            f"# Planned changes: gateway_template_add={'yes' if bool(plan.gateway_templates) else 'no'}",
            f"# Planned changes: scheduler={'yes' if bool(plan.scheduler_script) else 'no'}",
            f"# Planned changes: ntp={'yes' if bool(plan.ntp_script) else 'no'}",
            f"# Planned changes: clock={'yes' if bool(plan.clock_script) else 'no'}",
        ]
        return "\n".join(lines)

    def _build_template_summary(self, templates: list[GatewayTemplate]) -> list[str]:
        return [
            (
                f"# Gateway VLAN template: vlan={item.vlan_id} "
                f"iface={item.gateway_interface} "
                f"hex_untagged_iface={item.target_interface or '-'} "
                f"address={item.address or '-'} "
                f"network={item.network} "
                f"bridge={item.bridge or '-'} "
                f"source={item.source_identity}"
            )
            for item in templates
        ]

    def _build_gateway_context(self, plan: GenerationPlan) -> list[str]:
        gateway_result = plan.gateway_result
        if gateway_result is None:
            return []

        mgmt_vlan_id = str(plan.vlan["id"]).strip()
        lines = [
            f"# Linked gateway scan: {gateway_result.identity or '<unknown>'} ({gateway_result.ip})",
        ]

        gateway_rows = self._target_vlan_rows_by_id(gateway_result)
        mgmt_row = gateway_rows.get(mgmt_vlan_id)
        if mgmt_row is not None:
            lines.extend(
                [
                    f'# Gateway management VLAN {mgmt_vlan_id}: bridge={str(mgmt_row.get("bridge", "")).strip() or "-"}',
                    f'# Gateway management tagged ports={",".join(mgmt_row.get("tagged_ports", []) or []) or "-"}',
                    f'# Gateway management untagged ports={",".join(mgmt_row.get("untagged_ports", []) or []) or "-"}',
                    f'# Gateway management PVID ports={",".join(mgmt_row.get("pvid_ports", []) or []) or "-"}',
                ]
            )

        if not plan.gateway_templates:
            return lines

        lines.append("# Gateway source VLANs used for OSPF template networks:")
        target_rows = self._target_vlan_rows_by_id(plan.result)
        seen_vlan_ids: set[str] = set()
        for item in plan.gateway_templates:
            if item.vlan_id in seen_vlan_ids:
                continue
            seen_vlan_ids.add(item.vlan_id)
            lines.append(
                "#   VLAN {vlan}: iface={iface} bridge={bridge} tagged={tagged} untagged={untagged} pvid={pvid}".format(
                    vlan=item.vlan_id,
                    iface=item.gateway_interface or "-",
                    bridge=item.bridge or "-",
                    tagged=item.tagged_ports or "-",
                    untagged=item.untagged_ports or "-",
                    pvid=item.pvid_ports or "-",
                )
            )
            target_row = target_rows.get(item.vlan_id)
            if target_row is None:
                lines.append(f"#   hEX VLAN {item.vlan_id}: not present in target vlan_table")
                continue

            target_vlan_interfaces = target_row.get("vlan_interfaces", []) or []
            target_ifaces = ",".join(
                str(iface.get("name", "")).strip()
                for iface in target_vlan_interfaces
                if isinstance(iface, dict) and str(iface.get("name", "")).strip()
            ) or "-"
            lines.append(
                "#   hEX VLAN {vlan}: iface={iface} bridge={bridge} tagged={tagged} untagged={untagged} pvid={pvid}".format(
                    vlan=item.vlan_id,
                    iface=target_ifaces,
                    bridge=str(target_row.get("bridge", "")).strip() or "-",
                    tagged=",".join(target_row.get("tagged_ports", []) or []) or "-",
                    untagged=",".join(target_row.get("untagged_ports", []) or []) or "-",
                    pvid=",".join(target_row.get("pvid_ports", []) or []) or "-",
                )
            )
            lines.append(
                f"#   hEX camera L3 target for VLAN {item.vlan_id}: untagged-iface={item.target_interface or '-'}"
            )

        return lines

    def _extract_gateway_templates(
        self,
        *,
        result: AuditResult,
        vlan: dict[str, Any],
        matched_network: dict[str, Any],
        gateway_result: AuditResult | None,
    ) -> list[GatewayTemplate]:
        if gateway_result is None:
            return []

        mgmt_subnet = str(matched_network.get("subnet", "")).strip()
        mgmt_vlan_id = str(vlan.get("id", "")).strip()
        target_vlan_ids = self._extract_target_vlan_ids(
            result,
            exclude_vlan_id=mgmt_vlan_id,
        )
        if not target_vlan_ids:
            return []

        gateway_networks = self._gateway_networks_by_vlan(gateway_result)
        templates: list[GatewayTemplate] = []
        seen_networks: set[str] = set()

        for vlan_id in target_vlan_ids:
            for raw in gateway_networks.get(vlan_id, []):
                network = str(raw.get("network", "")).strip()
                if not network or network == mgmt_subnet or network in seen_networks:
                    continue

                seen_networks.add(network)
                templates.append(
                    GatewayTemplate(
                        vlan_id=vlan_id,
                        gateway_interface=str(raw.get("interface", "")).strip(),
                        target_interface=self._target_untagged_interface_for_vlan(result, vlan_id),
                        address=str(raw.get("address", "")).strip(),
                        network=network,
                        source_identity=str(raw.get("source_identity", "")).strip(),
                        bridge=str(raw.get("bridge", "")).strip(),
                        tagged_ports=str(raw.get("tagged_ports", "")).strip(),
                        untagged_ports=str(raw.get("untagged_ports", "")).strip(),
                        pvid_ports=str(raw.get("pvid_ports", "")).strip(),
                    )
                )

        return sorted(
            templates,
            key=lambda item: (
                int(item.vlan_id) if item.vlan_id.isdigit() else 0,
                item.network,
            ),
        )

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

        data = normalize_inventory_data(load_yaml_file(path))
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
                if device_ip in ipaddress.ip_network(subnet_raw, strict=False):
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
    def _extract_target_vlan_ids(
        result: AuditResult,
        *,
        exclude_vlan_id: str,
    ) -> list[str]:
        vlan_ids: set[str] = set()
        for row in getattr(result, "vlan_table", []) or []:
            if not isinstance(row, dict):
                continue
            vlan_id = str(row.get("vlan_id", "")).strip()
            if vlan_id and vlan_id != exclude_vlan_id:
                vlan_ids.add(vlan_id)
        return sorted(vlan_ids, key=lambda item: int(item) if item.isdigit() else item)

    @staticmethod
    def _gateway_networks_by_vlan(
        gateway_result: AuditResult,
    ) -> dict[str, list[dict[str, str]]]:
        networks_by_vlan: dict[str, list[dict[str, str]]] = {}
        vlan_rows = getattr(gateway_result, "vlan_table", []) or []
        ip_addresses = getattr(gateway_result, "ip_addresses", []) or []

        for row in vlan_rows:
            if not isinstance(row, dict):
                continue

            vlan_id = str(row.get("vlan_id", "")).strip()
            if not vlan_id:
                continue

            interface_names = {
                str(iface.get("name", "")).strip()
                for iface in row.get("vlan_interfaces", []) or []
                if isinstance(iface, dict) and str(iface.get("name", "")).strip()
            }
            if not interface_names:
                continue

            for ip_item in ip_addresses:
                if not isinstance(ip_item, dict):
                    continue
                interface_name = str(ip_item.get("interface", "")).strip()
                address = str(ip_item.get("address", "")).strip()
                if interface_name not in interface_names or "/" not in address:
                    continue
                try:
                    network = str(ipaddress.ip_interface(address).network)
                except ValueError:
                    continue

                networks_by_vlan.setdefault(vlan_id, []).append(
                    {
                        "address": address,
                        "network": network,
                        "interface": interface_name,
                        "source_identity": gateway_result.identity or gateway_result.ip,
                        "bridge": str(row.get("bridge", "")).strip(),
                        "tagged_ports": ",".join(row.get("tagged_ports", []) or []),
                        "untagged_ports": ",".join(row.get("untagged_ports", []) or []),
                        "pvid_ports": ",".join(row.get("pvid_ports", []) or []),
                    }
                )

        return networks_by_vlan

    @staticmethod
    def _target_vlan_rows_by_id(
        result: AuditResult,
    ) -> dict[str, dict[str, Any]]:
        rows_by_vlan: dict[str, dict[str, Any]] = {}
        for row in getattr(result, "vlan_table", []) or []:
            if not isinstance(row, dict):
                continue
            vlan_id = str(row.get("vlan_id", "")).strip()
            if vlan_id and vlan_id not in rows_by_vlan:
                rows_by_vlan[vlan_id] = row
        return rows_by_vlan

    @staticmethod
    def _target_untagged_interface_for_vlan(
        result: AuditResult,
        vlan_id: str,
    ) -> str:
        row = RouterOSScriptGenerator._target_vlan_rows_by_id(result).get(str(vlan_id).strip())
        if row is None:
            return ""
        for iface in row.get("untagged_ports", []) or []:
            name = str(iface).strip()
            if name:
                return name
        return ""

    def _has_target_instance(self, result: AuditResult, instance_name: str) -> bool:
        instances = getattr(result, "ospf_instance_details", None) or getattr(result, "ospf_instances", None)
        if not instances:
            return False
        for item in instances:
            if isinstance(item, str) and item.strip() == instance_name:
                return True
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                disabled = str(item.get("disabled", "false")).strip().lower()
                if name == instance_name and disabled not in {"true", "yes", "1"}:
                    return True
        return False

    def _has_correct_default_route(self, result: AuditResult, expected_gateway: str) -> bool:
        routes = getattr(result, "routes", None)
        if not routes:
            return False
        for route in routes:
            if not isinstance(route, dict):
                continue
            dst = str(route.get("dst") or route.get("dst-address") or route.get("dst_address") or "").strip()
            gateway = str(route.get("gateway", "")).strip()
            active = str(route.get("active", "true")).strip().lower()
            if dst == "0.0.0.0/0" and gateway == expected_gateway and active in {"true", "yes", "1", ""}:
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

    def _poll_gateway_result(self, gateway_ip: str) -> AuditResult | None:
        gateway_ip = gateway_ip.strip()
        if not gateway_ip:
            return None
        if gateway_ip in self._gateway_results_by_ip:
            return self._gateway_results_by_ip[gateway_ip]
        if (
            self.ssh is None
            or self.collector is None
            or self.gateway_credentials is None
            or not self.gateway_credentials.username
            or not self.gateway_credentials.password
        ):
            self._gateway_results_by_ip[gateway_ip] = None
            return None

        session = self.ssh.open_session(gateway_ip, self.gateway_credentials)
        if session is None:
            if self.logger:
                self.logger.debug("Gateway polling failed to open session ip=%s", gateway_ip)
            self._gateway_results_by_ip[gateway_ip] = None
            return None

        with session:
            info = self.collector.collect_router_data(session)
            if info is None:
                if self.logger:
                    self.logger.debug("Gateway polling failed to collect data ip=%s", gateway_ip)
                self._gateway_results_by_ip[gateway_ip] = None
                return None

        gateway_result = AuditResult(ip=gateway_ip, subnet="")
        gateway_result.apply_device_info(info)
        gateway_result.status = "GATEWAY_POLLED"
        self._gateway_results_by_ip[gateway_ip] = gateway_result
        return gateway_result

    def _resolve_gateway_result(
        self,
        *,
        gateway_ip: str,
        scanned_results: Iterable[AuditResult],
    ) -> AuditResult | None:
        gateway_ip = gateway_ip.strip()
        if not gateway_ip:
            return None
        for item in scanned_results:
            if (getattr(item, "ip", "") or "").strip() == gateway_ip:
                return item
        return self._poll_gateway_result(gateway_ip)

    def _build_scheduler_script(self, result: AuditResult) -> str:
        scheduler_cfg = getattr(self.config, "scheduler", None)
        if not scheduler_cfg or not scheduler_cfg.enabled or not scheduler_cfg.expected:
            return ""

        lines = ["# Reconcile scheduler entries from inventory config"]
        for rule in scheduler_cfg.expected:
            start_time = rule.resolve_device_start_time(
                ip=result.ip,
                identity=result.identity,
            )
            lines.extend(
                [
                    f"# Scheduler rule: {rule.name} start_time={start_time} interval={rule.interval}",
                    (
                        f':if ([:len [/system scheduler find where name="{rule.name}"]] > 0) do={{ '
                        f'/system scheduler remove [find where name="{rule.name}"] '
                        "}"
                    ),
                    MikroTikCommands.scheduler_add(
                        name=rule.name,
                        start_time=start_time,
                        start_date=rule.start_date,
                        interval=rule.interval,
                        on_event=rule.on_event,
                        policy=rule.policy,
                        disabled=rule.disabled,
                    ),
                ]
            )
        return "\n".join(lines)

    def _build_ntp_script(self) -> str:
        ntp_cfg = getattr(self.config, "ntp", None)
        if not ntp_cfg:
            return ""

        enabled = str(getattr(ntp_cfg, "enabled", "") or "").strip()
        servers = [
            str(item).strip()
            for item in getattr(ntp_cfg, "servers", []) or []
            if str(item).strip()
        ]
        if not enabled and not servers:
            return ""

        lines = ["# Reconcile NTP client settings from inventory config"]
        if enabled:
            lines.append(MikroTikCommands.ntp_client_set_enabled(enabled))
        lines.append(MikroTikCommands.ntp_client_servers_reset())
        for server in servers:
            lines.append(MikroTikCommands.ntp_client_server_add(server))
        return "\n".join(lines)

    def _build_clock_script(self) -> str:
        clock_cfg = self.inventory.get("clocks", {})
        if not isinstance(clock_cfg, dict):
            return ""

        enabled = str(clock_cfg.get("enabled", "") or "").strip().lower()
        timezone = str(clock_cfg.get("timezone", "") or "").strip()
        summer_time_mode = str(clock_cfg.get("summer_time_mode", "") or "").strip()
        if enabled not in {"yes", "true", "1"}:
            return ""
        if not timezone and not summer_time_mode:
            return ""

        settings: list[str] = []
        if timezone:
            settings.append(f"time-zone-name={MikroTikCommands._quote(timezone)}")
        if summer_time_mode:
            settings.append(f"summer-time={MikroTikCommands._quote(summer_time_mode)}")
        if not settings:
            return ""

        return "\n".join(
            [
                "# Reconcile system clock settings from inventory config",
                "/system clock set " + " ".join(settings),
            ]
        )
