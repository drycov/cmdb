"""Implementation details for models audit_result."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, List

from mikrotik_audit.constants.auth_methods import AuthMethod
from mikrotik_audit.models.device_info import DeviceInfo
from mikrotik_audit.models.firmware_result import FirmwareResult
from mikrotik_audit.models.radius_result import RadiusResult


@dataclass(slots=True)
class AuditResult:
    """Represent the auditresult payload."""
    EXPORT_HEADERS: ClassVar[List[str]] = [
        "ip",
        "subnet",
        "identity",
        "phpipam_ip",

        "phpipam_hostname",
        "version",
        "phpipam_note",

        "ping",
        "ssh_port",
        "auth_method",
        "uptime",
        "cpu_load",
        "board_name",
        "platform",
        "architecture",
        "total_memory",
        "free_memory",
        "total_hdd",
        "free_hdd",
        "license",
        "current_firmware",
        "upgrade_firmware",
        "interface_count",
        "mac_address",
        "uplink_interface",
        "uplink_mac",
        "neighbor_identity",
        "neighbor_address",
        "neighbor_interface",
        "neighbor_mac",
        "installed_packages",
        "ospf_instance_count",
        "ospf_neighbor_count",
        "ospf_instances",
        "ospf_full_neighbors",
"ospf_twoway_neighbors",
"ospf_other_neighbors",
"ospf_unstable_neighbors",
"ospf_dr",
"ospf_bdr",
        "bridge_count",
        "bridge_port_count",
        "bridge_hw_offload_ports",
"bridge_restricted_role_ports",
"bridge_access_ports",
"bridge_trunk_like_ports",
        "bridge_names",
        "bridge_protocol_modes",
"bridge_vlan_filtering",
"bridge_igmp_snooping",
        "bridge_warning",
        "scheduler_count",
        "scheduler_names",
        "scheduler_policy_status",
        "scheduler_policy_expected",
        "scheduler_policy_details",
        "dhcp_server_count",
        "dhcp_client_count",
        "ssh_port_value",
        "winbox_port_value",
        "firewall_filter_count",
        "firewall_nat_count",
        "firewall_filter_disabled_count",
"firewall_filter_drop_count",
"firewall_filter_accept_count",
        "route_count",
        "default_route_count",
        "disabled_route_count",
"dynamic_route_count",
"static_route_count",
        "vlan_count",
        "vlan_names",
        "radius_count",
        "ntp_enabled",
        "ntp_servers",
        "ntp_policy_status",
        "ntp_policy_details",
        "watchdog_enabled",
        "watchdog_automatic_supout",
        "watchdog_ping_start_after_boot",
        "watchdog_ping_timeout",
        "watchdog_timer",
        "watchdog_policy_status",
        "watchdog_policy_details",
        "radius_added",
        "radius_recreated",
        "radius_present_after",
        "aaa_enabled",
        "aaa_present_after",
        "firmware_candidate",
        "firmware_target_version",
        "firmware_upload_needed",
        "firmware_uploaded",
        "firmware_already_present",
        "firmware_reboot_sent",
        "firmware_error",
        "phpipam_exists",
        "phpipam_address_id",
        "phpipam_created",
        "phpipam_create_error",
        # --- добавить ---
        "phpipam_match_type",
        "phpipam_hostname_exists",
        "phpipam_description",
        "status",
        "inventory_status",
        "inventory_severity",
    ]

    ip: str
    subnet: str

    identity: str = ""
    ping: bool = False
    ssh_port: bool = False
    auth_method: str = ""

    version: str = ""
    uptime: str = ""
    cpu_load: str = ""
    board_name: str = ""
    platform: str = ""
    architecture: str = ""
    total_memory: str = ""
    free_memory: str = ""
    total_hdd: str = ""
    free_hdd: str = ""
    license: str = ""
    current_firmware: str = ""
    upgrade_firmware: str = ""
    interface_count: str = ""
    mac_address: str = ""
    uplink_interface: str = ""
    uplink_mac: str = ""
    neighbor_identity: str = ""
    neighbor_address: str = ""
    neighbor_interface: str = ""
    neighbor_mac: str = ""
    installed_packages: str = ""
    ospf_instance_count: str = ""
    ospf_neighbor_count: str = ""
    ospf_instances: str = ""
    bridge_count: str = ""
    bridge_port_count: str = ""
    bridge_names: str = ""
    scheduler_count: str = ""
    scheduler_names: str = ""
    scheduler_policy_status: str = ""
    scheduler_policy_expected: str = ""
    scheduler_policy_details: str = ""
    scheduler_policy_ok_count: str = ""
    scheduler_policy_issue_count: str = ""
    dhcp_server_count: str = ""
    dhcp_client_count: str = ""
    ssh_port_value: str = ""
    winbox_port_value: str = ""
    firewall_filter_count: str = ""
    firewall_nat_count: str = ""
    route_count: str = ""
    default_route_count: str = ""
    vlan_count: str = ""
    vlan_names: str = ""
    radius_count: str = ""
    ntp_enabled: str = ""
    ntp_servers: str = ""
    ntp_policy_status: str = ""
    ntp_policy_expected: str = ""
    ntp_policy_details: str = ""
    watchdog_enabled: str = ""
    watchdog_automatic_supout: str = ""
    watchdog_ping_start_after_boot: str = ""
    watchdog_ping_timeout: str = ""
    watchdog_timer: str = ""
    watchdog_policy_status: str = ""
    watchdog_policy_expected: str = ""
    watchdog_policy_details: str = ""

    radius_added: bool = False
    radius_recreated: bool = False
    radius_present_after: bool = False
    aaa_enabled: bool = False
    aaa_present_after: bool = False

    firmware_candidate: str = ""
    firmware_target_version: str = ""
    firmware_upload_needed: bool = False
    firmware_uploaded: bool = False
    firmware_already_present: bool = False
    firmware_reboot_sent: bool = False
    firmware_error: str = ""

    # --- phpIPAM report (READ-ONLY) ---
    phpipam_exists: bool = False
    phpipam_address_id: str = ""
    phpipam_created: bool = False
    phpipam_create_error: str = ""
    phpipam_match_type: str = ""  # ip | hostname | not_found
    phpipam_hostname_exists: bool = False
    phpipam_hostname: str = ""
    phpipam_ip: str = ""
    phpipam_description: str = ""
    phpipam_note: str = ""

    status: str = ""
    inventory_status: str = ""  # OK | HOSTNAME_MISMATCH | NOT_FOUND
    inventory_severity: str = ""  # INFO | WARNING | ERROR
        
        # --- OSPF extended ---
    ospf_full_neighbors: str = ""
    ospf_twoway_neighbors: str = ""
    ospf_other_neighbors: str = ""
    ospf_unstable_neighbors: str = ""
    ospf_dr: str = ""
    ospf_bdr: str = ""

    # --- Bridge extended ---
    bridge_protocol_modes: str = ""
    bridge_vlan_filtering: str = ""
    bridge_igmp_snooping: str = ""
    bridge_warning: str = ""
    
    vlan_table: list[dict[str, Any]] = field(default_factory=list)
    routes: list[dict[str, Any]] = field(default_factory=list)
    ip_addresses: list[dict[str, Any]] = field(default_factory=list)
    ospf_instance_details: list[dict[str, Any]] = field(default_factory=list)
    ospf_neighbor_details: list[dict[str, Any]] = field(default_factory=list)

    # --- Bridge ports ---
    bridge_hw_offload_ports: str = ""
    bridge_restricted_role_ports: str = ""
    bridge_access_ports: str = ""
    bridge_trunk_like_ports: str = ""

    # --- Routes extended ---
    disabled_route_count: str = ""
    dynamic_route_count: str = ""
    static_route_count: str = ""

    # --- Firewall extended ---
    firewall_filter_disabled_count: str = ""
    firewall_filter_drop_count: str = ""
    firewall_filter_accept_count: str = ""

    def apply_scheduler_policy(self, checks: list[Any]) -> None:
        if not checks:
            self.scheduler_policy_status = ""
            self.scheduler_policy_expected = ""
            self.scheduler_policy_details = ""
            self.scheduler_policy_ok_count = "0"
            self.scheduler_policy_issue_count = "0"
            return

        expected = []
        details = []
        ok_count = 0
        issue_count = 0

        for check in checks:
            name = getattr(check, "name", "")
            status = getattr(check, "status", "")
            expected_time = getattr(check, "expected_start_time", "")
            actual_time = getattr(check, "actual_start_time", "")
            message = getattr(check, "message", "")

            if name and expected_time:
                expected.append(f"{name}={expected_time}")

            if status == "OK":
                ok_count += 1
            else:
                issue_count += 1

            if status != "OK":
                summary = f"{name}:{status}"
                if actual_time:
                    summary += f":actual={actual_time}"
                if message:
                    summary += f":{message}"
                details.append(summary)

        self.scheduler_policy_status = "OK" if issue_count == 0 else "MISMATCH"
        self.scheduler_policy_expected = ", ".join(expected)
        self.scheduler_policy_details = "; ".join(details)
        self.scheduler_policy_ok_count = str(ok_count)
        self.scheduler_policy_issue_count = str(issue_count)

    def apply_ntp_policy(self, check: Any) -> None:
        self.ntp_policy_status = str(getattr(check, "status", "") or "")
        self.ntp_policy_expected = str(getattr(check, "expected", "") or "")
        self.ntp_policy_details = str(getattr(check, "message", "") or "")

    def apply_watchdog_policy(self, check: Any) -> None:
        self.watchdog_policy_status = str(getattr(check, "status", "") or "")
        self.watchdog_policy_expected = str(getattr(check, "expected", "") or "")
        self.watchdog_policy_details = str(getattr(check, "message", "") or "")
    
    def apply_device_info(self, info: DeviceInfo) -> None:
        self.identity = info.identity
        self.version = info.version
        self.uptime = info.uptime
        self.cpu_load = info.cpu_load
        self.board_name = info.board_name
        self.platform = info.platform
        self.architecture = info.architecture
        self.total_memory = info.total_memory
        self.free_memory = info.free_memory
        self.total_hdd = info.total_hdd
        self.free_hdd = info.free_hdd
        self.license = info.license
        self.current_firmware = info.current_firmware
        self.upgrade_firmware = info.upgrade_firmware
        self.interface_count = info.interface_count
        self.mac_address = info.mac_address
        self.uplink_interface = info.uplink_interface
        self.uplink_mac = info.uplink_mac
        self.neighbor_identity = info.neighbor_identity
        self.neighbor_address = info.neighbor_address
        self.neighbor_interface = info.neighbor_interface
        self.neighbor_mac = info.neighbor_mac
        self.installed_packages = info.installed_packages
        self.ospf_instance_count = info.ospf_instance_count
        self.ospf_neighbor_count = info.ospf_neighbor_count
        self.ospf_instances = info.ospf_instances
        self.bridge_count = info.bridge_count
        self.bridge_port_count = info.bridge_port_count
        self.bridge_names = info.bridge_names
        self.scheduler_count = info.scheduler_count
        self.scheduler_names = info.scheduler_names
        self.dhcp_server_count = info.dhcp_server_count
        self.dhcp_client_count = info.dhcp_client_count
        self.ssh_port_value = info.ssh_port_value
        self.winbox_port_value = info.winbox_port_value
        self.firewall_filter_count = info.firewall_filter_count
        self.firewall_nat_count = info.firewall_nat_count
        self.route_count = info.route_count
        self.default_route_count = info.default_route_count
        self.vlan_count = info.vlan_count
        self.vlan_names = info.vlan_names
        self.radius_count = info.radius_count
        self.ntp_enabled = info.ntp_enabled
        self.ntp_servers = info.ntp_servers
        self.watchdog_enabled = info.watchdog_enabled
        self.watchdog_automatic_supout = info.watchdog_automatic_supout
        self.watchdog_ping_start_after_boot = info.watchdog_ping_start_after_boot
        self.watchdog_ping_timeout = info.watchdog_ping_timeout
        self.watchdog_timer = info.watchdog_timer
        # OSPF extended
        self.ospf_full_neighbors = info.ospf_full_neighbors
        self.ospf_twoway_neighbors = info.ospf_twoway_neighbors
        self.ospf_other_neighbors = info.ospf_other_neighbors
        self.ospf_unstable_neighbors = info.ospf_unstable_neighbors
        self.ospf_dr = info.ospf_dr
        self.ospf_bdr = info.ospf_bdr

        # Bridge extended
        self.bridge_protocol_modes = info.bridge_protocol_modes
        self.bridge_vlan_filtering = info.bridge_vlan_filtering
        self.bridge_igmp_snooping = info.bridge_igmp_snooping
        self.bridge_warning = info.bridge_warning

        # Bridge ports
        self.bridge_hw_offload_ports = info.bridge_hw_offload_ports
        self.bridge_restricted_role_ports = info.bridge_restricted_role_ports
        self.bridge_access_ports = info.bridge_access_ports
        self.bridge_trunk_like_ports = info.bridge_trunk_like_ports

        # Routes extended
        self.disabled_route_count = info.disabled_route_count
        self.dynamic_route_count = info.dynamic_route_count
        self.static_route_count = info.static_route_count

        # Firewall extended
        self.firewall_filter_disabled_count = info.firewall_filter_disabled_count
        self.firewall_filter_drop_count = info.firewall_filter_drop_count
        self.firewall_filter_accept_count = info.firewall_filter_accept_count
        self.vlan_table = getattr(info, "vlan_table", [])
        self.routes = getattr(info, "routes", [])
        self.ip_addresses = getattr(info, "ip_addresses", [])
        self.ospf_instance_details = getattr(info, "ospf_instance_details", [])
        self.ospf_neighbor_details = getattr(info, "ospf_neighbor_details", [])

    def apply_firmware(self, fw: FirmwareResult) -> None:
        self.firmware_candidate = fw.firmware_candidate
        self.firmware_target_version = fw.firmware_target_version
        self.firmware_upload_needed = fw.firmware_upload_needed
        self.firmware_uploaded = fw.firmware_uploaded
        self.firmware_already_present = fw.firmware_already_present
        self.firmware_reboot_sent = fw.firmware_reboot_sent
        self.firmware_error = str(fw.firmware_error) if fw.firmware_error else ""

    def apply_radius(self, radius: RadiusResult) -> None:
        self.radius_added = radius.radius_added
        self.radius_recreated = radius.radius_recreated
        self.radius_present_after = radius.radius_present_after
        self.aaa_enabled = radius.aaa_enabled
        self.aaa_present_after = radius.aaa_present_after

    def set_auth_method(self, auth_method: AuthMethod) -> None:
        self.auth_method = auth_method.value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identity=self.identity,
            version=self.version,
            uptime=self.uptime,
            cpu_load=self.cpu_load,
            board_name=self.board_name,
            platform=self.platform,
            architecture=self.architecture,
            total_memory=self.total_memory,
            free_memory=self.free_memory,
            total_hdd=self.total_hdd,
            free_hdd=self.free_hdd,
            license=self.license,
            current_firmware=self.current_firmware,
            upgrade_firmware=self.upgrade_firmware,
            interface_count=self.interface_count,
            mac_address=self.mac_address,
            uplink_interface=self.uplink_interface,
            uplink_mac=self.uplink_mac,
            neighbor_identity=self.neighbor_identity,
            neighbor_address=self.neighbor_address,
            neighbor_interface=self.neighbor_interface,
            neighbor_mac=self.neighbor_mac,
            installed_packages=self.installed_packages,
            ospf_instance_count=self.ospf_instance_count,
            ospf_neighbor_count=self.ospf_neighbor_count,
            ospf_instances=self.ospf_instances,
            ospf_full_neighbors=self.ospf_full_neighbors,
            ospf_twoway_neighbors=self.ospf_twoway_neighbors,
            ospf_other_neighbors=self.ospf_other_neighbors,
            ospf_unstable_neighbors=self.ospf_unstable_neighbors,
            ospf_dr=self.ospf_dr,
            ospf_bdr=self.ospf_bdr,
            bridge_count=self.bridge_count,
            bridge_port_count=self.bridge_port_count,
            bridge_names=self.bridge_names,
            bridge_protocol_modes=self.bridge_protocol_modes,
            bridge_vlan_filtering=self.bridge_vlan_filtering,
            bridge_igmp_snooping=self.bridge_igmp_snooping,
            bridge_warning=self.bridge_warning,
            bridge_hw_offload_ports=self.bridge_hw_offload_ports,
            bridge_restricted_role_ports=self.bridge_restricted_role_ports,
            bridge_access_ports=self.bridge_access_ports,
            bridge_trunk_like_ports=self.bridge_trunk_like_ports,
            scheduler_count=self.scheduler_count,
            scheduler_names=self.scheduler_names,
            dhcp_server_count=self.dhcp_server_count,
            dhcp_client_count=self.dhcp_client_count,
            ssh_port_value=self.ssh_port_value,
            winbox_port_value=self.winbox_port_value,
            firewall_filter_count=self.firewall_filter_count,
            firewall_nat_count=self.firewall_nat_count,
            firewall_filter_disabled_count=self.firewall_filter_disabled_count,
            firewall_filter_drop_count=self.firewall_filter_drop_count,
            firewall_filter_accept_count=self.firewall_filter_accept_count,
            route_count=self.route_count,
            default_route_count=self.default_route_count,
            disabled_route_count=self.disabled_route_count,
            dynamic_route_count=self.dynamic_route_count,
            static_route_count=self.static_route_count,
            routes=self.routes,
            ip_addresses=self.ip_addresses,
            ospf_instance_details=self.ospf_instance_details,
            ospf_neighbor_details=self.ospf_neighbor_details,
            vlan_count=self.vlan_count,
            vlan_names=self.vlan_names,
            vlan_table=self.vlan_table,
            radius_count=self.radius_count,
            ntp_enabled=self.ntp_enabled,
            ntp_servers=self.ntp_servers,
            watchdog_enabled=self.watchdog_enabled,
            watchdog_automatic_supout=self.watchdog_automatic_supout,
            watchdog_ping_start_after_boot=self.watchdog_ping_start_after_boot,
            watchdog_ping_timeout=self.watchdog_ping_timeout,
            watchdog_timer=self.watchdog_timer,
        )

    def to_export_row(self) -> list[Any]:
        row_dict = self.to_dict()
        return [row_dict.get(header, "") for header in self.EXPORT_HEADERS]
    
    def to_row(self) -> dict[str, Any]:
        return {
            k: getattr(self, k, "")
            for k in self.EXPORT_HEADERS
        }
