from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, List

from constants.auth_methods import AuthMethod
from models.device_info import DeviceInfo
from models.firmware_result import FirmwareResult
from models.radius_result import RadiusResult


@dataclass(slots=True)
class AuditResult:
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
        "watchdog_enabled",
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
    watchdog_enabled: str = ""

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
        self.watchdog_enabled = info.watchdog_enabled
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

    def to_export_row(self) -> list[Any]:
        row_dict = self.to_dict()
        return [row_dict.get(header, "") for header in self.EXPORT_HEADERS]
    
    def to_row(self) -> dict[str, Any]:
        return {
            k: getattr(self, k, "")
            for k in self.EXPORT_HEADERS
        }
