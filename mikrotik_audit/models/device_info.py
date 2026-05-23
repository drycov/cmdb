"""Implementation details for models device_info."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class DeviceInfo:
    # System
    """Represent deviceinfo."""
    identity: str = ""
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

    # Interfaces
    interface_count: str = ""
    mac_address: str = ""
    uplink_interface: str = ""
    uplink_mac: str = ""

    # MikroTik neighbor
    neighbor_identity: str = ""
    neighbor_address: str = ""
    neighbor_interface: str = ""
    neighbor_mac: str = ""

    # Packages
    installed_packages: str = ""

    # OSPF
    ospf_instance_count: str = ""
    ospf_neighbor_count: str = ""
    ospf_instances: str = ""
    ospf_full_neighbors: str = ""
    ospf_twoway_neighbors: str = ""
    ospf_other_neighbors: str = ""
    ospf_unstable_neighbors: str = ""
    ospf_dr: str = ""
    ospf_bdr: str = ""

    # Bridge
    bridge_count: str = ""
    bridge_port_count: str = ""
    bridge_names: str = ""
    bridge_protocol_modes: str = ""
    bridge_vlan_filtering: str = ""
    bridge_igmp_snooping: str = ""
    bridge_warning: str = ""

    # Bridge ports
    bridge_hw_offload_ports: str = ""
    bridge_restricted_role_ports: str = ""
    bridge_access_ports: str = ""
    bridge_trunk_like_ports: str = ""

    # Scheduler
    scheduler_count: str = ""
    scheduler_names: str = ""

    # DHCP
    dhcp_server_count: str = ""
    dhcp_client_count: str = ""

    # Services
    ssh_port_value: str = ""
    winbox_port_value: str = ""

    # Firewall
    firewall_filter_count: str = ""
    firewall_nat_count: str = ""
    firewall_filter_disabled_count: str = ""
    firewall_filter_drop_count: str = ""
    firewall_filter_accept_count: str = ""

    # Routes
    route_count: str = ""
    default_route_count: str = ""
    disabled_route_count: str = ""
    dynamic_route_count: str = ""
    static_route_count: str = ""
    routes: list[dict[str, Any]] = field(default_factory=list)
    ip_addresses: list[dict[str, Any]] = field(default_factory=list)
    ospf_instance_details: list[dict[str, Any]] = field(default_factory=list)
    ospf_neighbor_details: list[dict[str, Any]] = field(default_factory=list)

    # VLAN
    vlan_count: str = ""
    vlan_names: str = ""

    # Parsed from:
    # /interface vlan print detail
    # /interface bridge vlan print detail
    # /interface bridge port print detail
    vlan_table: list[dict[str, Any]] = field(default_factory=list)

    # AAA / Radius
    radius_count: str = ""

    # NTP
    ntp_enabled: str = ""
    ntp_servers: str = ""

    # Watchdog
    watchdog_enabled: str = ""
    watchdog_automatic_supout: str = ""
    watchdog_ping_start_after_boot: str = ""
    watchdog_ping_timeout: str = ""
    watchdog_timer: str = ""
