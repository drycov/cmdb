from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass(slots=True)
class DeviceInfo:
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
    interface_count: str = ""
    mac_address: str = ""
    uplink_interface: str = ""
    uplink_mac: str = ""
    neighbor_identity: str = ""
    neighbor_address: str = ""
    neighbor_interface: str = ""
    neighbor_mac: str = ""