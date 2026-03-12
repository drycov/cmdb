from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, ClassVar, Dict, List

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
        "ping",
        "ssh_port",
        "auth_method",
        "version",
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
        "status",
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

    phpipam_exists: bool = False
    phpipam_address_id: str = ""
    phpipam_created: bool = False
    phpipam_create_error: str = ""

    status: str = ""

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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
