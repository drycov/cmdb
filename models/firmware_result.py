from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict

@dataclass(slots=True)
class FirmwareResult:
    firmware_candidate: str = ""
    firmware_target_version: str = ""
    firmware_upload_needed: bool = False
    firmware_uploaded: bool = False
    firmware_already_present: bool = False
    firmware_reboot_sent: bool = False
    firmware_error: str = ""