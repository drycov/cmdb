from __future__ import annotations
from enum import StrEnum


class FirmwareErrorCode(StrEnum):
    SKIP_NON_MMIPS = "skip_non_mmips"
    LOCAL_FIRMWARE_NOT_FOUND = "local_firmware_not_found"
    SAME_VERSION = "same_version"
    UPLOAD_FAILED = "upload_failed"
    REBOOT_COMMAND_FAILED = "reboot_command_failed"