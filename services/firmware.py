from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from commands.mikrotik import MikroTikCommands
from config import AppConfig
from constants.error_codes import FirmwareErrorCode
from models import FirmwareResult
from services.ssh import SSHSession
from utils import extract_version_from_filename, normalize_version


class FirmwareManager:
    def __init__(self, config: AppConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger

    def find_firmware_file(self, architecture: str) -> Optional[Path]:
        fw_dir = Path(self.config.firmware_dir)
        if not fw_dir.exists() or not fw_dir.is_dir():
            return None

        patterns = [
            f"routeros-{architecture}-*.npk",
            f"*{architecture}*.npk",
        ]

        for pattern in patterns:
            candidates = sorted(fw_dir.glob(pattern))
            if candidates:
                return candidates[-1]

        return None

    def ensure_uploaded(
        self,
        session: SSHSession,
        architecture: str,
        current_version: str,
    ) -> FirmwareResult:
        result = FirmwareResult()

        if architecture != "mmips":
            result.firmware_error = FirmwareErrorCode.SKIP_NON_MMIPS.value
            return result

        fw = self.find_firmware_file(architecture)
        if not fw:
            result.firmware_error = FirmwareErrorCode.LOCAL_FIRMWARE_NOT_FOUND.value
            return result

        result.firmware_candidate = fw.name
        result.firmware_target_version = extract_version_from_filename(fw.name, architecture)

        normalized_current = normalize_version(current_version)
        normalized_target = normalize_version(result.firmware_target_version)

        if (
            self.config.only_if_version_diff
            and normalized_current
            and normalized_target
            and normalized_current == normalized_target
        ):
            result.firmware_error = FirmwareErrorCode.SAME_VERSION.value
            return result

        result.firmware_upload_needed = True

        if session.remote_file_exists(fw.name):
            result.firmware_already_present = True
        else:
            uploaded = session.upload_file_sftp(fw)
            if not uploaded:
                result.firmware_error = FirmwareErrorCode.UPLOAD_FAILED.value
                return result
            result.firmware_uploaded = True

        if self.config.auto_reboot_after_upload and result.firmware_uploaded:
            reboot_ok = session.exec_ok(MikroTikCommands.SYSTEM_REBOOT)
            result.firmware_reboot_sent = reboot_ok
            if not reboot_ok:
                result.firmware_error = FirmwareErrorCode.REBOOT_COMMAND_FAILED.value

        return result