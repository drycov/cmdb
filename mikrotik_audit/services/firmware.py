from __future__ import annotations

import logging
from pathlib import Path

from commands.mikrotik import MikroTikCommands
from config import AppConfig
from constants.error_codes import FirmwareErrorCode
from models import FirmwareResult
from services.ssh import SSHSession
from utils import (
    _version_tokens,
    compare_versions,
    extract_version_from_filename,
    normalize_version,
)


class FirmwareManager:
    def __init__(self, config: AppConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger

    def find_firmware_file(self, architecture: str) -> Path | None:
        fw_dir = Path(self.config.firmware_dir)
        if not fw_dir.exists() or not fw_dir.is_dir():
            return None

        candidates: list[tuple[Path, str]] = []
        patterns = [
            f"routeros-{architecture}-*.npk",
            f"*{architecture}*.npk",
        ]

        for pattern in patterns:
            for path in fw_dir.glob(pattern):
                target_version = extract_version_from_filename(path.name, architecture)
                if target_version:
                    candidates.append((path, target_version))

        if not candidates:
            return None

        candidates.sort(key=lambda item: _version_tokens(item[1]))
        return candidates[-1][0]

    def _should_skip_upload(
        self,
        architecture: str,
        current_version: str,
        target_version: str,
    ) -> str | None:
        normalized_current = normalize_version(current_version)
        normalized_target = normalize_version(target_version)

        if (
            self.config.only_if_version_diff
            and normalized_current
            and normalized_target
            and normalized_current == normalized_target
        ):
            return FirmwareErrorCode.SAME_VERSION.value

        if normalized_current and normalized_target:
            if compare_versions(normalized_current, normalized_target) >= 0:
                return FirmwareErrorCode.SKIP_TARGET_NOT_NEWER.value

        return None

    def ensure_uploaded(
        self,
        session: SSHSession,
        architecture: str,
        current_version: str,
    ) -> FirmwareResult:
        result = FirmwareResult()

        fw = self.find_firmware_file(architecture)
        if not fw:
            result.firmware_error = FirmwareErrorCode.LOCAL_FIRMWARE_NOT_FOUND.value
            return result

        result.firmware_candidate = fw.name
        result.firmware_target_version = extract_version_from_filename(fw.name, architecture)
        skip_reason = self._should_skip_upload(
            architecture=architecture,
            current_version=current_version,
            target_version=result.firmware_target_version,
        )
        if skip_reason is not None:
            result.firmware_error = skip_reason
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

    def inspect_status(
        self,
        architecture: str,
        current_version: str,
    ) -> FirmwareResult:
        result = FirmwareResult()

        fw = self.find_firmware_file(architecture)
        if not fw:
            result.firmware_error = FirmwareErrorCode.LOCAL_FIRMWARE_NOT_FOUND.value
            return result

        result.firmware_candidate = fw.name
        result.firmware_target_version = extract_version_from_filename(fw.name, architecture)

        skip_reason = self._should_skip_upload(
            architecture=architecture,
            current_version=current_version,
            target_version=result.firmware_target_version,
        )
        if skip_reason is not None:
            result.firmware_error = skip_reason
            return result

        result.firmware_upload_needed = True
        return result
