from __future__ import annotations

from typing import List

from constants.statuses import AuditStatus
from models import AuditResult


class StatusBuilder:
    @staticmethod
    def build_primary(result: AuditResult) -> str:
        parts: List[str] = [AuditStatus.SSH_OK.value]

        if result.firmware_uploaded:
            parts.append(AuditStatus.FW_UPLOADED.value)
        if result.firmware_already_present:
            parts.append(AuditStatus.FW_ALREADY_PRESENT.value)
        if result.firmware_reboot_sent:
            parts.append(AuditStatus.FW_REBOOT_SENT.value)
        if result.firmware_error and not result.firmware_error.startswith("skip_"):
            parts.append(result.firmware_error)

        return "_".join(parts)

    @staticmethod
    def build_fallback(result: AuditResult) -> str:
        parts: List[str] = [AuditStatus.FALLBACK_OK.value]

        if result.radius_added:
            parts.append(AuditStatus.RADIUS_ADDED.value)
        if result.radius_recreated:
            parts.append(AuditStatus.RADIUS_RECREATED.value)
        if result.aaa_enabled:
            parts.append(AuditStatus.AAA_ENABLED.value)
        if not result.radius_present_after:
            parts.append(AuditStatus.RADIUS_VERIFY_FAILED.value)
        if not result.aaa_present_after:
            parts.append(AuditStatus.AAA_VERIFY_FAILED.value)
        if result.firmware_uploaded:
            parts.append(AuditStatus.FW_UPLOADED.value)
        if result.firmware_already_present:
            parts.append(AuditStatus.FW_ALREADY_PRESENT.value)
        if result.firmware_reboot_sent:
            parts.append(AuditStatus.FW_REBOOT_SENT.value)
        if result.firmware_error and not result.firmware_error.startswith("skip_"):
            parts.append(result.firmware_error)

        return "_".join(parts)
