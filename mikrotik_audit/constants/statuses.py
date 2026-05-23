"""Implementation details for constants statuses."""

from __future__ import annotations
from enum import StrEnum


class AuditStatus(StrEnum):
    """Represent auditstatus."""
    SSH_OK = "ssh_ok"
    FALLBACK_OK = "fallback_ok"
    OFFLINE = "offline"
    SSH_CLOSED = "ssh_closed"
    AUTH_FAILED = "auth_failed"

    RADIUS_ADDED = "radius_added"
    RADIUS_RECREATED = "radius_recreated"
    AAA_ENABLED = "aaa_enabled"
    RADIUS_VERIFY_FAILED = "radius_verify_failed"
    AAA_VERIFY_FAILED = "aaa_verify_failed"

    FW_UPLOADED = "fw_uploaded"
    FW_ALREADY_PRESENT = "fw_already_present"
    FW_REBOOT_SENT = "fw_reboot_sent"