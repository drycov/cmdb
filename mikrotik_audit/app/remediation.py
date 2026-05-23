"""Implementation details for app remediation."""

from __future__ import annotations

from typing import List


def generate_safe_fixes(timezone: str = "Asia/Almaty", disable_scheduler_name: str = "reboot-night") -> List[str]:
    """Handle generate safe fixes."""
    lines: List[str] = []
    lines.append(f"/system clock set time-zone-name={timezone}")
    # disable scheduler if exists
    lines.append(f"/system scheduler disable [find name=\"{disable_scheduler_name}\"] || :put \"no-scheduler\"")
    # ingress filtering placeholder
    lines.append("/interface bridge set [find] ingress-filtering=yes || :put \"no-bridge\"")
    return lines
