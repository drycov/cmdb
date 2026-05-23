"""Implementation details for services compliance."""

from __future__ import annotations

from dataclasses import dataclass

from mikrotik_audit.config import NTPConfig, WatchdogConfig
from mikrotik_audit.models import DeviceInfo


@dataclass(slots=True, frozen=True)
class PolicyCheck:
    """Represent policycheck."""
    name: str
    status: str
    expected: str
    actual: str
    message: str = ""


class DevicePolicyInspector:
    """Represent devicepolicyinspector."""
    def inspect_ntp(
        self,
        *,
        info: DeviceInfo,
        config: NTPConfig,
    ) -> PolicyCheck:
        expected_enabled = (config.enabled or "").strip()
        expected_servers = self._normalize_csv(config.servers)
        actual_enabled = (info.ntp_enabled or "").strip()
        actual_servers = self._normalize_csv(
            [item for item in (info.ntp_servers or "").split(",") if item.strip()]
        )

        mismatches: list[str] = []
        if expected_enabled and actual_enabled != expected_enabled:
            mismatches.append(f"enabled={actual_enabled or '<empty>'} != {expected_enabled}")
        if expected_servers != actual_servers:
            mismatches.append(
                f"servers={', '.join(actual_servers) or '<empty>'} != {', '.join(expected_servers) or '<empty>'}"
            )

        return PolicyCheck(
            name="ntp",
            status="OK" if not mismatches else "MISMATCH",
            expected=self._format_ntp_expected(expected_enabled, expected_servers),
            actual=self._format_ntp_expected(actual_enabled, actual_servers),
            message=", ".join(mismatches),
        )

    def inspect_watchdog(
        self,
        *,
        info: DeviceInfo,
        config: WatchdogConfig,
    ) -> PolicyCheck:
        expected = {
            "automatic_supout": (config.automatic_supout or "").strip(),
            "ping_start_after_boot": (config.ping_start_after_boot or "").strip(),
            "ping_timeout": (config.ping_timeout or "").strip(),
            "watchdog_timer": (config.watchdog_timer or "").strip(),
        }
        actual = {
            "automatic_supout": (info.watchdog_automatic_supout or "").strip(),
            "ping_start_after_boot": (info.watchdog_ping_start_after_boot or "").strip(),
            "ping_timeout": (info.watchdog_ping_timeout or "").strip(),
            "watchdog_timer": (info.watchdog_timer or "").strip(),
        }

        mismatches = [
            f"{key}={actual[key] or '<empty>'} != {value}"
            for key, value in expected.items()
            if value and actual[key] != value
        ]

        return PolicyCheck(
            name="watchdog",
            status="OK" if not mismatches else "MISMATCH",
            expected=self._format_mapping(expected),
            actual=self._format_mapping(actual),
            message=", ".join(mismatches),
        )

    @staticmethod
    def _normalize_csv(values: list[str]) -> list[str]:
        normalized = [str(value).strip() for value in values if str(value).strip()]
        return sorted(dict.fromkeys(normalized))

    @staticmethod
    def _format_ntp_expected(enabled: str, servers: list[str]) -> str:
        parts: list[str] = []
        if enabled:
            parts.append(f"enabled={enabled}")
        if servers:
            parts.append(f"servers={', '.join(servers)}")
        return "; ".join(parts)

    @staticmethod
    def _format_mapping(values: dict[str, str]) -> str:
        parts = [f"{key}={value}" for key, value in values.items() if value]
        return "; ".join(parts)
