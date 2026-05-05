from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from constants.statuses import AuditStatus
from models import AuditResult


@dataclass(slots=True)
class SummaryAccumulator:
    total: int = 0
    flags: Counter[str] = field(default_factory=Counter)
    statuses: Counter[str] = field(default_factory=Counter)
    inventory_statuses: Counter[str] = field(default_factory=Counter)
    inventory_severities: Counter[str] = field(default_factory=Counter)
    matches: Counter[str] = field(default_factory=Counter)
    firmware_errors: Counter[str] = field(default_factory=Counter)

    def add(self, result: AuditResult) -> None:
        self.total += 1

        if result.ping:
            self.flags["alive"] += 1

        if result.status.startswith(AuditStatus.SSH_OK.value):
            self.statuses["ssh_ok"] += 1
        elif result.status.startswith(AuditStatus.FALLBACK_OK.value):
            self.statuses["fallback_ok"] += 1
        elif result.status:
            self.statuses[result.status.lower()] += 1

        if result.inventory_status:
            self.inventory_statuses[result.inventory_status] += 1

        if result.inventory_severity:
            self.inventory_severities[result.inventory_severity] += 1

        if result.phpipam_match_type:
            self.matches[result.phpipam_match_type] += 1

        if result.firmware_error:
            self.firmware_errors[result.firmware_error] += 1

    def rows(self) -> list[dict[str, object]]:
        alive = self.flags["alive"]
        ok = self.inventory_statuses["OK"]

        return [
            {"metric": "total_hosts", "value": self.total},
            {"metric": "alive", "value": alive},
            {"metric": "alive_percent", "value": round(alive / self.total * 100, 2) if self.total else 0},
            {"metric": "ssh_ok", "value": self.statuses["ssh_ok"]},
            {"metric": "fallback_ok", "value": self.statuses["fallback_ok"]},
            {"metric": "inventory_ok", "value": ok},
            {"metric": "inventory_compliance_percent", "value": round(ok / self.total * 100, 2) if self.total else 0},
            {"metric": "severity_info", "value": self.inventory_severities["INFO"]},
            {"metric": "severity_warning", "value": self.inventory_severities["WARNING"]},
            {"metric": "severity_error", "value": self.inventory_severities["ERROR"]},
            {"metric": "match_ip", "value": self.matches["ip"]},
            {"metric": "match_hostname", "value": self.matches["hostname"]},
            {"metric": "match_not_found", "value": self.matches["not_found"]},
        ]