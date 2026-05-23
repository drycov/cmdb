"""Implementation details for services setup_mode."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from mikrotik_audit.config import AppConfig, load_yaml_file

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


class SetupModeService:
    """Provide the setupmodeservice service."""
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.inventory_path = Path(config.inventory_path)

    def build_defaults(self) -> dict[str, Any]:
        return {
            "workers": self.config.runtime.workers,
            "max_targets": self.config.runtime.max_targets,
            "preload_phpipam_cache": self.config.audit.preload_phpipam_cache,
            "compliance_phpipam": self.config.compliance.phpipam,
            "compliance_scheduler": self.config.compliance.scheduler,
            "compliance_ntp": self.config.compliance.ntp,
            "compliance_watchdog": self.config.compliance.watchdog,
            "remediation_enabled": self.config.remediation.enabled,
            "remediation_allow_apply": self.config.remediation.allow_apply,
            "remediation_allow_generate_script": self.config.remediation.allow_generate_script,
            "report_write_excel": self.config.report.write_excel,
            "report_write_ndjson": self.config.report.write_ndjson,
            "report_write_google_sheets": self.config.report.write_google_sheets,
        }

    def save(self, updates: dict[str, Any]) -> str:
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required for setup mode. Install the dependencies from reqqurements.txt."
            )

        inventory = load_yaml_file(self.inventory_path)
        original = deepcopy(inventory)

        settings = inventory.setdefault("settings", {})
        runtime = settings.setdefault("runtime", {})
        audit = settings.setdefault("audit", {})
        compliance = settings.setdefault("compliance", {})
        remediation = settings.setdefault("remediation", {})
        report = settings.setdefault("report", {})

        runtime["workers"] = max(1, int(updates.get("workers", runtime.get("workers", 100))))
        runtime["max_targets"] = max(0, int(updates.get("max_targets", runtime.get("max_targets", 0))))

        audit["preload_phpipam_cache"] = bool(
            updates.get("preload_phpipam_cache", audit.get("preload_phpipam_cache", True))
        )

        compliance["phpipam"] = bool(updates.get("compliance_phpipam", compliance.get("phpipam", True)))
        compliance["scheduler"] = bool(updates.get("compliance_scheduler", compliance.get("scheduler", True)))
        compliance["ntp"] = bool(updates.get("compliance_ntp", compliance.get("ntp", True)))
        compliance["watchdog"] = bool(updates.get("compliance_watchdog", compliance.get("watchdog", True)))

        remediation["enabled"] = bool(updates.get("remediation_enabled", remediation.get("enabled", True)))
        remediation["allow_apply"] = bool(
            updates.get("remediation_allow_apply", remediation.get("allow_apply", False))
        )
        remediation["allow_generate_script"] = bool(
            updates.get(
                "remediation_allow_generate_script",
                remediation.get("allow_generate_script", True),
            )
        )

        report["write_excel"] = bool(updates.get("report_write_excel", report.get("write_excel", True)))
        report["write_ndjson"] = bool(updates.get("report_write_ndjson", report.get("write_ndjson", True)))
        report["write_google_sheets"] = bool(
            updates.get("report_write_google_sheets", report.get("write_google_sheets", True))
        )

        try:
            with self.inventory_path.open("w", encoding="utf-8") as fh:
                yaml.safe_dump(inventory, fh, sort_keys=False, allow_unicode=False)

            validated = AppConfig.from_env()
            validated.validate()
        except Exception:
            with self.inventory_path.open("w", encoding="utf-8") as fh:
                yaml.safe_dump(original, fh, sort_keys=False, allow_unicode=False)
            raise

        return str(self.inventory_path.resolve())
