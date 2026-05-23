"""Implementation details for config_parts app."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mikrotik_audit.config_parts.env import (
    env_bool,
    env_csv,
    env_int,
    env_str,
    resolve_project_path,
)
from mikrotik_audit.config_parts.inventory import (
    load_yaml_file,
    normalize_inventory_data,
    parse_hms,
)
from mikrotik_audit.config_parts.models import (
    AuditConfig,
    BackupConfig,
    ComplianceConfig,
    CredentialConfig,
    FirmwareConfig,
    GatewayAuthConfig,
    GoogleConfig,
    MikroTikAuthConfig,
    NTPConfig,
    PHPIPAMConfig,
    RadiusConfig,
    RemediationConfig,
    ReportConfig,
    RuntimeConfig,
    SchedulerConfig,
    ServiceConfig,
    WatchdogConfig,
)


@dataclass(slots=True, frozen=True)
class AppConfig:
    """Represent appconfig settings."""
    log_level: str
    log_console_level: str
    log_file_level: str
    log_dir: str
    log_file: str
    error_log_file: str
    log_max_bytes_mb: int
    log_backup_count: int
    log_inventory_details: bool
    runtime: RuntimeConfig
    mikrotik_auth: MikroTikAuthConfig
    service: ServiceConfig
    audit: AuditConfig
    compliance: ComplianceConfig
    remediation: RemediationConfig
    backup: BackupConfig
    report: ReportConfig
    inventory_file: str
    secrets_file: str
    exclude_gateways: bool
    prefer_devices_over_networks: bool
    firmware: FirmwareConfig
    gateway_auth: GatewayAuthConfig
    test_mode: bool
    test_limit: int
    test_ips_raw: str
    test_ips: list[str]
    radius: RadiusConfig
    phpipam: PHPIPAMConfig
    google: GoogleConfig
    ntp: NTPConfig
    scheduler: SchedulerConfig
    watchdog: WatchdogConfig

    @property
    def inventory_path(self) -> Path:
        return Path(self.inventory_file).expanduser()

    @property
    def secrets_path(self) -> Path:
        return Path(self.secrets_file).expanduser()

    @property
    def username(self) -> str:
        return self.mikrotik_auth.username

    @property
    def password(self) -> str:
        return self.mikrotik_auth.password

    @property
    def fallback_credentials(self) -> list[CredentialConfig]:
        return self.mikrotik_auth.fallback

    @property
    def mikrotik_credentials(self) -> list[CredentialConfig]:
        return self.mikrotik_auth.credentials

    @property
    def ssh_port(self) -> int:
        return self.runtime.ssh_port

    @property
    def timeout(self) -> int:
        return self.runtime.connect_timeout

    @property
    def banner_timeout(self) -> int:
        return self.runtime.banner_timeout

    @property
    def command_timeout(self) -> int:
        return self.runtime.command_timeout

    @property
    def auth_timeout(self) -> int:
        return self.runtime.auth_timeout

    @property
    def ping_timeout(self) -> int:
        return self.runtime.ping_timeout

    @property
    def ping_count(self) -> int:
        return self.runtime.ping_count

    @property
    def workers(self) -> int:
        return self.runtime.workers

    @property
    def max_targets(self) -> int:
        return self.runtime.max_targets

    @property
    def firmware_username(self) -> str:
        return self.firmware.credentials.username

    @property
    def firmware_password(self) -> str:
        return self.firmware.credentials.password

    @property
    def firmware_dir(self) -> str:
        return self.firmware.directory

    @property
    def gateway_username(self) -> str:
        return self.gateway_auth.credentials.username

    @property
    def gateway_password(self) -> str:
        return self.gateway_auth.credentials.password

    @property
    def auto_upload_mmips(self) -> bool:
        return self.firmware.auto_upload_mmips

    @property
    def auto_reboot_after_upload(self) -> bool:
        return self.firmware.auto_reboot_after_upload

    @property
    def only_if_version_diff(self) -> bool:
        return self.firmware.only_if_version_diff

    @property
    def radius_addr(self) -> str:
        return self.radius.address

    @property
    def radius_secret(self) -> str:
        return self.radius.secret

    @property
    def radius_service(self) -> str:
        return self.radius.service

    @property
    def output_xlsx(self) -> str:
        return self.report.output_xlsx

    @property
    def output_json(self) -> str | None:
        return self.report.output_json

    @property
    def preload_phpipam_cache(self) -> bool:
        return self.audit.preload_phpipam_cache

    @property
    def export_single_audit(self) -> bool:
        return self.audit.export_single_audit

    def remediation_domain_allowed(self, domain: str) -> bool:
        normalized = (domain or "").strip().lower()
        return normalized in {item.lower() for item in self.remediation.allowed_domains}

    @classmethod
    def from_env(cls) -> AppConfig:
        default_inventory_file = "network_inventory.yml"
        inventory_file = env_str("INVENTORY_FILE") or env_str("SUBNETS_FILE") or default_inventory_file
        secrets_file = env_str("SECRETS_FILE", "secrets.yml")

        inventory_file = str(resolve_project_path(inventory_file))
        secrets_file = str(resolve_project_path(secrets_file))

        secrets = load_yaml_file(secrets_file)
        inventory_data = normalize_inventory_data(load_yaml_file(inventory_file))

        mikrotik_auth = MikroTikAuthConfig.from_sources(secrets)
        first_fallback = mikrotik_auth.fallback[0] if mikrotik_auth.fallback else None
        runtime = RuntimeConfig.from_sources(inventory_data)
        audit = AuditConfig.from_inventory(inventory_data)
        compliance = ComplianceConfig.from_inventory(inventory_data)
        remediation = RemediationConfig.from_inventory(inventory_data)
        backup = BackupConfig.from_inventory(inventory_data)
        report = ReportConfig.from_inventory(inventory_data)
        service = ServiceConfig.from_inventory(inventory_data)

        return cls(
            log_level=env_str("LOG_LEVEL", "INFO").upper(),
            log_console_level=env_str("LOG_CONSOLE_LEVEL", env_str("LOG_LEVEL", "INFO")).upper(),
            log_file_level=env_str("LOG_FILE_LEVEL", env_str("LOG_LEVEL", "INFO")).upper(),
            log_dir=env_str("LOG_DIR", "logs"),
            log_file=env_str("LOG_FILE", "mikrotik_audit.log"),
            error_log_file=env_str("ERROR_LOG_FILE", "mikrotik_audit.error.log"),
            log_max_bytes_mb=env_int("LOG_MAX_BYTES_MB", 10),
            log_backup_count=env_int("LOG_BACKUP_COUNT", 5),
            log_inventory_details=env_bool("LOG_INVENTORY_DETAILS", False),
            runtime=runtime,
            mikrotik_auth=mikrotik_auth,
            service=service,
            audit=audit,
            compliance=compliance,
            remediation=remediation,
            backup=backup,
            report=report,
            inventory_file=inventory_file,
            secrets_file=secrets_file,
            exclude_gateways=env_bool("EXCLUDE_GATEWAYS", True),
            prefer_devices_over_networks=env_bool("PREFER_DEVICES_OVER_NETWORKS", True),
            firmware=FirmwareConfig.from_sources(
                secrets=secrets,
                fallback_credential=first_fallback,
            ),
            gateway_auth=GatewayAuthConfig.from_sources(secrets),
            test_mode=env_bool("TEST_MODE", False),
            test_limit=env_int("TEST_LIMIT", 2),
            test_ips_raw=env_str("TEST_IPS"),
            test_ips=env_csv("TEST_IPS"),
            radius=RadiusConfig.from_sources(secrets=secrets, inventory_data=inventory_data),
            phpipam=PHPIPAMConfig.from_sources(secrets),
            google=GoogleConfig.from_sources(secrets),
            ntp=NTPConfig.from_inventory(inventory_data.get("ntp")),
            scheduler=SchedulerConfig.from_inventory(inventory_data.get("scheduler")),
            watchdog=WatchdogConfig.from_inventory(inventory_data.get("watchdog")),
        )

    def validate(self) -> None:
        errors: list[str] = []

        if not self.mikrotik_auth.primary.is_valid:
            errors.append("MikroTik primary credentials are not configured")
        if self.ssh_port <= 0 or self.ssh_port > 65535:
            errors.append(f"Invalid MikroTik SSH port: {self.ssh_port}")
        if self.timeout <= 0:
            errors.append("MIKROTIK_TIMEOUT must be greater than 0")
        if self.banner_timeout <= 0:
            errors.append("MIKROTIK_BANNER_TIMEOUT must be greater than 0")
        if self.workers <= 0:
            errors.append("MIKROTIK_WORKERS must be greater than 0")

        if self.phpipam.enabled:
            if not self.phpipam.base_url:
                errors.append("PHPIPAM_BASE_URL is required when PHPIPAM_ENABLED=true")
            if not self.phpipam.app_id:
                errors.append("PHPIPAM_APP_ID is required when PHPIPAM_ENABLED=true")
            if not self.phpipam.username or not self.phpipam.password:
                errors.append("phpIPAM credentials are required when PHPIPAM_ENABLED=true")

        if self.google.enabled:
            if not self.google.credentials_file:
                errors.append("GOOGLE_CREDENTIALS_FILE or google.credentials_file is required when GOOGLE_ENABLED=true")
            if not self.google.spreadsheet:
                errors.append("GOOGLE_SPREADSHEET is required when GOOGLE_ENABLED=true")

        if self.auth_timeout <= 0:
            errors.append("MIKROTIK_AUTH_TIMEOUT must be greater than 0")
        if self.command_timeout < self.timeout:
            errors.append("MIKROTIK_COMMAND_TIMEOUT must be greater than or equal to MIKROTIK_TIMEOUT")
        if self.ping_timeout <= 0:
            errors.append("MIKROTIK_PING_TIMEOUT must be greater than 0")
        if self.ping_count <= 0:
            errors.append("MIKROTIK_PING_COUNT must be greater than 0")
        if self.max_targets < 0:
            errors.append("MAX_TARGETS cannot be negative")

        allowed_service_actions = {
            "audit",
            "export",
            "phpipam-report",
            "topology",
            "generate-script",
            "backup-configs",
        }
        if self.service.action not in allowed_service_actions:
            errors.append(
                "SERVICE_ACTION must be one of: audit, export, phpipam-report, topology, generate-script, backup-configs"
            )

        if self.service.interval_seconds <= 0:
            errors.append("SERVICE_INTERVAL_SECONDS must be greater than 0")
        if not self.report.write_excel and not self.report.write_ndjson and not (
            self.report.write_google_sheets and self.google.enabled
        ):
            errors.append("At least one report output must be enabled")
        if not self.remediation.allowed_domains:
            errors.append("settings.remediation.allowed_domains must not be empty")

        if self.remediation.git_enabled:
            if not self.remediation.git_repo_dir.strip():
                errors.append("REMEDIATION_GIT_REPO_DIR must not be empty when git mode is enabled")
            if not self.remediation.git_author_name.strip():
                errors.append("REMEDIATION_GIT_AUTHOR_NAME must not be empty when git mode is enabled")
            if not self.remediation.git_author_email.strip():
                errors.append("REMEDIATION_GIT_AUTHOR_EMAIL must not be empty when git mode is enabled")

        allowed_backup_filename_modes = {"identity-ip", "identity", "ip"}
        if self.backup.filename_mode not in allowed_backup_filename_modes:
            errors.append("BACKUP_FILENAME_MODE must be one of: identity-ip, identity, ip")
        if not self.backup.export_command.strip():
            errors.append("BACKUP_EXPORT_COMMAND must not be empty")

        if self.backup.git_enabled:
            if not self.backup.git_repo_dir.strip():
                errors.append("BACKUP_GIT_REPO_DIR must not be empty when backup git mode is enabled")
            if not self.backup.git_author_name.strip():
                errors.append("BACKUP_GIT_AUTHOR_NAME must not be empty when backup git mode is enabled")
            if not self.backup.git_author_email.strip():
                errors.append("BACKUP_GIT_AUTHOR_EMAIL must not be empty when backup git mode is enabled")

        for index, rule in enumerate(self.scheduler.expected, start=1):
            if rule.is_staggered:
                if parse_hms(rule.time_window_start) is None:
                    errors.append(f"scheduler.expected[{index}].time_window_start must be HH:MM:SS")
                if parse_hms(rule.time_window_end) is None:
                    errors.append(f"scheduler.expected[{index}].time_window_end must be HH:MM:SS")
                if rule.slot_minutes <= 0:
                    errors.append(f"scheduler.expected[{index}].slot_minutes must be greater than 0")

        if errors:
            raise RuntimeError("Invalid application config:\n- " + "\n- ".join(errors))

    def safe_dump(self) -> dict[str, Any]:
        return {
            "log_level": self.log_level,
            "inventory_file": self.inventory_file,
            "secrets_file": self.secrets_file,
            "runtime": {
                "workers": self.workers,
                "ssh_port": self.ssh_port,
                "connect_timeout": self.timeout,
                "auth_timeout": self.auth_timeout,
                "banner_timeout": self.banner_timeout,
                "command_timeout": self.command_timeout,
                "ping_timeout": self.ping_timeout,
                "ping_count": self.ping_count,
                "max_targets": self.max_targets,
            },
            "service": {
                "enabled": self.service.enabled,
                "action": self.service.action,
                "interval_seconds": self.service.interval_seconds,
                "progress": self.service.progress,
            },
            "audit": {
                "read_only": self.audit.read_only,
                "preload_phpipam_cache": self.audit.preload_phpipam_cache,
                "export_single_audit": self.audit.export_single_audit,
                "fail_fast": self.audit.fail_fast,
            },
            "compliance": {
                "radius": self.compliance.radius,
                "ntp": self.compliance.ntp,
                "scheduler": self.compliance.scheduler,
                "watchdog": self.compliance.watchdog,
                "phpipam": self.compliance.phpipam,
            },
            "remediation": {
                "enabled": self.remediation.enabled,
                "allow_apply": self.remediation.allow_apply,
                "allow_generate_script": self.remediation.allow_generate_script,
                "allowed_domains": self.remediation.allowed_domains,
                "output_dir": self.remediation.output_dir,
                "git_enabled": self.remediation.git_enabled,
                "git_repo_dir": self.remediation.git_repo_dir,
                "git_author_name": self.remediation.git_author_name,
                "git_author_email": self.remediation.git_author_email,
            },
            "backup": {
                "enabled": self.backup.enabled,
                "output_dir": self.backup.output_dir,
                "git_enabled": self.backup.git_enabled,
                "git_repo_dir": self.backup.git_repo_dir,
                "git_author_name": self.backup.git_author_name,
                "git_author_email": self.backup.git_author_email,
                "export_command": self.backup.export_command,
                "filename_mode": self.backup.filename_mode,
            },
            "report": {
                "output_xlsx": self.output_xlsx,
                "output_json": self.output_json,
                "write_excel": self.report.write_excel,
                "write_ndjson": self.report.write_ndjson,
                "write_google_sheets": self.report.write_google_sheets,
            },
            "mikrotik": {
                "primary": self.mikrotik_auth.primary.masked(),
                "fallback": [cred.masked() for cred in self.mikrotik_auth.fallback],
            },
            "firmware": {
                "directory": self.firmware.directory,
                "credentials": self.firmware.credentials.masked(),
                "auto_upload_mmips": self.firmware.auto_upload_mmips,
                "auto_reboot_after_upload": self.firmware.auto_reboot_after_upload,
                "only_if_version_diff": self.firmware.only_if_version_diff,
            },
            "phpipam": {
                "enabled": self.phpipam.enabled,
                "base_url": self.phpipam.base_url,
                "app_id": self.phpipam.app_id,
                "username": self.phpipam.username,
                "password": "***" if self.phpipam.password else "",
                "section_id": self.phpipam.section_id,
                "subnet_id": self.phpipam.subnet_id,
                "verify_ssl": self.phpipam.verify_ssl,
                "sync_enabled": self.phpipam.sync_enabled,
            },
            "google": {
                "enabled": self.google.enabled,
                "credentials_file": self.google.credentials_file,
                "spreadsheet": self.google.spreadsheet,
                "worksheet": self.google.worksheet,
                "max_batch_cells": self.google.max_batch_cells,
                "suppress_cell_limit_errors": self.google.suppress_cell_limit_errors,
            },
        }
