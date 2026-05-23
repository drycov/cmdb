"""Implementation details for config_parts models."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha1
from typing import Any, Iterator

from mikrotik_audit.config_parts.env import (
    env_bool,
    env_int,
    env_optional_path,
    env_raw,
    env_str,
)
from mikrotik_audit.config_parts.inventory import (
    as_bool,
    as_dict,
    as_list,
    format_hms,
    parse_hms,
)


@dataclass(slots=True, frozen=True)
class CredentialConfig:
    """Represent credentialconfig settings."""
    username: str = ""
    password: str = ""
    name: str = ""

    @classmethod
    def from_mapping(cls, data: Any, *, name: str = "") -> CredentialConfig:
        data = as_dict(data)
        return cls(
            username=str(data.get("username", "") or "").strip(),
            password=str(data.get("password", "") or ""),
            name=str(data.get("name", name) or name).strip(),
        )

    @classmethod
    def from_env(
        cls,
        *,
        username_key: str,
        password_key: str,
        username_default: str = "",
        password_default: str = "",
        name: str = "",
    ) -> CredentialConfig:
        return cls(
            username=env_str(username_key, username_default),
            password=env_raw(password_key, password_default),
            name=name,
        )

    @property
    def is_valid(self) -> bool:
        return bool(self.username and self.password)

    def masked(self) -> dict[str, str]:
        return {
            "name": self.name,
            "username": self.username,
            "password": "***" if self.password else "",
        }


@dataclass(slots=True, frozen=True)
class MikroTikAuthConfig:
    """Represent mikrotikauthconfig settings."""
    primary: CredentialConfig = field(default_factory=CredentialConfig)
    fallback: list[CredentialConfig] = field(default_factory=list)
    auth_retries: int = 1

    @classmethod
    def from_sources(cls, secrets: dict[str, Any]) -> MikroTikAuthConfig:
        mikrotik_data = as_dict(secrets.get("mikrotik"))

        yaml_primary = CredentialConfig.from_mapping(
            mikrotik_data.get("primary"),
            name="primary",
        )
        env_primary = CredentialConfig.from_env(
            username_key="MIKROTIK_USERNAME",
            password_key="MIKROTIK_PASSWORD",
            name="primary",
        )

        primary = env_primary if env_primary.is_valid else yaml_primary

        fallback: list[CredentialConfig] = []
        for index, item in enumerate(as_list(mikrotik_data.get("fallback")), start=1):
            cred = CredentialConfig.from_mapping(item, name=f"fallback_{index}")
            if cred.is_valid:
                fallback.append(cred)

        return cls(
            primary=primary,
            fallback=fallback,
            auth_retries=max(1, env_int("MIKROTIK_AUTH_RETRIES", 1)),
        )

    def iter_credentials(self) -> Iterator[CredentialConfig]:
        if self.primary.is_valid:
            yield self.primary

        seen: set[tuple[str, str]] = set()
        if self.primary.is_valid:
            seen.add((self.primary.username, self.primary.password))

        for cred in self.fallback:
            if not cred.is_valid:
                continue

            key = (cred.username, cred.password)
            if key in seen:
                continue

            seen.add(key)
            yield cred

    @property
    def credentials(self) -> list[CredentialConfig]:
        return list(self.iter_credentials())

    @property
    def username(self) -> str:
        return self.primary.username

    @property
    def password(self) -> str:
        return self.primary.password


@dataclass(slots=True, frozen=True)
class PHPIPAMConfig:
    """Represent phpipamconfig settings."""
    enabled: bool = False
    base_url: str = ""
    app_id: str = ""
    username: str = ""
    password: str = ""
    section_id: str = ""
    subnet_id: str = ""
    verify_ssl: bool = True
    timeout: int = 10
    sync_enabled: bool = False
    create_missing: bool = False
    update_existing: bool = True

    @classmethod
    def from_sources(cls, secrets: dict[str, Any]) -> PHPIPAMConfig:
        phpipam_data = as_dict(secrets.get("phpipam"))

        return cls(
            enabled=env_bool("PHPIPAM_ENABLED", False),
            base_url=env_str("PHPIPAM_BASE_URL").rstrip("/"),
            app_id=env_str("PHPIPAM_APP_ID"),
            username=env_str("PHPIPAM_USERNAME", str(phpipam_data.get("username", "") or "")),
            password=env_raw("PHPIPAM_PASSWORD", str(phpipam_data.get("password", "") or "")),
            section_id=env_str("PHPIPAM_SECTION_ID"),
            subnet_id=env_str("PHPIPAM_SUBNET_ID"),
            verify_ssl=env_bool("PHPIPAM_VERIFY_SSL", True),
            timeout=env_int("PHPIPAM_TIMEOUT", 10),
            sync_enabled=env_bool("PHPIPAM_SYNC_ENABLED", False),
            create_missing=env_bool("PHPIPAM_CREATE_MISSING", False),
            update_existing=env_bool("PHPIPAM_UPDATE_EXISTING", True),
        )


@dataclass(slots=True, frozen=True)
class GoogleConfig:
    """Represent googleconfig settings."""
    enabled: bool = False
    credentials_file: str = ""
    spreadsheet: str = ""
    worksheet: str = "mikrotik_inventory"
    max_batch_cells: int = 10000
    suppress_cell_limit_errors: bool = True

    @classmethod
    def from_sources(cls, secrets: dict[str, Any]) -> GoogleConfig:
        google_data = as_dict(secrets.get("google"))

        return cls(
            enabled=env_bool("GOOGLE_ENABLED", False),
            credentials_file=env_str(
                "GOOGLE_CREDENTIALS_FILE",
                str(google_data.get("credentials_file", "") or ""),
            ),
            spreadsheet=env_str("GOOGLE_SPREADSHEET"),
            worksheet=env_str("GOOGLE_WORKSHEET", "mikrotik_inventory"),
            max_batch_cells=max(
                1,
                env_int(
                    "GOOGLE_MAX_BATCH_CELLS",
                    int(google_data.get("max_batch_cells", 10000) or 10000),
                ),
            ),
            suppress_cell_limit_errors=env_bool(
                "GOOGLE_SUPPRESS_CELL_LIMIT_ERRORS",
                as_bool(google_data.get("suppress_cell_limit_errors"), True),
            ),
        )


@dataclass(slots=True, frozen=True)
class FirmwareConfig:
    """Represent firmwareconfig settings."""
    credentials: CredentialConfig = field(default_factory=CredentialConfig)
    directory: str = "firmware"
    auto_upload_mmips: bool = False
    auto_reboot_after_upload: bool = False
    only_if_version_diff: bool = True

    @classmethod
    def from_sources(
        cls,
        *,
        secrets: dict[str, Any],
        fallback_credential: CredentialConfig | None = None,
    ) -> FirmwareConfig:
        firmware_data = as_dict(secrets.get("firmware"))
        yaml_cred = CredentialConfig.from_mapping(firmware_data, name="firmware")

        env_cred = CredentialConfig.from_env(
            username_key="FIRMWARE_USERNAME",
            password_key="FIRMWARE_PASSWORD",
            username_default=fallback_credential.username if fallback_credential else "",
            password_default=fallback_credential.password if fallback_credential else "",
            name="firmware",
        )

        credentials = env_cred if env_cred.is_valid else yaml_cred

        return cls(
            credentials=credentials,
            directory=env_str("FIRMWARE_DIR", "firmware"),
            auto_upload_mmips=env_bool("AUTO_UPLOAD_MMIPS", False),
            auto_reboot_after_upload=env_bool("AUTO_REBOOT_AFTER_UPLOAD", False),
            only_if_version_diff=env_bool("ONLY_IF_VERSION_DIFF", True),
        )


@dataclass(slots=True, frozen=True)
class GatewayAuthConfig:
    """Represent gatewayauthconfig settings."""
    credentials: CredentialConfig = field(default_factory=CredentialConfig)

    @classmethod
    def from_sources(cls, secrets: dict[str, Any]) -> GatewayAuthConfig:
        gateway_data = as_dict(secrets.get("us_gateway"))
        yaml_cred = CredentialConfig.from_mapping(gateway_data, name="us_gateway")
        env_cred = CredentialConfig.from_env(
            username_key="GATEWAY_USERNAME",
            password_key="GATEWAY_PASSWORD",
            username_default="",
            password_default="",
            name="us_gateway",
        )
        return cls(credentials=env_cred if env_cred.is_valid else yaml_cred)


@dataclass(slots=True, frozen=True)
class RadiusConfig:
    """Represent radiusconfig settings."""
    address: str = ""
    secret: str = ""
    service: str = "login"

    @classmethod
    def from_sources(cls, *, secrets: dict[str, Any], inventory_data: dict[str, Any]) -> RadiusConfig:
        secrets_radius = as_dict(secrets.get("radius"))
        inventory_radius = as_dict(inventory_data.get("radius"))

        return cls(
            address=env_str(
                "RADIUS_ADDR",
                str(inventory_radius.get("address", secrets_radius.get("address", "")) or ""),
            ),
            secret=env_raw(
                "RADIUS_SECRET",
                str(inventory_radius.get("secret", secrets_radius.get("secret", "")) or ""),
            ),
            service=env_str(
                "RADIUS_SERVICE",
                str(inventory_radius.get("service", secrets_radius.get("service", "login")) or "login"),
            ),
        )


@dataclass(slots=True, frozen=True)
class NTPConfig:
    """Represent ntpconfig settings."""
    enabled: str = ""
    servers: list[str] = field(default_factory=list)

    @classmethod
    def from_inventory(cls, data: Any) -> NTPConfig:
        data = as_dict(data)
        return cls(
            enabled=str(data.get("enabled", "") or "").strip(),
            servers=[str(item).strip() for item in as_list(data.get("servers")) if str(item).strip()],
        )


@dataclass(slots=True, frozen=True)
class SchedulerRule:
    """Represent schedulerrule."""
    name: str = ""
    interval: str = ""
    on_event: str = ""
    policy: str = ""
    start_date: str = ""
    start_time: str = ""
    start_time_mode: str = "fixed"
    time_window_start: str = ""
    time_window_end: str = ""
    slot_minutes: int = 0
    seed_by: str = "ip"
    disabled: str = "no"

    @classmethod
    def from_inventory(cls, data: Any) -> SchedulerRule:
        data = as_dict(data)

        return cls(
            name=str(data.get("name", "") or "").strip(),
            interval=str(data.get("interval", "") or "").strip(),
            on_event=str(data.get("on_event", "") or "").strip(),
            policy=str(data.get("policy", "") or "").strip(),
            start_date=str(data.get("start_date", "") or "").strip(),
            start_time=str(data.get("start_time", "") or "").strip(),
            start_time_mode=str(data.get("start_time_mode", "fixed") or "fixed").strip().lower(),
            time_window_start=str(data.get("time_window_start", "") or "").strip(),
            time_window_end=str(data.get("time_window_end", "") or "").strip(),
            slot_minutes=int(data.get("slot_minutes", 0) or 0),
            seed_by=str(data.get("seed_by", "ip") or "ip").strip().lower(),
            disabled=str(data.get("disabled", "no") or "no").strip(),
        )

    @property
    def is_staggered(self) -> bool:
        return self.start_time_mode == "staggered"

    def resolve_seed(self, *, ip: str, identity: str = "") -> str:
        seed_mode = self.seed_by or "ip"

        if seed_mode == "identity":
            return identity or ip
        if seed_mode in {"identity_name", "identity-and-name"}:
            base = identity or ip
            return f"{base}:{self.name}"
        if seed_mode in {"ip_name", "ip-and-name"}:
            return f"{ip}:{self.name}"

        return ip

    def resolve_start_time(self, seed: str) -> str:
        if not self.is_staggered:
            return self.start_time

        start = parse_hms(self.time_window_start)
        end = parse_hms(self.time_window_end)

        if start is None or end is None or end < start or self.slot_minutes <= 0:
            return self.start_time

        slot_seconds = self.slot_minutes * 60
        slot_count = max(1, ((end - start) // slot_seconds) + 1)
        digest = sha1(seed.encode("utf-8")).hexdigest()
        slot_index = int(digest[:8], 16) % slot_count

        return format_hms(start + slot_index * slot_seconds)

    def resolve_device_start_time(self, *, ip: str, identity: str = "") -> str:
        return self.resolve_start_time(
            self.resolve_seed(ip=ip, identity=identity),
        )


@dataclass(slots=True, frozen=True)
class SchedulerConfig:
    """Represent schedulerconfig settings."""
    enabled: bool = False
    expected: list[SchedulerRule] = field(default_factory=list)

    @classmethod
    def from_inventory(cls, data: Any) -> SchedulerConfig:
        data = as_dict(data)
        return cls(
            enabled=as_bool(data.get("enabled"), True),
            expected=[
                SchedulerRule.from_inventory(item)
                for item in as_list(data.get("expected"))
                if isinstance(item, dict)
            ],
        )


@dataclass(slots=True, frozen=True)
class WatchdogConfig:
    """Represent watchdogconfig settings."""
    automatic_supout: str = ""
    ping_start_after_boot: str = ""
    ping_timeout: str = ""
    watchdog_timer: str = ""

    @classmethod
    def from_inventory(cls, data: Any) -> WatchdogConfig:
        data = as_dict(data)
        return cls(
            automatic_supout=str(data.get("automatic_supout", "") or "").strip(),
            ping_start_after_boot=str(data.get("ping_start_after_boot", "") or "").strip(),
            ping_timeout=str(data.get("ping_timeout", "") or "").strip(),
            watchdog_timer=str(data.get("watchdog_timer", "") or "").strip(),
        )


@dataclass(slots=True, frozen=True)
class RuntimeConfig:
    """Represent runtimeconfig settings."""
    workers: int = 100
    ssh_port: int = 22
    connect_timeout: int = 2
    auth_timeout: int = 2
    banner_timeout: int = 5
    command_timeout: int = 7
    ping_timeout: int = 1
    ping_count: int = 1
    max_targets: int = 0

    @classmethod
    def from_sources(cls, inventory_data: dict[str, Any]) -> RuntimeConfig:
        runtime = as_dict(as_dict(inventory_data.get("settings")).get("runtime"))
        connect_timeout = env_int(
            "MIKROTIK_TIMEOUT",
            int(runtime.get("connect_timeout", 2) or 2),
        )

        return cls(
            workers=env_int("MIKROTIK_WORKERS", int(runtime.get("workers", 100) or 100)),
            ssh_port=env_int("MIKROTIK_SSH_PORT", int(runtime.get("ssh_port", 22) or 22)),
            connect_timeout=connect_timeout,
            auth_timeout=env_int(
                "MIKROTIK_AUTH_TIMEOUT",
                int(runtime.get("auth_timeout", connect_timeout) or connect_timeout),
            ),
            banner_timeout=env_int(
                "MIKROTIK_BANNER_TIMEOUT",
                int(runtime.get("banner_timeout", max(connect_timeout, 5)) or max(connect_timeout, 5)),
            ),
            command_timeout=env_int(
                "MIKROTIK_COMMAND_TIMEOUT",
                int(runtime.get("command_timeout", connect_timeout + 5) or (connect_timeout + 5)),
            ),
            ping_timeout=env_int(
                "MIKROTIK_PING_TIMEOUT",
                int(runtime.get("ping_timeout", 1) or 1),
            ),
            ping_count=env_int(
                "MIKROTIK_PING_COUNT",
                int(runtime.get("ping_count", 1) or 1),
            ),
            max_targets=env_int(
                "MAX_TARGETS",
                int(runtime.get("max_targets", 0) or 0),
            ),
        )


@dataclass(slots=True, frozen=True)
class ServiceConfig:
    """Represent serviceconfig settings."""
    enabled: bool = False
    action: str = "audit"
    interval_seconds: int = 3600
    progress: bool = False

    @classmethod
    def from_inventory(cls, inventory_data: dict[str, Any]) -> ServiceConfig:
        service = as_dict(as_dict(inventory_data.get("settings")).get("service"))
        return cls(
            enabled=env_bool("SERVICE_ENABLED", as_bool(service.get("enabled"), False)),
            action=env_str(
                "SERVICE_ACTION",
                str(service.get("action", "audit") or "audit"),
            ).strip().lower(),
            interval_seconds=env_int(
                "SERVICE_INTERVAL_SECONDS",
                int(service.get("interval_seconds", 3600) or 3600),
            ),
            progress=env_bool("SERVICE_PROGRESS", as_bool(service.get("progress"), False)),
        )


@dataclass(slots=True, frozen=True)
class AuditConfig:
    """Represent auditconfig settings."""
    read_only: bool = True
    preload_phpipam_cache: bool = True
    export_single_audit: bool = True
    fail_fast: bool = False

    @classmethod
    def from_inventory(cls, inventory_data: dict[str, Any]) -> AuditConfig:
        audit = as_dict(as_dict(inventory_data.get("settings")).get("audit"))
        return cls(
            read_only=env_bool("AUDIT_READ_ONLY", as_bool(audit.get("read_only"), True)),
            preload_phpipam_cache=env_bool(
                "PRELOAD_PHPIPAM_CACHE",
                as_bool(audit.get("preload_phpipam_cache"), True),
            ),
            export_single_audit=env_bool(
                "EXPORT_SINGLE_AUDIT",
                as_bool(audit.get("export_single_audit"), True),
            ),
            fail_fast=env_bool("AUDIT_FAIL_FAST", as_bool(audit.get("fail_fast"), False)),
        )


@dataclass(slots=True, frozen=True)
class ComplianceConfig:
    """Represent complianceconfig settings."""
    radius: bool = True
    ntp: bool = True
    scheduler: bool = True
    watchdog: bool = True
    phpipam: bool = True

    @classmethod
    def from_inventory(cls, inventory_data: dict[str, Any]) -> ComplianceConfig:
        compliance = as_dict(as_dict(inventory_data.get("settings")).get("compliance"))
        return cls(
            radius=env_bool("COMPLIANCE_RADIUS", as_bool(compliance.get("radius"), True)),
            ntp=env_bool("COMPLIANCE_NTP", as_bool(compliance.get("ntp"), True)),
            scheduler=env_bool("COMPLIANCE_SCHEDULER", as_bool(compliance.get("scheduler"), True)),
            watchdog=env_bool("COMPLIANCE_WATCHDOG", as_bool(compliance.get("watchdog"), True)),
            phpipam=env_bool("COMPLIANCE_PHPIPAM", as_bool(compliance.get("phpipam"), True)),
        )


@dataclass(slots=True, frozen=True)
class RemediationConfig:
    """Represent remediationconfig settings."""
    enabled: bool = True
    allow_apply: bool = False
    allow_generate_script: bool = True
    allowed_domains: list[str] = field(default_factory=lambda: ["ntp", "watchdog", "scheduler"])
    output_dir: str = "logs/remediation"
    git_enabled: bool = False
    git_repo_dir: str = "logs/script-history"
    git_author_name: str = "mikrotik-audit"
    git_author_email: str = "mikrotik-audit@local"

    @classmethod
    def from_inventory(cls, inventory_data: dict[str, Any]) -> RemediationConfig:
        remediation = as_dict(as_dict(inventory_data.get("settings")).get("remediation"))
        allowed_domains = [
            str(item).strip().lower()
            for item in as_list(remediation.get("allowed_domains"))
            if str(item).strip()
        ]
        if not allowed_domains:
            allowed_domains = ["ntp", "watchdog", "scheduler"]

        return cls(
            enabled=env_bool("REMEDIATION_ENABLED", as_bool(remediation.get("enabled"), True)),
            allow_apply=env_bool("REMEDIATION_ALLOW_APPLY", as_bool(remediation.get("allow_apply"), False)),
            allow_generate_script=env_bool(
                "REMEDIATION_ALLOW_GENERATE_SCRIPT",
                as_bool(remediation.get("allow_generate_script"), True),
            ),
            allowed_domains=allowed_domains,
            output_dir=env_str(
                "REMEDIATION_OUTPUT_DIR",
                str(remediation.get("output_dir", "logs/remediation") or "logs/remediation"),
            ),
            git_enabled=env_bool(
                "REMEDIATION_GIT_ENABLED",
                as_bool(remediation.get("git_enabled"), False),
            ),
            git_repo_dir=env_str(
                "REMEDIATION_GIT_REPO_DIR",
                str(remediation.get("git_repo_dir", "logs/script-history") or "logs/script-history"),
            ),
            git_author_name=env_str(
                "REMEDIATION_GIT_AUTHOR_NAME",
                str(remediation.get("git_author_name", "mikrotik-audit") or "mikrotik-audit"),
            ),
            git_author_email=env_str(
                "REMEDIATION_GIT_AUTHOR_EMAIL",
                str(remediation.get("git_author_email", "mikrotik-audit@local") or "mikrotik-audit@local"),
            ),
        )


@dataclass(slots=True, frozen=True)
class BackupConfig:
    """Represent backupconfig settings."""
    enabled: bool = True
    output_dir: str = "logs/config-backups"
    git_enabled: bool = True
    git_repo_dir: str = "logs/config-backup-history"
    git_author_name: str = "mikrotik-audit"
    git_author_email: str = "mikrotik-audit@local"
    export_command: str = "/export terse"
    filename_mode: str = "identity-ip"

    @classmethod
    def from_inventory(cls, inventory_data: dict[str, Any]) -> BackupConfig:
        backup = as_dict(as_dict(inventory_data.get("settings")).get("backup"))
        return cls(
            enabled=env_bool("BACKUP_ENABLED", as_bool(backup.get("enabled"), True)),
            output_dir=env_str(
                "BACKUP_OUTPUT_DIR",
                str(backup.get("output_dir", "logs/config-backups") or "logs/config-backups"),
            ),
            git_enabled=env_bool(
                "BACKUP_GIT_ENABLED",
                as_bool(backup.get("git_enabled"), True),
            ),
            git_repo_dir=env_str(
                "BACKUP_GIT_REPO_DIR",
                str(backup.get("git_repo_dir", "logs/config-backup-history") or "logs/config-backup-history"),
            ),
            git_author_name=env_str(
                "BACKUP_GIT_AUTHOR_NAME",
                str(backup.get("git_author_name", "mikrotik-audit") or "mikrotik-audit"),
            ),
            git_author_email=env_str(
                "BACKUP_GIT_AUTHOR_EMAIL",
                str(backup.get("git_author_email", "mikrotik-audit@local") or "mikrotik-audit@local"),
            ),
            export_command=env_str(
                "BACKUP_EXPORT_COMMAND",
                str(backup.get("export_command", "/export terse") or "/export terse"),
            ),
            filename_mode=env_str(
                "BACKUP_FILENAME_MODE",
                str(backup.get("filename_mode", "identity-ip") or "identity-ip"),
            ).strip().lower(),
        )


@dataclass(slots=True, frozen=True)
class ReportConfig:
    """Represent reportconfig settings."""
    output_xlsx: str = "mikrotik_inventory.xlsx"
    output_json: str | None = None
    write_excel: bool = True
    write_ndjson: bool = True
    write_google_sheets: bool = True

    @classmethod
    def from_inventory(cls, inventory_data: dict[str, Any]) -> ReportConfig:
        report = as_dict(as_dict(inventory_data.get("settings")).get("report"))
        output_xlsx = env_str(
            "OUTPUT_XLSX",
            str(report.get("output_xlsx", "mikrotik_inventory.xlsx") or "mikrotik_inventory.xlsx"),
        )
        output_json = env_optional_path("OUTPUT_JSON")
        if output_json is None:
            configured_output_json = str(report.get("output_json", "") or "").strip()
            output_json = configured_output_json or None

        return cls(
            output_xlsx=output_xlsx,
            output_json=output_json,
            write_excel=env_bool("WRITE_EXCEL_REPORT", as_bool(report.get("write_excel"), True)),
            write_ndjson=env_bool("WRITE_NDJSON_REPORT", as_bool(report.get("write_ndjson"), True)),
            write_google_sheets=env_bool(
                "WRITE_GOOGLE_SHEETS_REPORT",
                as_bool(report.get("write_google_sheets"), True),
            ),
        )
