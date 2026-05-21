from __future__ import annotations

import os
from dataclasses import dataclass, field
from hashlib import sha1
from pathlib import Path
from typing import Any, Iterator

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv() -> bool:
        return False

load_dotenv()


# =============================================================================
# ENV HELPERS
# =============================================================================

TRUE_VALUES = {"1", "true", "yes", "on", "y"}
FALSE_VALUES = {"0", "false", "no", "off", "n"}


def env_str(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


def env_raw(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "")


def env_int(name: str, default: int) -> int:
    raw = env_str(name, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    return default


def env_optional_path(name: str) -> str | None:
    value = env_str(name)
    return value or None


def env_csv(name: str, default: str = "") -> list[str]:
    raw = env_str(name, default)
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


# =============================================================================
# YAML HELPERS
# =============================================================================


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        return {}

    if yaml is None:
        raise RuntimeError(
            "PyYAML is required to read YAML configuration files. "
            "Install the dependencies from reqqurements.txt."
        )

    try:
        with file_path.open("r", encoding="utf-8") as fh:
            payload = yaml.safe_load(fh) or {}
    except Exception:
        return {}

    return payload if isinstance(payload, dict) else {}


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default

    raw = str(value).strip().lower()
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    return default


# =============================================================================
# TIME HELPERS
# =============================================================================


def parse_hms(value: str) -> int | None:
    parts = value.split(":")
    if len(parts) != 3:
        return None

    try:
        h, m, s = (int(part) for part in parts)
    except ValueError:
        return None

    if not (0 <= h <= 23 and 0 <= m <= 59 and 0 <= s <= 59):
        return None

    return h * 3600 + m * 60 + s


def format_hms(total_seconds: int) -> str:
    total_seconds %= 24 * 3600
    h = total_seconds // 3600
    m = (total_seconds % 3600) // 60
    s = total_seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


# =============================================================================
# CREDENTIALS
# =============================================================================


@dataclass(slots=True, frozen=True)
class CredentialConfig:
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

        # Legacy env fallback compatibility.
        legacy_fallback = CredentialConfig.from_env(
            username_key="FALLBACK_USERNAME",
            password_key="FALLBACK_PASSWORD",
            username_default="satcoadm",
            password_default="",
            name="fallback_env",
        )
        if legacy_fallback.is_valid and legacy_fallback not in fallback:
            fallback.append(legacy_fallback)

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

    @property
    def fallback_username(self) -> str:
        return self.fallback[0].username if self.fallback else ""

    @property
    def fallback_password(self) -> str:
        return self.fallback[0].password if self.fallback else ""


# =============================================================================
# INTEGRATION CONFIGS
# =============================================================================


@dataclass(slots=True, frozen=True)
class PHPIPAMConfig:
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
    enabled: bool = False
    credentials_file: str = ""
    spreadsheet: str = ""
    worksheet: str = "mikrotik_inventory"

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
        )


@dataclass(slots=True, frozen=True)
class FirmwareConfig:
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


# =============================================================================
# INVENTORY-DERIVED CONFIGS
# =============================================================================


@dataclass(slots=True, frozen=True)
class NTPConfig:
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


# =============================================================================
# MAIN APP CONFIG
# =============================================================================


@dataclass(slots=True, frozen=True)
class AppConfig:
    # Logging
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

    # MikroTik connection
    mikrotik_auth: MikroTikAuthConfig

    # Behavior and output
    service: ServiceConfig
    audit: AuditConfig
    compliance: ComplianceConfig
    remediation: RemediationConfig
    backup: BackupConfig
    report: ReportConfig

    # Runtime files
    inventory_file: str
    secrets_file: str

    # Inventory behavior
    exclude_gateways: bool
    prefer_devices_over_networks: bool

    # Firmware
    firmware: FirmwareConfig
    gateway_auth: GatewayAuthConfig

    # Test mode
    test_mode: bool
    test_limit: int
    test_ips_raw: str
    test_ips: list[str]

    # Integrations
    radius: RadiusConfig
    phpipam: PHPIPAMConfig
    google: GoogleConfig

    # Inventory expected state
    ntp: NTPConfig
    scheduler: SchedulerConfig
    watchdog: WatchdogConfig

    @property
    def inventory_path(self) -> Path:
        return Path(self.inventory_file).expanduser()

    @property
    def secrets_path(self) -> Path:
        return Path(self.secrets_file).expanduser()

    # -------------------------------------------------------------------------
    # Backward-compatible aliases
    # -------------------------------------------------------------------------

    @property
    def username(self) -> str:
        return self.mikrotik_auth.username

    @property
    def password(self) -> str:
        return self.mikrotik_auth.password

    @property
    def fallback_username(self) -> str:
        return self.mikrotik_auth.fallback_username

    @property
    def fallback_password(self) -> str:
        return self.mikrotik_auth.fallback_password

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

    # -------------------------------------------------------------------------
    # Factory
    # -------------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> AppConfig:
        inventory_file = (
            env_str("INVENTORY_FILE")
            or env_str("SUBNETS_FILE")
            or "mgmt_vlan_inventory.yml"
        )
        secrets_file = env_str("SECRETS_FILE", "secrets.yml")

        secrets = load_yaml_file(secrets_file)
        inventory_data = load_yaml_file(inventory_file)

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
                    errors.append(
                        f"scheduler.expected[{index}].time_window_start must be HH:MM:SS"
                    )
                if parse_hms(rule.time_window_end) is None:
                    errors.append(
                        f"scheduler.expected[{index}].time_window_end must be HH:MM:SS"
                    )
                if rule.slot_minutes <= 0:
                    errors.append(
                        f"scheduler.expected[{index}].slot_minutes must be greater than 0"
                    )

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
            },
        }


settings = AppConfig.from_env()
