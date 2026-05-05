from __future__ import annotations

import os
from dataclasses import dataclass, field
from hashlib import sha1
from pathlib import Path
from typing import Any, Iterator

import yaml
from dotenv import load_dotenv

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

    # MikroTik connection
    mikrotik_auth: MikroTikAuthConfig
    ssh_port: int
    timeout: int
    banner_timeout: int
    workers: int

    # Output
    output_xlsx: str
    output_json: str | None

    # Runtime files
    inventory_file: str
    secrets_file: str

    # Inventory behavior
    exclude_gateways: bool
    prefer_devices_over_networks: bool

    # Firmware
    firmware: FirmwareConfig

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
    def firmware_username(self) -> str:
        return self.firmware.credentials.username

    @property
    def firmware_password(self) -> str:
        return self.firmware.credentials.password

    @property
    def firmware_dir(self) -> str:
        return self.firmware.directory

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

            mikrotik_auth=mikrotik_auth,
            ssh_port=env_int("MIKROTIK_SSH_PORT", 22),
            timeout=env_int("MIKROTIK_TIMEOUT", 2),
            banner_timeout=env_int("MIKROTIK_BANNER_TIMEOUT", env_int("MIKROTIK_TIMEOUT", 5)),
            workers=env_int("MIKROTIK_WORKERS", 100),

            output_xlsx=env_str("OUTPUT_XLSX", "mikrotik_inventory.xlsx"),
            output_json=env_optional_path("OUTPUT_JSON"),

            inventory_file=inventory_file,
            secrets_file=secrets_file,

            exclude_gateways=env_bool("EXCLUDE_GATEWAYS", True),
            prefer_devices_over_networks=env_bool("PREFER_DEVICES_OVER_NETWORKS", True),

            firmware=FirmwareConfig.from_sources(
                secrets=secrets,
                fallback_credential=first_fallback,
            ),

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

        if errors:
            raise RuntimeError("Invalid application config:\n- " + "\n- ".join(errors))

    def safe_dump(self) -> dict[str, Any]:
        return {
            "log_level": self.log_level,
            "inventory_file": self.inventory_file,
            "secrets_file": self.secrets_file,
            "output_xlsx": self.output_xlsx,
            "mikrotik": {
                "ssh_port": self.ssh_port,
                "timeout": self.timeout,
                "banner_timeout": self.banner_timeout,
                "workers": self.workers,
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
