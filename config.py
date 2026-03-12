from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _get_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class PHPIPAMConfig:
    enabled: bool
    base_url: str
    app_id: str
    username: str
    password: str
    section_id: str
    subnet_id: str
    verify_ssl: bool
    timeout: int
    sync_enabled: bool
    create_missing: bool
    update_existing: bool

    @classmethod
    def from_env(cls) -> "PHPIPAMConfig":
        return cls(
            enabled=_get_bool("PHPIPAM_ENABLED", False),
            base_url=os.getenv("PHPIPAM_BASE_URL", "").rstrip("/"),
            app_id=os.getenv("PHPIPAM_APP_ID", "").strip(),
            username=os.getenv("PHPIPAM_USERNAME", "").strip(),
            password=os.getenv("PHPIPAM_PASSWORD", ""),
            section_id=os.getenv("PHPIPAM_SECTION_ID", "").strip(),
            subnet_id=os.getenv("PHPIPAM_SUBNET_ID", "").strip(),
            verify_ssl=_get_bool("PHPIPAM_VERIFY_SSL", True),
            timeout=int(os.getenv("PHPIPAM_TIMEOUT", "10")),
            sync_enabled=_get_bool("PHPIPAM_SYNC_ENABLED", False),
            create_missing=_get_bool("PHPIPAM_CREATE_MISSING", False),
            update_existing=_get_bool("PHPIPAM_UPDATE_EXISTING", True),
        )


@dataclass(slots=True)
class AppConfig:
    log_level: str
    log_dir: str
    log_file: str
    error_log_file: str

    username: str
    password: str

    ssh_port: int
    timeout: int
    workers: int

    fallback_username: str
    fallback_password: str

    firmware_username: str
    firmware_password: str

    radius_addr: str
    radius_secret: str
    radius_service: str

    output_xlsx: str

    firmware_dir: str
    auto_upload_mmips: bool
    auto_reboot_after_upload: bool
    only_if_version_diff: bool

    test_mode: bool
    test_limit: int
    test_ips_raw: str

    inventory_file: str
    exclude_gateways: bool
    prefer_devices_over_networks: bool

    phpipam: PHPIPAMConfig

    @property
    def inventory_path(self) -> Path:
        return Path(self.inventory_file)

    @classmethod
    def from_env(cls) -> "AppConfig":
        fallback_username = os.getenv("FALLBACK_USERNAME", "satcoadm").strip()
        fallback_password = os.getenv("FALLBACK_PASSWORD", "password")

        # Обратная совместимость:
        # если INVENTORY_FILE не задан, используем старый SUBNETS_FILE,
        # но по умолчанию уже ориентируемся на YAML inventory.
        inventory_file = (
            os.getenv("INVENTORY_FILE")
            or os.getenv("SUBNETS_FILE")
            or "mgmt_vlan_inventory.yml"
        )

        return cls(
            log_level=os.getenv("LOG_LEVEL", "INFO").upper().strip(),
            log_dir=os.getenv("LOG_DIR", "logs").strip(),
            log_file=os.getenv("LOG_FILE", "mikrotik_audit.log").strip(),
            error_log_file=os.getenv(
                "ERROR_LOG_FILE",
                "mikrotik_audit.error.log",
            ).strip(),
            username=os.getenv("MIKROTIK_USERNAME", "").strip(),
            password=os.getenv("MIKROTIK_PASSWORD", ""),
            ssh_port=int(os.getenv("MIKROTIK_SSH_PORT", "22")),
            timeout=int(os.getenv("MIKROTIK_TIMEOUT", "2")),
            workers=int(os.getenv("MIKROTIK_WORKERS", "100")),
            fallback_username=fallback_username,
            fallback_password=fallback_password,
            firmware_username=os.getenv(
                "FIRMWARE_USERNAME",
                fallback_username,
            ).strip(),
            firmware_password=os.getenv(
                "FIRMWARE_PASSWORD",
                fallback_password,
            ),
            radius_addr=os.getenv("RADIUS_ADDR", "10.216.40.3").strip(),
            radius_secret=os.getenv("RADIUS_SECRET", "secret"),
            radius_service=os.getenv("RADIUS_SERVICE", "login").strip(),
            output_xlsx=os.getenv(
                "OUTPUT_XLSX",
                "mikrotik_inventory.xlsx",
            ).strip(),
            firmware_dir=os.getenv("FIRMWARE_DIR", "firmware").strip(),
            auto_upload_mmips=_get_bool("AUTO_UPLOAD_MMIPS", False),
            auto_reboot_after_upload=_get_bool(
                "AUTO_REBOOT_AFTER_UPLOAD",
                False,
            ),
            only_if_version_diff=_get_bool("ONLY_IF_VERSION_DIFF", True),
            test_mode=_get_bool("TEST_MODE", False),
            test_limit=int(os.getenv("TEST_LIMIT", "2")),
            test_ips_raw=os.getenv("TEST_IPS", "").strip(),
            inventory_file=inventory_file.strip(),
            exclude_gateways=_get_bool("EXCLUDE_GATEWAYS", True),
            prefer_devices_over_networks=_get_bool(
                "PREFER_DEVICES_OVER_NETWORKS",
                True,
            ),
            phpipam=PHPIPAMConfig.from_env(),
        )