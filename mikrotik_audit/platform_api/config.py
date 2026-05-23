"""Implementation details for platform_api config."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _parse_csv_env(value: str | None, default: list[str]) -> list[str]:
    """Internal helper for parse csv env."""
    if value is None:
        return default
    items = [item.strip() for item in value.split(",")]
    return [item for item in items if item] or default


@dataclass(slots=True)
class AuthConfig:
    """Represent authconfig settings."""
    username: str = "admin"
    password: str = "admin"
    secret: str = "change-this-secret"
    access_token_expires_seconds: int = 900
    refresh_token_expires_seconds: int = 604_800

    @classmethod
    def from_env(cls) -> "AuthConfig":
        return cls(
            username=os.getenv("MIKROTIK_SOT_AUTH_USERNAME", "admin"),
            password=os.getenv("MIKROTIK_SOT_AUTH_PASSWORD", "admin"),
            secret=os.getenv("MIKROTIK_SOT_AUTH_SECRET", "change-this-secret"),
            access_token_expires_seconds=int(
                os.getenv("MIKROTIK_SOT_ACCESS_TOKEN_EXPIRES", "900")
            ),
            refresh_token_expires_seconds=int(
                os.getenv("MIKROTIK_SOT_REFRESH_TOKEN_EXPIRES", "604800")
            ),
        )


@dataclass(slots=True)
class PlatformApiSettings:
    """Represent platformapisettings."""
    app_name: str = "MikroTik SoT API"
    app_version: str = "0.1.0"
    database_url: str = "sqlite+aiosqlite:///./mikrotik_sot.db"
    auto_create_schema: bool = True
    cors_allowed_origins: list[str] = field(
        default_factory=lambda: ["http://127.0.0.1:4173", "http://localhost:4173"]
    )
    auth_config: AuthConfig = field(default_factory=AuthConfig)

    @classmethod
    def from_env(cls) -> "PlatformApiSettings":
        return cls(
            app_name=os.getenv("MIKROTIK_SOT_APP_NAME", "MikroTik SoT API"),
            app_version=os.getenv("MIKROTIK_SOT_APP_VERSION", "0.1.0"),
            database_url=os.getenv(
                "MIKROTIK_SOT_DATABASE_URL",
                "sqlite+aiosqlite:///./mikrotik_sot.db",
            ),
            auto_create_schema=os.getenv(
                "MIKROTIK_SOT_AUTO_CREATE_SCHEMA",
                "true",
            ).strip().lower()
            in {"1", "true", "yes", "on"},
            cors_allowed_origins=_parse_csv_env(
                os.getenv("MIKROTIK_SOT_CORS_ALLOWED_ORIGINS"),
                ["http://127.0.0.1:4173", "http://localhost:4173"],
            ),
            auth_config=AuthConfig.from_env(),
        )
