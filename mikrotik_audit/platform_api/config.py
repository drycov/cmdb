from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class PlatformApiSettings:
    app_name: str = "MikroTik SoT API"
    app_version: str = "0.1.0"
    database_url: str = "sqlite+aiosqlite:///./mikrotik_sot.db"
    auto_create_schema: bool = True

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
        )