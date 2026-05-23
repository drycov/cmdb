"""Implementation details for config_parts env."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv() -> bool:
        return False


load_dotenv()

TRUE_VALUES = {"1", "true", "yes", "on", "y"}
FALSE_VALUES = {"0", "false", "no", "off", "n"}


def env_str(name: str, default: str = "") -> str:
    """Handle env str."""
    return str(os.getenv(name, default) or "").strip()


def env_raw(name: str, default: str = "") -> str:
    """Handle env raw."""
    return str(os.getenv(name, default) or "")


def env_int(name: str, default: int) -> int:
    """Handle env int."""
    raw = env_str(name, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    """Handle env bool."""
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
    """Handle env optional path."""
    value = env_str(name)
    return value or None


def env_csv(name: str, default: str = "") -> list[str]:
    """Handle env csv."""
    raw = env_str(name, default)
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def resolve_project_path(path: str | Path) -> Path:
    """Resolve project path."""
    file_path = Path(path).expanduser()
    if file_path.is_absolute() or file_path.exists():
        return file_path
    return Path(__file__).resolve().parent.parent / file_path
