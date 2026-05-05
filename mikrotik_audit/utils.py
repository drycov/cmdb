from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional


# =========================
# NETWORK
# =========================
def network_of_ip(ip: str, prefix: int = 24) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP: {ip}")

    if address.version != 4:
        raise ValueError(f"Only IPv4 is supported, got: {ip}")

    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


# =========================
# COMMON NORMALIZATION
# =========================
def normalize_key(key: str) -> str:
    return re.sub(r"[\s\-]+", "_", key.strip().lower())


def normalize_value(value: str) -> str:
    return value.strip()


def normalize_hostname(value: str | None) -> str:
    if not value:
        return ""

    value = value.strip().lower()

    # убираем комментарии MikroTik
    if "(" in value:
        value = value.split("(", 1)[0]

    if value.endswith("_ukg"):
        value = value[:-4]

    return value.strip()


# =========================
# PARSERS
# =========================
def parse_colon_output(output: str) -> Dict[str, str]:
    data: Dict[str, str] = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line or ":" not in line:
            continue

        key, value = line.split(":", 1)

        data[normalize_key(key)] = normalize_value(value)

    return data


def parse_detail_blocks(output: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}

    item_start = re.compile(r"^\s*(\d+)\s+([A-Z;\s]*)?(.*)$")
    kv_pattern = re.compile(r'([\w\-]+)=("[^"]*"|\S+)')

    def flush() -> None:
        nonlocal current
        if current:
            blocks.append(current)
            current = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line:
            flush()
            continue

        if line.startswith(("Flags:", "Columns:", "#")):
            continue

        start = item_start.match(raw_line)
        if start and start.group(1):
            rest = start.group(3).strip()

            if "=" in rest:
                flush()
                current["index"] = start.group(1)

                flags = (start.group(2) or "").strip()
                if flags:
                    current["flags"] = " ".join(flags.split())

                for key, value in kv_pattern.findall(rest):
                    current[normalize_key(key)] = value.strip('"')
                continue

        if "=" in line:
            for key, value in kv_pattern.findall(line):
                current[normalize_key(key)] = value.strip('"')
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            current[normalize_key(key)] = normalize_value(value)

    flush()
    return blocks

# =========================
# VERSION
# =========================
def normalize_version(version: str) -> str:
    return " ".join(version.strip().split())


def extract_version_from_filename(filename: str, architecture: str) -> str:
    name = filename.strip().lower()
    architecture = architecture.strip().lower()

    patterns = [
        rf"routeros-{architecture}-(.+?)\.npk",
        rf"routeros-(.+?)-{architecture}\.npk",
    ]

    for pattern in patterns:
        match = re.match(pattern, name)
        if match:
            return match.group(1)

    return ""


# =========================
# INTERFACES
# =========================
def parse_interface_brief(output: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []

    first_line_pattern = re.compile(
        r"^\s*(\d+)\s+([A-ZDXRS]*)\s*(?:;;; ?(.*))?$"
    )
    single_line_pattern = re.compile(
        r"^\s*(\d+)\s+([A-ZDXRS]*)\s+([A-Za-z0-9._/\-+]+)\s+\S+.*?([0-9A-Fa-f:]{17})\s*$"
    )
    second_line_pattern = re.compile(
        r"^\s*([A-Za-z0-9._/\-+]+)\s+\S+.*?([0-9A-Fa-f:]{17})\s*$"
    )

    pending: Optional[Dict[str, Any]] = None

    for raw_line in output.splitlines():
        stripped = raw_line.strip()

        if not stripped or stripped.startswith(("Flags:", "#")):
            continue

        # --- single line ---
        match = single_line_pattern.match(raw_line)
        if match:
            _, flags, name, mac = match.groups()

            items.append(_build_interface_item(name, mac, flags, ""))
            pending = None
            continue

        # --- first line ---
        match = first_line_pattern.match(raw_line)
        if match:
            _, flags, comment = match.groups()

            pending = {
                "flags": flags or "",
                "comment": comment or "",
            }
            continue

        # --- second line ---
        match = second_line_pattern.match(raw_line)
        if match and pending:
            name, mac = match.groups()

            items.append(
                _build_interface_item(
                    name,
                    mac,
                    pending.get("flags", ""),
                    pending.get("comment", ""),
                )
            )
            pending = None

    return items


def _build_interface_item(
    name: str,
    mac: str,
    flags: str,
    comment: str,
) -> Dict[str, Any]:
    flags = flags.strip()

    return {
        "name": name.strip(),
        "mac_address": mac.upper(),
        "flags": flags,
        "running": "R" in flags,
        "slave": "S" in flags,
        "disabled": "X" in flags,
        "dynamic": "D" in flags,
        "comment": comment.strip(),
    }


# =========================
# EXTRA (новое)
# =========================
def safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None


def safe_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if not value:
        return False

    value = str(value).lower()
    return value in {"yes", "true", "1", "enabled", "up"}


def compact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Удаляет пустые значения — удобно перед экспортом
    """
    return {k: v for k, v in data.items() if v not in ("", None)}
