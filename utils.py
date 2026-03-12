from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List


def network_of_ip(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        raise ValueError(f"Only IPv4 is supported, got: {ip}")

    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(network)


def parse_colon_output(output: str) -> Dict[str, str]:
    data: Dict[str, str] = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue

        key, value = line.split(":", 1)
        normalized_key = (
            key.strip()
            .lower()
            .replace(" ", "_")
            .replace("-", "_")
        )
        data[normalized_key] = value.strip()

    return data


def parse_detail_blocks(output: str) -> List[Dict[str, str]]:
    blocks: List[Dict[str, str]] = []
    current: Dict[str, str] = {}

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            if current:
                blocks.append(current)
                current = {}
            continue

        if stripped.startswith("Flags:") or stripped.startswith("Columns:"):
            continue

        if stripped.startswith("#"):
            continue

        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        normalized_key = (
            key.strip()
            .lower()
            .replace(" ", "_")
            .replace("-", "_")
        )
        current[normalized_key] = value.strip()

    if current:
        blocks.append(current)

    return blocks


def normalize_version(version: str) -> str:
    return " ".join(version.strip().split())


def extract_version_from_filename(filename: str, architecture: str) -> str:
    name = filename.strip()

    prefix = f"routeros-{architecture}-"
    suffix = ".npk"

    if name.startswith(prefix) and name.endswith(suffix):
        return name[len(prefix):-len(suffix)]

    alt_prefix = "routeros-"
    alt_suffix = f"-{architecture}.npk"

    if name.startswith(alt_prefix) and name.endswith(alt_suffix):
        return name[len(alt_prefix):-len(alt_suffix)]

    return ""


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

    pending: Dict[str, Any] | None = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("Flags:"):
            continue

        if stripped.startswith("#"):
            continue

        # Случай: вся запись в одной строке
        single_match = single_line_pattern.match(line)
        if single_match:
            _, flags, name, mac = single_match.groups()
            items.append(
                {
                    "name": name.strip(),
                    "mac_address": mac.upper(),
                    "flags": flags.strip(),
                    "running": "R" in flags,
                    "slave": "S" in flags,
                    "disabled": "X" in flags,
                    "dynamic": "D" in flags,
                    "comment": "",
                }
            )
            pending = None
            continue

        # Случай: первая строка записи, возможно с комментарием
        first_match = first_line_pattern.match(line)
        if first_match:
            _, flags, comment = first_match.groups()
            pending = {
                "flags": (flags or "").strip(),
                "comment": (comment or "").strip(),
            }
            continue

        # Случай: вторая строка записи
        second_match = second_line_pattern.match(line)
        if second_match and pending is not None:
            name, mac = second_match.groups()
            flags = str(pending.get("flags", ""))

            items.append(
                {
                    "name": name.strip(),
                    "mac_address": mac.upper(),
                    "flags": flags,
                    "running": "R" in flags,
                    "slave": "S" in flags,
                    "disabled": "X" in flags,
                    "dynamic": "D" in flags,
                    "comment": str(pending.get("comment", "")).strip(),
                }
            )
            pending = None
            continue

    return items