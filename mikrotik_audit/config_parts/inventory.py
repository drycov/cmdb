"""Implementation details for config_parts inventory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

from mikrotik_audit.config_parts.env import FALSE_VALUES, TRUE_VALUES, resolve_project_path


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    """Load yaml file."""
    file_path = resolve_project_path(path)
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
    """Handle as dict."""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """Handle as list."""
    return value if isinstance(value, list) else []


def as_bool(value: Any, default: bool = False) -> bool:
    """Handle as bool."""
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


def normalize_inventory_data(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize inventory data."""
    if not isinstance(data, dict):
        return {}

    normalized = dict(data)
    flat_vlans: list[dict[str, Any]] = []
    target_networks: list[dict[str, Any]] = []

    for item in as_list(data.get("vlans")):
        vlan = as_dict(item)
        if vlan:
            flat_vlans.append(vlan)
            for network in as_list(vlan.get("networks")):
                network_item = as_dict(network)
                if network_item:
                    target_networks.append(network_item)

    for group in as_list(data.get("inventory_groups")):
        group_data = as_dict(group)
        group_type = str(group_data.get("type", "") or "").strip().lower()
        group_name = str(group_data.get("name", "") or group_type).strip()
        for item in as_list(group_data.get("vlans")):
            vlan = dict(as_dict(item))
            if not vlan:
                continue
            if group_type and "inventory_type" not in vlan:
                vlan["inventory_type"] = group_type
            if group_name and "inventory_group" not in vlan:
                vlan["inventory_group"] = group_name
            flat_vlans.append(vlan)
            for network in as_list(vlan.get("networks")):
                network_item = dict(as_dict(network))
                if not network_item:
                    continue
                if group_type and "inventory_type" not in network_item:
                    network_item["inventory_type"] = group_type
                if group_name and "inventory_group" not in network_item:
                    network_item["inventory_group"] = group_name
                target_networks.append(network_item)

    environments = as_dict(data.get("environments"))
    for environment_type, entries in environments.items():
        env_type = str(environment_type or "").strip().lower()
        for entry in as_list(entries):
            entry_data = dict(as_dict(entry))
            if not entry_data:
                continue
            entry_name = str(entry_data.get("name", "") or env_type).strip()
            networks = [dict(as_dict(item)) for item in as_list(entry_data.get("networks")) if as_dict(item)]

            for network_item in networks:
                if env_type and "inventory_type" not in network_item:
                    network_item["inventory_type"] = env_type
                if entry_name and "inventory_group" not in network_item:
                    network_item["inventory_group"] = entry_name
                target_networks.append(network_item)

            if "id" not in entry_data or "vlan_name" not in entry_data:
                continue

            vlan = {
                "id": entry_data.get("id"),
                "name": entry_data.get("vlan_name"),
                "ignored_ips": entry_data.get("ignored_ips", []),
                "ospf": entry_data.get("ospf"),
                "networks": networks,
                "inventory_type": env_type,
                "inventory_group": entry_name,
            }
            flat_vlans.append(vlan)

    normalized["vlans"] = flat_vlans
    normalized["target_networks"] = target_networks
    return normalized


def parse_hms(value: str) -> int | None:
    """Parse hms."""
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
    """Handle format hms."""
    total_seconds %= 24 * 3600
    h = total_seconds // 3600
    m = (total_seconds % 3600) // 60
    s = total_seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"
