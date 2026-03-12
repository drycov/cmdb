from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

from config import AppConfig


class TargetProvider:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def get_target_ips(self) -> list[str]:
        inventory_path = Path(self.config.inventory_file)
        if not inventory_path.exists():
            raise FileNotFoundError(
                f"Inventory file not found: {inventory_path}"
            )

        data = self._load_yaml(inventory_path)
        vlans = data.get("vlans", [])
        if not isinstance(vlans, list):
            raise ValueError("Inventory format error: 'vlans' must be a list")

        ip_set: set[str] = set()

        for vlan in vlans:
            if not isinstance(vlan, dict):
                continue

            networks = vlan.get("networks", [])
            if not isinstance(networks, list):
                continue

            for network_item in networks:
                if not isinstance(network_item, dict):
                    continue

                subnet_raw = network_item.get("subnet")
                gateway_raw = network_item.get("gateway")

                if not subnet_raw:
                    continue

                subnet = ipaddress.ip_network(subnet_raw, strict=False)
                gateway_ip = None

                if gateway_raw:
                    gateway_ip = ipaddress.ip_address(gateway_raw)

                for host in subnet.hosts():
                    if self.config.exclude_gateways and gateway_ip and host == gateway_ip:
                        continue
                    ip_set.add(str(host))

        return sorted(ip_set, key=self._ip_sort_key)

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        if not isinstance(data, dict):
            raise ValueError("Inventory root must be a mapping/dict")

        return data

    @staticmethod
    def _ip_sort_key(ip: str) -> tuple[int, int, int, int]:
        return tuple(int(part) for part in ip.split("."))