"""Implementation details for services phpipam_async."""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from typing import Any

import httpx

from mikrotik_audit.config import PHPIPAMConfig
from mikrotik_audit.models import AuditResult


class AsyncPHPIPAMClient:
    """Communicate through the asyncphpipamclient client."""
    def __init__(self, config: PHPIPAMConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.token: str = ""

        self.client = httpx.AsyncClient(
            base_url=f"{config.base_url.rstrip('/')}/api/{config.app_id}",
            verify=config.verify_ssl,
            timeout=httpx.Timeout(config.timeout),
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
            ),
        )

        self._by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._by_hostname: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._cache_loaded = False

    async def close(self) -> None:
        await self.client.aclose()

    @staticmethod
    def ip_to_decimal(ip: str) -> int:
        return int(ipaddress.ip_address(ip))

    @staticmethod
    def decimal_to_ip(value: Any) -> str:
        try:
            return str(ipaddress.ip_address(int(value)))
        except Exception:
            return str(value or "")

    async def authenticate(self) -> None:
        self.logger.info("phpIPAM AUTH start app_id=%s", self.config.app_id)

        response = await self.client.post(
            "/user/",
            auth=(self.config.username, self.config.password),
        )
        response.raise_for_status()

        payload = response.json()
        if not payload.get("success"):
            raise RuntimeError(f"phpIPAM auth failed: {payload}")

        token = payload.get("data", {}).get("token")
        if not token:
            raise RuntimeError(f"phpIPAM token missing: {payload}")

        self.token = token
        self.client.headers.update({"token": token})

        self.logger.info("phpIPAM AUTH success")

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if not self.token:
            await self.authenticate()

        response = await self.client.request(method, url, **kwargs)

        if response.status_code == 403:
            self.logger.warning("phpIPAM token rejected, re-authenticating")
            await self.authenticate()
            response = await self.client.request(method, url, **kwargs)

        return response

    async def preload_addresses(self) -> None:
        if self._cache_loaded:
            return

        self.logger.info("phpIPAM cache preload started")

        response = await self._request("GET", "/addresses/all/")

        if response.status_code == 404:
            self.logger.warning("phpIPAM cache preload: no addresses returned")
            self._cache_loaded = True
            return

        response.raise_for_status()

        payload = response.json()
        if not payload.get("success"):
            raise RuntimeError(f"phpIPAM addresses preload failed: {payload}")

        rows = payload.get("data") or []
        if isinstance(rows, dict):
            rows = [rows]

        for row in rows:
            ip = self.decimal_to_ip(row.get("ip"))
            hostname = str(row.get("hostname", "") or "").strip().lower()

            if ip:
                self._by_ip[ip].append(row)

            if hostname:
                self._by_hostname[hostname].append(row)

        self._cache_loaded = True

        self.logger.info(
            "phpIPAM cache preload finished rows=%s unique_ips=%s unique_hostnames=%s",
            len(rows),
            len(self._by_ip),
            len(self._by_hostname),
        )

    def get_cached_by_ip(
        self,
        ip: str,
        subnet_id: str | None = None,
    ) -> dict[str, Any] | None:
        items = self._by_ip.get(ip, [])

        if not items:
            return None

        if not subnet_id:
            return items[0]

        for item in items:
            if str(item.get("subnetId", "")) == str(subnet_id):
                return item

        return items[0]

    def get_cached_by_hostname(self, hostname: str) -> list[dict[str, Any]]:
        hostname = hostname.strip().lower()
        if not hostname:
            return []

        return self._by_hostname.get(hostname, [])

    async def create_address(self, audit: AuditResult) -> dict[str, Any]:
        payload = self._build_address_payload(audit)

        response = await self._request("POST", "/addresses/", json=payload)
        response.raise_for_status()

        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"phpIPAM create failed: {data}")

        return data

    def _build_address_payload(self, audit: AuditResult) -> dict[str, Any]:
        hostname = audit.identity.strip() if audit.identity else audit.ip

        return {
            "subnetId": self.config.subnet_id,
            "ip": self.ip_to_decimal(audit.ip),
            "hostname": hostname,
            "description": " ".join(
                part for part in ["MikroTik", audit.board_name] if part
            ),
            "note": "; ".join(
                part
                for part in [
                    f"status={audit.status}" if audit.status else "",
                    f"auth={audit.auth_method}" if audit.auth_method else "",
                    f"uptime={audit.uptime}" if audit.uptime else "",
                    f"platform={audit.platform}" if audit.platform else "",
                    f"arch={audit.architecture}" if audit.architecture else "",
                ]
                if part
            ),
            "custom_version": audit.version,
            "custom_board_name": audit.board_name,
            "custom_platform": audit.platform,
            "custom_architecture": audit.architecture,
            "custom_status": audit.status,
            "custom_license": audit.license,
            "custom_current_firmware": audit.current_firmware,
            "custom_upgrade_firmware": audit.upgrade_firmware,
            "custom_interface_count": audit.interface_count,
        }
