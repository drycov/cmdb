"""Implementation details for services phpipam."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional

import requests

from mikrotik_audit.config import PHPIPAMConfig
from mikrotik_audit.models import AuditResult


class PHPIPAMClient:
    """Communicate through the phpipamclient client."""
    def __init__(self, config: PHPIPAMConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = self.config.verify_ssl
        self.token: str = ""

    @property
    def api_base(self) -> str:
        return f"{self.config.base_url}/api/{self.config.app_id}"

    # =========================
    # AUTH
    # =========================
    def authenticate(self) -> None:
        url = f"{self.api_base}/user/"

        self.logger.info(
            "phpIPAM AUTH start url=%s user=%s",
            url,
            self.config.username,
        )

        try:
            response = self.session.post(
                url,
                auth=(self.config.username, self.config.password),
                timeout=self.config.timeout,
            )
        except Exception as exc:
            self.logger.exception("phpIPAM AUTH request failed error=%s", exc)
            raise

        response.raise_for_status()

        payload = response.json()

        if not payload.get("success"):
            self.logger.error("phpIPAM AUTH failed payload=%s", payload)
            raise RuntimeError(f"phpIPAM auth failed: {payload}")

        token = payload.get("data", {}).get("token")

        if not token:
            raise RuntimeError(f"phpIPAM auth token missing: {payload}")

        self.token = token
        self.session.headers.update({"token": token})

        self.logger.info("phpIPAM AUTH success")

    # =========================
    # UTILS
    # =========================
    @staticmethod
    def ip_to_decimal(ip: str) -> int:
        return int(ipaddress.ip_address(ip))

    # =========================
    # LOOKUP BY IP
    # =========================
    def get_address_by_ip(self, ip: str, subnet_id: str) -> Optional[Dict[str, Any]]:
        ip_decimal = self.ip_to_decimal(ip)
        url = f"{self.api_base}/addresses/search/{ip_decimal}/"

        try:
            response = self.session.get(url, timeout=self.config.timeout)
        except Exception as exc:
            self.logger.exception(
                "phpIPAM lookup failed ip=%s error=%s",
                ip,
                exc,
            )
            return None

        if response.status_code == 404:
            return None

        response.raise_for_status()

        payload = response.json()

        if not payload.get("success"):
            self.logger.debug(
                "phpIPAM lookup unsuccessful ip=%s payload=%s",
                ip,
                payload,
            )
            return None

        items = payload.get("data") or []
        if isinstance(items, dict):
            items = [items]

        for item in items:
            if str(item.get("subnetId", "")) == str(subnet_id):
                self.logger.debug(
                    "phpIPAM IP match ip=%s address_id=%s",
                    ip,
                    item.get("id"),
                )
                return item

        return None

    # =========================
    # LOOKUP BY HOSTNAME
    # =========================
    def get_addresses_by_hostname(self, hostname: str) -> list[dict[str, Any]]:
        hostname = hostname.strip()

        if not hostname:
            return []

        url = f"{self.api_base}/addresses/search_hostname/{hostname}/"

        try:
            response = self.session.get(url, timeout=self.config.timeout)
        except Exception as exc:
            self.logger.exception(
                "phpIPAM hostname lookup failed hostname=%s error=%s",
                hostname,
                exc,
            )
            return []

        if response.status_code == 404:
            return []

        response.raise_for_status()

        payload = response.json()

        if not payload.get("success"):
            return []

        data = payload.get("data") or []

        if isinstance(data, dict):
            return [data]

        return list(data)

    # =========================
    # CREATE
    # =========================
    def create_address(self, audit: AuditResult) -> Dict[str, Any]:
        url = f"{self.api_base}/addresses/"
        payload = self._build_address_payload(audit)

        self.logger.info(
            "phpIPAM CREATE start ip=%s hostname=%s",
            audit.ip,
            payload.get("hostname"),
        )

        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=self.config.timeout,
            )
        except Exception as exc:
            self.logger.exception(
                "phpIPAM CREATE request failed ip=%s error=%s",
                audit.ip,
                exc,
            )
            raise

        response.raise_for_status()

        data = response.json()

        if not data.get("success"):
            self.logger.error(
                "phpIPAM CREATE failed ip=%s payload=%s",
                audit.ip,
                data,
            )
            raise RuntimeError(f"phpIPAM create failed: {data}")

        self.logger.info("phpIPAM CREATE success ip=%s", audit.ip)

        return data

    # =========================
    # PAYLOAD
    # =========================
    def _build_address_payload(self, audit: AuditResult) -> Dict[str, Any]:
        hostname = audit.identity.strip() if audit.identity else audit.ip

        description_parts = ["MikroTik"]
        if audit.board_name:
            description_parts.append(audit.board_name.strip())

        description = " ".join(description_parts).strip()

        note_parts = [
            f"status={audit.status}",
            f"auth={audit.auth_method}",
            f"uptime={audit.uptime}",
            f"platform={audit.platform}",
            f"arch={audit.architecture}",
        ]

        note = "; ".join(p for p in note_parts if p)

        return {
            "subnetId": self.config.subnet_id,
            "ip": self.ip_to_decimal(audit.ip),
            "hostname": hostname,
            "description": description,
            "note": note,
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
