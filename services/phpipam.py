from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional

import requests

from config import PHPIPAMConfig
from models import AuditResult


class PHPIPAMClient:
    def __init__(self, config: PHPIPAMConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = self.config.verify_ssl
        self.token: str = ""

    @property
    def api_base(self) -> str:
        return f"{self.config.base_url}/api/{self.config.app_id}"

    def authenticate(self) -> None:
        url = f"{self.api_base}/user/"
        self.logger.info(
            "phpIPAM auth start url=%s user=%s",
            url,
            self.config.username,
        )

        response = self.session.post(
            url,
            auth=(self.config.username, self.config.password),
            timeout=self.config.timeout,
        )
        response.raise_for_status()

        payload = response.json()
        if not payload.get("success"):
            raise RuntimeError(f"phpIPAM auth failed: {payload}")

        token = payload.get("data", {}).get("token")
        if not token:
            raise RuntimeError(f"phpIPAM auth token missing: {payload}")

        self.token = token
        self.session.headers.update({"token": self.token})

        self.logger.info("phpIPAM auth success")

    @staticmethod
    def ip_to_decimal(ip: str) -> int:
        return int(ipaddress.ip_address(ip))

    def get_address_by_ip(self, ip: str, subnet_id: str) -> Optional[Dict[str, Any]]:
        ip_decimal = self.ip_to_decimal(ip)
        url = f"{self.api_base}/addresses/search/{ip_decimal}/"

        self.logger.debug(
            "phpIPAM address lookup ip=%s ip_decimal=%s subnet_id=%s",
            ip,
            ip_decimal,
            subnet_id,
        )

        response = self.session.get(url, timeout=self.config.timeout)

        if response.status_code == 404:
            self.logger.debug("phpIPAM address not found ip=%s", ip)
            return None

        response.raise_for_status()

        payload = response.json()
        if not payload.get("success"):
            self.logger.debug("phpIPAM address lookup unsuccessful ip=%s payload=%s", ip, payload)
            return None

        items = payload.get("data") or []
        if isinstance(items, dict):
            items = [items]

        for item in items:
            if str(item.get("subnetId", "")) == str(subnet_id):
                self.logger.debug(
                    "phpIPAM address matched ip=%s address_id=%s subnet_id=%s",
                    ip,
                    item.get("id", ""),
                    subnet_id,
                )
                return item

        self.logger.debug("phpIPAM address found outside target subnet ip=%s subnet_id=%s", ip, subnet_id)
        return None

    def create_address(self, audit: AuditResult) -> Dict[str, Any]:
        url = f"{self.api_base}/addresses/"
        payload = self._build_address_payload(audit)

        self.logger.info("phpIPAM create address start ip=%s hostname=%s", audit.ip, payload.get("hostname", ""))

        response = self.session.post(
            url,
            json=payload,
            timeout=self.config.timeout,
        )
        response.raise_for_status()

        data = response.json()
        if not data.get("success"):
            raise RuntimeError(f"phpIPAM create failed: {data}")

        self.logger.info("phpIPAM create address success ip=%s", audit.ip)
        return data

    def _build_address_payload(self, audit: AuditResult) -> Dict[str, Any]:
        hostname = audit.identity.strip() if audit.identity else audit.ip
        description_parts = ["MikroTik"]
        if audit.board_name:
            description_parts.append(audit.board_name.strip())
        description = " ".join(part for part in description_parts if part).strip()

        note_parts = [
            f"status={audit.status}" if audit.status else "",
            f"auth={audit.auth_method}" if audit.auth_method else "",
            f"uptime={audit.uptime}" if audit.uptime else "",
            f"platform={audit.platform}" if audit.platform else "",
            f"arch={audit.architecture}" if audit.architecture else "",
        ]
        note = "; ".join(part for part in note_parts if part)

        payload: Dict[str, Any] = {
            "subnetId": self.config.subnet_id,
            "ip": self.ip_to_decimal(audit.ip),
            "hostname": hostname,
            "description": description,
            "note": note,
            # custom fields below must match actual phpIPAM field names
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

        return payload