from __future__ import annotations

import logging

from config import PHPIPAMConfig
from models import AuditResult
from services.phpipam_async import AsyncPHPIPAMClient
from utils import normalize_hostname


class AsyncPHPIPAMRegistryService:
    def __init__(
        self,
        config: PHPIPAMConfig,
        client: AsyncPHPIPAMClient,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.client = client
        self.logger = logger

    async def preload(self) -> None:
        if not self.config.enabled:
            return

        await self.client.preload_addresses()

    # =========================
    # MAIN LOGIC
    # =========================

    def enrich_report_only_from_cache(self, result: AuditResult) -> AuditResult:
        result.phpipam_exists = False
        result.phpipam_hostname_exists = False
        result.phpipam_match_type = "not_found"
        result.inventory_status = "NOT_FOUND"
        result.inventory_severity = "ERROR"

        item = self.client.get_cached_by_ip(result.ip, self.config.subnet_id or None)

        if item:
            result.phpipam_exists = True
            result.phpipam_address_id = str(item.get("id", ""))
            result.phpipam_hostname = str(item.get("hostname", ""))
            result.phpipam_ip = result.ip
            result.phpipam_description = str(item.get("description", ""))
            result.phpipam_note = str(item.get("note", ""))
            result.phpipam_match_type = "ip"

            device_hostname = self._normalize_hostname(result.identity)
            ipam_hostname = self._normalize_hostname(result.phpipam_hostname)

            if not device_hostname or not ipam_hostname:
                result.inventory_status = "HOSTNAME_INCOMPLETE"
                result.inventory_severity = "WARNING"
            elif device_hostname == ipam_hostname:
                result.inventory_status = "OK"
                result.inventory_severity = "INFO"
            elif device_hostname in ipam_hostname or ipam_hostname in device_hostname:
                result.inventory_status = "HOSTNAME_PARTIAL_MATCH"
                result.inventory_severity = "WARNING"
            else:
                result.inventory_status = "HOSTNAME_MISMATCH"
                result.inventory_severity = "WARNING"

            self.logger.warning(
                "phpIPAM IP match hostname_check ip=%s device_hostname=%s ipam_hostname=%s status=%s",
                result.ip,
                device_hostname,
                ipam_hostname,
                result.inventory_status,
            )

            return result

        hostname = self._normalize_hostname(result.identity)
        if not hostname:
            result.inventory_status = "HOSTNAME_INCOMPLETE"
            result.inventory_severity = "WARNING"
            self.logger.warning("phpIPAM MISS ip=%s reason=no_device_hostname", result.ip)
            return result

        matches = self.client.get_cached_by_hostname(hostname)

        if matches:
            first = matches[0]
            result.phpipam_hostname_exists = True
            result.phpipam_address_id = str(first.get("id", ""))
            result.phpipam_hostname = str(first.get("hostname", ""))
            result.phpipam_ip = self.client.decimal_to_ip(first.get("ip"))
            result.phpipam_description = str(first.get("description", ""))
            result.phpipam_note = str(first.get("note", ""))
            result.phpipam_match_type = "hostname"

            if result.phpipam_ip == result.ip:
                result.inventory_status = "OK"
                result.inventory_severity = "INFO"
            else:
                result.inventory_status = "HOSTNAME_MISMATCH"
                result.inventory_severity = "WARNING"

            return result

        equivalent = self._find_equivalent_hostname_match(hostname)

        if equivalent:
            result.phpipam_hostname_exists = True
            result.phpipam_address_id = str(equivalent.get("id", ""))
            result.phpipam_hostname = str(equivalent.get("hostname", ""))
            result.phpipam_ip = self.client.decimal_to_ip(equivalent.get("ip"))
            result.phpipam_description = str(equivalent.get("description", ""))
            result.phpipam_note = str(equivalent.get("note", ""))
            result.phpipam_match_type = "hostname"

            if result.phpipam_ip == result.ip:
                result.inventory_status = "OK"
                result.inventory_severity = "INFO"
            else:
                result.inventory_status = "HOSTNAME_MISMATCH"
                result.inventory_severity = "WARNING"

            return result

        partial = self._find_partial_hostname_match(hostname)

        if partial:
            result.phpipam_hostname_exists = True
            result.phpipam_address_id = str(partial.get("id", ""))
            result.phpipam_hostname = str(partial.get("hostname", ""))
            result.phpipam_ip = self.client.decimal_to_ip(partial.get("ip"))
            result.phpipam_description = str(partial.get("description", ""))
            result.phpipam_note = str(partial.get("note", ""))
            result.phpipam_match_type = "partial_hostname"
            result.inventory_status = "HOSTNAME_PARTIAL_MATCH"
            result.inventory_severity = "WARNING"

            self.logger.warning(
                "phpIPAM PARTIAL HOSTNAME MATCH device_ip=%s device_hostname=%s ipam_hostname=%s ipam_ip=%s",
                result.ip,
                hostname,
                result.phpipam_hostname,
                result.phpipam_ip,
            )

            return result

        self.logger.error("phpIPAM MISS ip=%s hostname=%s", result.ip, hostname)
        return result


    # =========================
    # HELPERS
    # =========================
    @staticmethod
    def _normalize_hostname(value: str | None) -> str:
        return normalize_hostname(value)

    def _find_equivalent_hostname_match(self, hostname: str) -> dict | None:
        hostname = self._normalize_hostname(hostname)
        if not hostname:
            return None

        for ipam_hostname, items in self.client._by_hostname.items():
            if self._normalize_hostname(ipam_hostname) == hostname:
                return items[0]

        return None


    def _find_partial_hostname_match(self, hostname: str) -> dict | None:
        hostname = self._normalize_hostname(hostname)

        if len(hostname) < 4:
            return None

        for ipam_hostname, items in self.client._by_hostname.items():
            normalized_ipam = self._normalize_hostname(ipam_hostname)

            if not normalized_ipam:
                continue

            if hostname in normalized_ipam or normalized_ipam in hostname:
                return items[0]

        return None
