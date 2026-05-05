from __future__ import annotations

import logging

from config import PHPIPAMConfig
from constants.statuses import AuditStatus
from models import AuditResult
from services.phpipam import PHPIPAMClient
from utils import normalize_hostname


class PHPIPAMRegistryService:
    def __init__(
        self,
        config: PHPIPAMConfig,
        client: PHPIPAMClient,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.client = client
        self.logger = logger
        self._authenticated = False

    # =========================
    # INTERNAL
    # =========================
    def _ensure_auth(self) -> None:
        if not self._authenticated:
            self.client.authenticate()
            self._authenticated = True

    @staticmethod
    def _normalize_hostname(value: str | None) -> str:
        return normalize_hostname(value)

    # =========================
    # SYNC MODE (WRITE)
    # =========================
    def enrich_and_create_if_needed(self, result: AuditResult) -> AuditResult:
        if not self.config.enabled or not self.config.sync_enabled:
            return result

        self._ensure_auth()

        existing = self.client.get_address_by_ip(result.ip, self.config.subnet_id)

        if existing:
            result.phpipam_exists = True
            result.phpipam_address_id = str(existing.get("id", ""))

            self.logger.debug(
                "phpIPAM SYNC exists ip=%s address_id=%s",
                result.ip,
                result.phpipam_address_id,
            )
            return result

        result.phpipam_exists = False

        if not self._is_creatable(result):
            self.logger.debug(
                "phpIPAM SKIP create ip=%s reason=not_creatable",
                result.ip,
            )
            return result

        try:
            response = self.client.create_address(result)
            result.phpipam_created = True

            data = response.get("data")
            if isinstance(data, dict):
                result.phpipam_address_id = str(data.get("id", ""))

            self.logger.info(
                "phpIPAM CREATE ip=%s address_id=%s",
                result.ip,
                result.phpipam_address_id,
            )

        except Exception as exc:
            result.phpipam_create_error = str(exc)

            self.logger.exception(
                "phpIPAM CREATE FAILED ip=%s error=%s",
                result.ip,
                exc,
            )

        return result

    # =========================
    # REPORT MODE (READ ONLY)
    # =========================
    def enrich_report_only(self, result: AuditResult) -> AuditResult:
        if not self.config.enabled:
            return result

        self._ensure_auth()

        # reset state
        result.phpipam_exists = False
        result.phpipam_hostname_exists = False
        result.phpipam_match_type = "not_found"

        # -------------------------
        # 1. LOOKUP BY IP
        # -------------------------
        existing = self.client.get_address_by_ip(
            result.ip,
            self.config.subnet_id,
        )

        if existing:
            result.phpipam_exists = True
            result.phpipam_address_id = str(existing.get("id", ""))
            result.phpipam_hostname = str(existing.get("hostname", ""))
            result.phpipam_description = str(existing.get("description", ""))
            result.phpipam_note = str(existing.get("note", ""))
            result.phpipam_match_type = "ip"

            self.logger.info(
                "phpIPAM MATCH ip=%s type=IP address_id=%s hostname=%s",
                result.ip,
                result.phpipam_address_id,
                result.phpipam_hostname,
            )
            return result

        # -------------------------
        # 2. LOOKUP BY HOSTNAME
        # -------------------------
        hostname = self._normalize_hostname(result.identity)

        if not hostname:
            self.logger.warning(
                "phpIPAM MISS ip=%s reason=no_hostname",
                result.ip,
            )
            return result

        matches = self.client.get_addresses_by_hostname(hostname)

        if matches:
            first = matches[0]

            result.phpipam_hostname_exists = True
            result.phpipam_address_id = str(first.get("id", ""))
            result.phpipam_hostname = str(first.get("hostname", ""))
            result.phpipam_ip = str(first.get("ip", ""))
            result.phpipam_description = str(first.get("description", ""))
            result.phpipam_note = str(first.get("note", ""))
            result.phpipam_match_type = "hostname"

            self.logger.warning(
                "phpIPAM MATCH ip=%s type=HOSTNAME hostname=%s ipam_ip=%s",
                result.ip,
                hostname,
                result.phpipam_ip,
            )

            # 🔥 mismatch detection
            if result.phpipam_ip != result.ip:
                self.logger.error(
                    "phpIPAM MISMATCH ip=%s device_hostname=%s ipam_ip=%s",
                    result.ip,
                    hostname,
                    result.phpipam_ip,
                )

        else:
            raw_matches = self.client.get_addresses_by_hostname(result.identity or "")
            normalized_match = None

            for candidate in raw_matches:
                if self._normalize_hostname(candidate.get("hostname")) == hostname:
                    normalized_match = candidate
                    break

            if normalized_match is not None:
                result.phpipam_hostname_exists = True
                result.phpipam_address_id = str(normalized_match.get("id", ""))
                result.phpipam_hostname = str(normalized_match.get("hostname", ""))
                result.phpipam_ip = str(normalized_match.get("ip", ""))
                result.phpipam_description = str(normalized_match.get("description", ""))
                result.phpipam_note = str(normalized_match.get("note", ""))
                result.phpipam_match_type = "hostname"
            else:
                self.logger.error(
                    "phpIPAM MISS ip=%s hostname=%s",
                    result.ip,
                    hostname,
                )

        return result

    # =========================
    # BUSINESS RULES
    # =========================
    @staticmethod
    def _is_creatable(result: AuditResult) -> bool:
        if not result.ping:
            return False

        if not result.ssh_port:
            return False

        if result.status.startswith(AuditStatus.SSH_OK.value):
            return True

        if result.status.startswith(AuditStatus.FALLBACK_OK.value):
            return True

        return False
