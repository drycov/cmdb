from __future__ import annotations

import logging

from config import PHPIPAMConfig
from constants.statuses import AuditStatus
from models import AuditResult
from services.phpipam import PHPIPAMClient


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

    def _ensure_auth(self) -> None:
        if not self._authenticated:
            self.client.authenticate()
            self._authenticated = True

    def enrich_and_create_if_needed(self, result: AuditResult) -> AuditResult:
        if not self.config.enabled or not self.config.sync_enabled:
            return result

        self._ensure_auth()

        existing = self.client.get_address_by_ip(result.ip, self.config.subnet_id)

        if existing is not None:
            result.phpipam_exists = True
            result.phpipam_address_id = str(existing.get("id", ""))
            return result

        result.phpipam_exists = False

        # Нет в IPAM — дальше смотрим, можно ли создавать
        if not self._is_creatable(result):
            return result

        try:
            response = self.client.create_address(result)
            result.phpipam_created = True

            data = response.get("data")
            if isinstance(data, dict):
                result.phpipam_address_id = str(data.get("id", ""))

        except Exception as exc:
            result.phpipam_create_error = str(exc)
            self.logger.exception(
                "phpIPAM create failed ip=%s error=%s",
                result.ip,
                exc,
            )

        return result

    @staticmethod
    def _is_creatable(result: AuditResult) -> bool:
        # Минимальная бизнес-логика:
        # 1. ping есть
        # 2. ssh port есть
        # 3. был успешный аудит: либо primary, либо fallback
        if not result.ping:
            return False

        if not result.ssh_port:
            return False

        if result.status.startswith(AuditStatus.SSH_OK.value):
            return True

        if result.status.startswith(AuditStatus.FALLBACK_OK.value):
            return True

        return False