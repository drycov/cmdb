from __future__ import annotations

import logging
from typing import Iterable

from config import PHPIPAMConfig
from models import AuditResult
from services.phpipam import PHPIPAMClient


class PHPIPAMSyncService:
    def __init__(
        self,
        config: PHPIPAMConfig,
        client: PHPIPAMClient,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.client = client
        self.logger = logger

    def sync_results(self, results: Iterable[AuditResult]) -> None:
        if not self.config.enabled or not self.config.sync_enabled:
            self.logger.info("phpIPAM sync skipped: disabled")
            return

        self.client.authenticate()

        for result in results:
            self.sync_one(result)

    def sync_one(self, result: AuditResult) -> None:
        existing = self.client.get_address_by_ip(result.ip, self.config.subnet_id)

        if existing is None:
            if not self.config.create_missing:
                self.logger.info(
                    "phpIPAM create skipped ip=%s reason=create_missing_disabled",
                    result.ip,
                )
                return

            self.client.create_address(result)
            return

        if not self.config.update_existing:
            self.logger.info(
                "phpIPAM update skipped ip=%s reason=update_existing_disabled",
                result.ip,
            )
            return

        self.client.update_address(str(existing["id"]), result)
