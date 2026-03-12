from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List

from config import AppConfig
from constants.statuses import AuditStatus
from domain.auditor import DeviceAuditor
from domain.exporter import ExcelExporter
from domain.phpipam_registry import PHPIPAMRegistryService
from domain.targets import TargetProvider
from models import AuditResult
from tqdm import tqdm
from services.routeros_script_generator import RouterOSScriptGenerator


class AuditRunner:
    def __init__(
        self,
        config: AppConfig,
        logger: logging.Logger,
        target_provider: TargetProvider,
        auditor: DeviceAuditor,
        exporter: ExcelExporter,
        phpipam_registry: PHPIPAMRegistryService | None = None,
        script_generator: RouterOSScriptGenerator | None = None,
    ) -> None:
        self.config = config
        self.logger = logger
        self.target_provider = target_provider
        self.auditor = auditor
        self.exporter = exporter
        self.phpipam_registry = phpipam_registry
        self.script_generator = script_generator
        self.executor = ThreadPoolExecutor(max_workers=self.config.workers)

    async def run(self) -> None:
        self.logger.info("Run started")

        try:
            ips = self.target_provider.get_target_ips()

            if not ips:
                self.logger.warning("No target IPs found")
                return

            if self.config.test_mode and self.config.auto_upload_mmips and len(ips) > 2:
                self.logger.error(
                    "Refusing firmware upload in TEST_MODE for more than 2 devices"
                )
                return

            self.logger.info("Total target IPs: %s", len(ips))

            loop = asyncio.get_running_loop()
            tasks = [
                loop.run_in_executor(self.executor, self.auditor.audit_device, ip)
                for ip in ips
            ]

            results: List[AuditResult] = []

            stats = {
                "alive": 0,
                "ssh_ok": 0,
                "fallback": 0,
                "fail": 0,
                "scripts": 0,
            }

            with tqdm(total=len(tasks), desc="Scanning MikroTik") as pbar:
                for future in asyncio.as_completed(tasks):
                    result = await future

                    if self.phpipam_registry is not None:
                        try:
                            result = self.phpipam_registry.enrich_and_create_if_needed(
                                result
                            )
                        except Exception as exc:
                            self.logger.exception(
                                "phpIPAM registry processing failed ip=%s error=%s",
                                result.ip,
                                exc,
                            )
                            result.phpipam_create_error = str(exc)

                    if self.script_generator is not None:
                        try:
                            script_path = self.script_generator.generate_for_result(result)
                            if script_path is not None:
                                stats["scripts"] += 1
                                self.logger.warning(
                                    "Generated migration script ip=%s file=%s",
                                    result.ip,
                                    script_path,
                                )
                        except Exception as exc:
                            self.logger.exception(
                                "Failed to generate migration script ip=%s error=%s",
                                result.ip,
                                exc,
                            )

                    results.append(result)

                    if result.ping:
                        stats["alive"] += 1

                    if result.status.startswith(AuditStatus.SSH_OK.value):
                        stats["ssh_ok"] += 1
                    elif result.status.startswith(AuditStatus.FALLBACK_OK.value):
                        stats["fallback"] += 1
                    elif result.status != AuditStatus.OFFLINE.value:
                        stats["fail"] += 1

                    pbar.set_postfix(stats)
                    pbar.update(1)

            results.sort(key=lambda x: tuple(int(p) for p in x.ip.split(".")))

            self.exporter.export(results)
            self.logger.info(
                "Run finished successfully rows=%s file=%s",
                len(results),
                self.config.output_xlsx,
            )
        finally:
            self.executor.shutdown(wait=True, cancel_futures=False)