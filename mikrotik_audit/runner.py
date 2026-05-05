from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterable
from concurrent.futures import ThreadPoolExecutor

from config import AppConfig
from constants.statuses import AuditStatus
from domain.auditor import DeviceAuditor
from domain.phpipam_registry_async import AsyncPHPIPAMRegistryService
from domain.targets import TargetProvider
from models import AuditResult
from services.routeros_script_generator import RouterOSScriptGenerator
from tqdm import tqdm

from report.pipeline import ReportPipeline


class AuditRunner:
    def __init__(
        self,
        config: AppConfig,
        logger: logging.Logger,
        target_provider: TargetProvider,
        auditor: DeviceAuditor,
        report_pipeline: ReportPipeline,
        phpipam_registry: AsyncPHPIPAMRegistryService | None = None,
        script_generator: RouterOSScriptGenerator | None = None,
    ) -> None:
        self.config = config
        self.logger = logger
        self.target_provider = target_provider
        self.auditor = auditor
        self.report_pipeline = report_pipeline
        self.phpipam_registry = phpipam_registry
        self.script_generator = script_generator

    # ---------------------------------------------------
    # PUBLIC API
    # ---------------------------------------------------

    async def run_audit_command(self) -> None:
        ips = self.target_provider.get_target_ips()

        if not ips:
            self.logger.warning("No target IPs")
            return

        self.logger.info("Streaming audit started total=%s", len(ips))

        if self.phpipam_registry:
            await self.phpipam_registry.preload()

        stream = self._audit_stream(ips)

        await self.report_pipeline.run(stream)

        self.logger.info("Streaming audit finished")

    async def run_single_audit_command(self, ip: str) -> AuditResult:
        result = await asyncio.to_thread(self.auditor.audit_device, ip)

        if self.phpipam_registry:
            self.phpipam_registry.enrich_report_only_from_cache(result)

        return result

    async def shutdown(self) -> None:
        if self.phpipam_registry:
            await self.phpipam_registry.client.close()

    # ---------------------------------------------------
    # STREAM CORE
    # ---------------------------------------------------

    async def _audit_stream(self, ips: list[str]) -> AsyncIterable[AuditResult]:
        loop = asyncio.get_running_loop()

        stats = {
            "alive": 0,
            "ssh_ok": 0,
            "fallback": 0,
            "fail": 0,
        }

        with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
            tasks = [
                loop.run_in_executor(executor, self.auditor.audit_device, ip)
                for ip in ips
            ]

            with tqdm(total=len(tasks), desc="Streaming MikroTik audit") as pbar:
                for future in asyncio.as_completed(tasks):
                    try:
                        result: AuditResult = await future
                    except Exception as exc:
                        self.logger.exception("Audit failed error=%s", exc)
                        pbar.update(1)
                        continue

                    self._update_stats(result, stats)

                    if self.phpipam_registry:
                        self.phpipam_registry.enrich_report_only_from_cache(result)

                    self._log_result(result)

                    pbar.set_postfix(stats)
                    pbar.update(1)

                    yield result

        self.logger.info(
            "Audit stats alive=%s ssh_ok=%s fallback=%s fail=%s",
            stats["alive"],
            stats["ssh_ok"],
            stats["fallback"],
            stats["fail"],
        )

    # ---------------------------------------------------
    # INTERNAL
    # ---------------------------------------------------

    def _update_stats(self, result: AuditResult, stats: dict[str, int]) -> None:
        if result.ping:
            stats["alive"] += 1

        if result.status.startswith(AuditStatus.SSH_OK.value):
            stats["ssh_ok"] += 1
        elif result.status.startswith(AuditStatus.FALLBACK_OK.value):
            stats["fallback"] += 1
        elif result.status != AuditStatus.OFFLINE.value:
            stats["fail"] += 1

    def _log_result(self, result: AuditResult) -> None:
        self.logger.debug(
            "Audit result ip=%s identity=%s status=%s ping=%s ssh=%s",
            result.ip,
            result.identity,
            result.status,
            result.ping,
            result.ssh_port,
        )