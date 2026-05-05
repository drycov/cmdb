from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from config import AppConfig
from constants.statuses import AuditStatus
from domain.auditor import DeviceAuditor
from domain.exporter import ExcelExporter
from domain.phpipam_registry_async import AsyncPHPIPAMRegistryService
from domain.targets import TargetProvider
from services.google_sheets import GoogleSheetsExporter
from models import AuditResult
from services.routeros_script_generator import RouterOSScriptGenerator
from tqdm import tqdm

Stats = dict[str, int]
FinalizeHandler = Callable[[AuditResult, Stats], AuditResult]


class AuditRunner:
    def __init__(
        self,
        config: AppConfig,
        logger: logging.Logger,
        target_provider: TargetProvider,
        auditor: DeviceAuditor,
        exporter: ExcelExporter,
        phpipam_registry: AsyncPHPIPAMRegistryService | None = None,
        script_generator: RouterOSScriptGenerator | None = None,
        google_exporter: GoogleSheetsExporter | None = None,
    ) -> None:
        self.config = config
        self.logger = logger
        self.target_provider = target_provider
        self.auditor = auditor
        self.exporter = exporter
        self.phpipam_registry = phpipam_registry
        self.script_generator = script_generator
        self.google_exporter = google_exporter

    @staticmethod
    def _new_stats() -> Stats:
        return {
            "alive": 0,
            "ssh_ok": 0,
            "fallback": 0,
            "fail": 0,
        }

    async def shutdown(self) -> None:
        if self.phpipam_registry is not None:
            await self.phpipam_registry.client.close()

    async def run_audit_command(self) -> None:
        ips = self.target_provider.get_target_ips()
        results = await self.audit_many(ips)

        if not results:
            self.logger.warning("No audit results to export")
            return

        await self._enrich_with_phpipam(results, log_results=False)
        self._export_audit_results(results)

    async def run_export_command(self) -> None:
        await self.run_audit_command()

    async def run_single_audit_command(
        self,
        ip: str,
        *,
        export: bool,
    ) -> AuditResult:
        result = await self.audit_one(ip)
        await self._enrich_with_phpipam([result], log_results=False)
        if export:
            self.exporter.export([result])
        return result

    async def audit_many(self, ips: list[str]) -> list[AuditResult]:
        return await self._audit_batch(
            ips=ips,
            description="Scanning MikroTik",
            finalize=self._finalize_audit,
        )

    async def audit_one(self, ip: str) -> AuditResult:
        self.logger.info("Single audit started ip=%s", ip)

        result = await asyncio.to_thread(self.auditor.audit_device, ip)
        stats = self._new_stats()
        result = self._finalize_audit(result, stats)

        self.logger.info(
            "Single audit finished ip=%s identity=%s status=%s ping=%s ssh=%s",
            result.ip,
            result.identity,
            result.status,
            result.ping,
            result.ssh_port,
        )

        return result

    async def export_only(self) -> None:
        await self.run_export_command()

    async def sync_phpipam(self) -> None:
        # Историческое имя команды. Фактически это read-only Excel report.
        await self.run_phpipam_report_command()

    async def run_phpipam_report_command(self) -> None:
        if self.phpipam_registry is None:
            self.logger.warning("phpIPAM integration is disabled")
            return

        ips = self.target_provider.get_target_ips()

        self.logger.info(
            "phpIPAM inventory report started total=%s",
            len(ips),
        )

        results = await self._audit_batch(
            ips=ips,
            description="Auditing MikroTik for phpIPAM report",
            finalize=self._finalize_without_external_enrichment,
        )

        if not results:
            self.logger.warning("No results for phpIPAM report")
            return

        await self._enrich_with_phpipam(results, log_results=True)
        self._export_inventory_results(results)

    async def generate_script_for_ip(self, ip: str) -> str | None:
        if self.script_generator is None:
            self.logger.warning("Script generator is not configured")
            return None

        result = await self.audit_one(ip)
        await self._enrich_with_phpipam([result], log_results=False)
        return self._generate_script(result)

    async def _enrich_with_phpipam(
        self,
        results: list[AuditResult],
        *,
        log_results: bool,
    ) -> None:
        if self.phpipam_registry is None or not results:
            return

        await self.phpipam_registry.preload()

        for result in results:
            self.phpipam_registry.enrich_report_only_from_cache(result)
            if log_results:
                self._log_inventory_result(result)

        self._log_inventory_summary(results)

    async def _audit_batch(
        self,
        *,
        ips: list[str],
        description: str,
        finalize: FinalizeHandler,
    ) -> list[AuditResult]:
        self.logger.info("%s started total=%s", description, len(ips))

        if not ips:
            return []

        if self.config.test_mode and self.config.auto_upload_mmips and len(ips) > 2:
            self.logger.error(
                "Refusing firmware upload in TEST_MODE for more than 2 devices"
            )
            return []

        loop = asyncio.get_running_loop()
        results: list[AuditResult] = []
        stats = self._new_stats()

        with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
            tasks = [
                loop.run_in_executor(executor, self.auditor.audit_device, ip)
                for ip in ips
            ]

            with tqdm(total=len(tasks), desc=description) as pbar:
                for future in asyncio.as_completed(tasks):
                    try:
                        result = await future
                    except Exception as exc:
                        self.logger.exception(
                            "%s device audit failed error=%s",
                            description,
                            exc,
                        )
                        pbar.update(1)
                        continue

                    result = finalize(result, stats)
                    results.append(result)

                    self._log_audit_result(result)

                    pbar.set_postfix(stats)
                    pbar.update(1)

        results.sort(key=self._ip_sort_key)

        self.logger.info(
            "%s finished total=%s alive=%s ssh_ok=%s fallback=%s fail=%s",
            description,
            len(results),
            stats["alive"],
            stats["ssh_ok"],
            stats["fallback"],
            stats["fail"],
        )

        return results

    def _finalize_audit(
        self,
        result: AuditResult,
        stats: Stats,
    ) -> AuditResult:
        self._update_stats(result, stats)
        return result

    def _finalize_without_external_enrichment(
        self,
        result: AuditResult,
        stats: Stats,
    ) -> AuditResult:
        self._update_stats(result, stats)
        return result

    def _generate_script(
        self,
        result: AuditResult,
    ) -> str | None:
        if self.script_generator is None:
            return None

        try:
            script_path = self.script_generator.generate_for_result(result)

            if script_path is not None:
                self.logger.info(
                    "Generated migration script ip=%s identity=%s file=%s",
                    result.ip,
                    result.identity,
                    script_path,
                )
                return str(script_path)

        except Exception as exc:
            self.logger.exception(
                "Failed to generate migration script ip=%s identity=%s error=%s",
                result.ip,
                result.identity,
                exc,
            )

        return None

    def _update_stats(
        self,
        result: AuditResult,
        stats: Stats,
    ) -> None:
        if result.ping:
            stats["alive"] += 1

        if result.status.startswith(AuditStatus.SSH_OK.value):
            stats["ssh_ok"] += 1
        elif result.status.startswith(AuditStatus.FALLBACK_OK.value):
            stats["fallback"] += 1
        elif result.status != AuditStatus.OFFLINE.value:
            stats["fail"] += 1

    def _log_audit_result(self, result: AuditResult) -> None:
        self.logger.debug(
            "Audit result ip=%s identity=%s status=%s ping=%s ssh=%s auth=%s version=%s board=%s",
            result.ip,
            result.identity,
            result.status,
            result.ping,
            result.ssh_port,
            result.auth_method,
            result.version,
            result.board_name,
        )

    def _log_inventory_result(self, result: AuditResult) -> None:
        severity = getattr(result, "inventory_severity", "")
        status = getattr(result, "inventory_status", "")
        match_type = getattr(result, "phpipam_match_type", "")

        log_message = (
            "Inventory result ip=%s identity=%s status=%s severity=%s "
            "match=%s ipam_ip=%s ipam_hostname=%s address_id=%s"
        )

        args = (
            result.ip,
            result.identity,
            status,
            severity,
            match_type,
            result.phpipam_ip,
            result.phpipam_hostname,
            result.phpipam_address_id,
        )

        if severity == "ERROR":
            self.logger.error(log_message, *args)
        elif severity == "WARNING":
            self.logger.warning(log_message, *args)
        elif self.config.log_inventory_details:
            self.logger.info(log_message, *args)
        else:
            self.logger.debug(log_message, *args)

    def _log_inventory_summary(self, results: list[AuditResult]) -> None:
        summary: dict[str, int] = {
            "OK": 0,
            "HOSTNAME_MISMATCH": 0,
            "HOSTNAME_PARTIAL_MATCH": 0,
            "HOSTNAME_INCOMPLETE": 0,
            "NOT_FOUND": 0,
            "DUPLICATE": 0,
            "UNKNOWN": 0,
        }

        severity_summary: dict[str, int] = {
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "UNKNOWN": 0,
        }

        for result in results:
            status = result.inventory_status or "UNKNOWN"
            severity = result.inventory_severity or "UNKNOWN"

            summary[status] = summary.get(status, 0) + 1
            severity_summary[severity] = severity_summary.get(severity, 0) + 1

        self.logger.info(
            "INVENTORY SUMMARY total=%s ok=%s mismatch=%s partial=%s incomplete=%s not_found=%s duplicate=%s "
            "severity_info=%s severity_warning=%s severity_error=%s",
            len(results),
            summary.get("OK", 0),
            summary.get("HOSTNAME_MISMATCH", 0),
            summary.get("HOSTNAME_PARTIAL_MATCH", 0),
            summary.get("HOSTNAME_INCOMPLETE", 0),
            summary.get("NOT_FOUND", 0),
            summary.get("DUPLICATE", 0),
            severity_summary.get("INFO", 0),
            severity_summary.get("WARNING", 0),
            severity_summary.get("ERROR", 0),
        )

    def _export_audit_results(self, results: list[AuditResult]) -> None:
        self.exporter.export(results)
        self.logger.info(
            "Audit finished rows=%s file=%s",
            len(results),
            self.config.output_xlsx,
        )

    def _export_inventory_results(self, results: list[AuditResult]) -> None:
        self.exporter.export(results)

        if self.google_exporter is not None:
            self.google_exporter.export([result.to_row() for result in results])

        self.logger.info(
            "phpIPAM inventory report finished rows=%s file=%s",
            len(results),
            self.config.output_xlsx,
        )

    @staticmethod
    def _ip_sort_key(result: AuditResult) -> tuple[int, int, int, int]:
        try:
            return tuple(int(part) for part in result.ip.split("."))
        except Exception:
            return (999, 999, 999, 999)
