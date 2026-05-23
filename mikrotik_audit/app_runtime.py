"""Core runtime orchestration for audits, exports, remediation, and service mode.

This module glues together the lower-level services into one application-facing
runtime. The goal is to keep command handlers thin and give the team one place
that explains how target resolution, device auditing, report generation, and
long-running service loops fit together.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import time
from collections import Counter
from collections.abc import AsyncIterable, Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

from mikrotik_audit.config import AppConfig, load_yaml_file, normalize_inventory_data

if TYPE_CHECKING:
    from mikrotik_audit.app.topology.analyzer import TopologyAnalyzer
    from mikrotik_audit.app.topology.models import TopologyAnalysisResult
from mikrotik_audit.constants.auth_methods import AuthMethod
from mikrotik_audit.constants.statuses import AuditStatus
from mikrotik_audit.domain.phpipam_registry_async import AsyncPHPIPAMRegistryService
from mikrotik_audit.domain.status_builder import StatusBuilder
from mikrotik_audit.logging_setup import setup_logging
from mikrotik_audit.models import AuditResult, Credentials
from mikrotik_audit.report.writers.base import ReportWriter
from mikrotik_audit.report.writers.excel import ExcelWriter
from mikrotik_audit.report.writers.gsheet import GSheetWriter
from mikrotik_audit.report.writers.json import JsonWriter
from mikrotik_audit.services.collector import MikroTikCollector
from mikrotik_audit.services.compliance import DevicePolicyInspector
from mikrotik_audit.services.config_backup import ConfigBackupResult, ConfigBackupService
from mikrotik_audit.services.export.common import (
    INVENTORY_HEADERS,
    ISSUE_HEADERS,
    PHPIPAM_MISMATCH_HEADERS,
    TOPOLOGY_HEADERS,
    VLAN_HEADERS,
)
from mikrotik_audit.services.firmware import FirmwareManager
from mikrotik_audit.services.phpipam_async import AsyncPHPIPAMClient
from mikrotik_audit.services.radius import RadiusRemediator
from mikrotik_audit.services.routeros_script_generator import RouterOSScriptGenerator
from mikrotik_audit.services.scheduler import SchedulerPolicyInspector
from mikrotik_audit.services.ssh import SSHService, SSHSession
from mikrotik_audit.services.targeted_remediation import (
    TargetedRemediationResult,
    TargetedRemediator,
)
from tqdm import tqdm
from mikrotik_audit.utils import network_of_ip

REPORT_SECTIONS: dict[str, list[str]] = {
    "mikrotik_inventory": INVENTORY_HEADERS,
    "topology": TOPOLOGY_HEADERS,
    "phpipam_mismatches": PHPIPAM_MISMATCH_HEADERS,
    "issues": ISSUE_HEADERS,
    "vlans": VLAN_HEADERS,
    "raw_inventory": AuditResult.EXPORT_HEADERS,
}
REPORT_SECTION_ORDER = tuple(REPORT_SECTIONS)


class TargetProvider:
    """Resolve target IPs from the normalized inventory model.

    The provider hides inventory schema details from callers and returns a
    de-duplicated host list in inventory order. Preserving that order keeps CLI
    previews, progress output, and exported reports stable between runs.
    """
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def get_target_ips(self) -> list[str]:
        inventory_path = Path(self.config.inventory_file)
        if not inventory_path.exists():
            raise FileNotFoundError(f"Inventory file not found: {inventory_path}")

        data = self._load_yaml(inventory_path)
        target_networks = data.get("target_networks")
        if isinstance(target_networks, list) and target_networks:
            network_items = target_networks
        else:
            vlans = data.get("vlans", [])
            if not isinstance(vlans, list):
                raise ValueError("Inventory format error: 'vlans' must be a list")
            network_items = []
            for vlan in vlans:
                if not isinstance(vlan, dict):
                    continue
                networks = vlan.get("networks", [])
                if not isinstance(networks, list):
                    continue
                network_items.extend(
                    network_item
                    for network_item in networks
                    if isinstance(network_item, dict)
                )

        # Keep host order as defined by the inventory so operators see the same
        # traversal order in previews, progress bars, and exported artifacts.
        ordered_ips: list[str] = []
        seen_ips: set[str] = set()
        for network_item in network_items:
            if not isinstance(network_item, dict):
                continue

            subnet_raw = network_item.get("subnet")
            gateway_raw = network_item.get("gateway")
            if not subnet_raw:
                continue

            subnet = ipaddress.ip_network(subnet_raw, strict=False)
            gateway_ip = ipaddress.ip_address(gateway_raw) if gateway_raw else None

            for host in subnet.hosts():
                if self.config.exclude_gateways and gateway_ip and host == gateway_ip:
                    continue
                host_str = str(host)
                if host_str in seen_ips:
                    continue
                seen_ips.add(host_str)
                ordered_ips.append(host_str)

        return ordered_ips

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        data = normalize_inventory_data(load_yaml_file(path))
        if not isinstance(data, dict):
            raise ValueError("Inventory root must be a mapping/dict")
        return data

    @staticmethod
    def _ip_sort_key(ip: str) -> tuple[int, int, int, int]:
        return tuple(int(part) for part in ip.split("."))


class DeviceAuditor:
    """Represent deviceauditor."""
    StatusBuilderFn = Callable[[AuditResult], str]

    def __init__(
        self,
        config: AppConfig,
        ssh: SSHService,
        collector: MikroTikCollector,
        compliance_inspector: DevicePolicyInspector,
        firmware_manager: FirmwareManager,
        radius_remediator: RadiusRemediator,
        logger: logging.Logger,
        auth_credentials: list[Credentials],
        scheduler_inspector: SchedulerPolicyInspector | None = None,
    ) -> None:
        self.config = config
        self.ssh = ssh
        self.collector = collector
        self.compliance_inspector = compliance_inspector
        self.firmware_manager = firmware_manager
        self.radius_remediator = radius_remediator
        self.logger = logger
        self.auth_credentials = [cred for cred in auth_credentials if cred.username and cred.password]
        self.primary_credentials = self.auth_credentials[0] if self.auth_credentials else Credentials("", "")
        self.fallback_credentials = (
            self.auth_credentials[1] if len(self.auth_credentials) > 1 else Credentials("", "")
        )
        self.scheduler_inspector = scheduler_inspector

    def audit_device(self, ip: str) -> AuditResult:
        self.logger.info("Audit started ip=%s", ip)
        result = AuditResult(ip=ip, subnet=network_of_ip(ip))

        if not self.ssh.ping_host(ip):
            result.status = AuditStatus.OFFLINE.value
            return self._finish(result)

        result.ping = True
        if not self.ssh.check_ssh_port(ip):
            result.status = AuditStatus.SSH_CLOSED.value
            return self._finish(result)

        result.ssh_port = True

        for index, credentials in enumerate(self.auth_credentials):
            auth_method = AuthMethod.PRIMARY if index == 0 else AuthMethod.FALLBACK
            status_builder = StatusBuilder.build_primary if index == 0 else StatusBuilder.build_fallback
            auth_result = self._process_session(
                ip=ip,
                result=result,
                credentials=credentials,
                auth_method=auth_method,
                status_builder=status_builder,
                include_radius=index > 0,
            )
            if auth_result is not None:
                return self._finish(auth_result)

        result.status = AuditStatus.AUTH_FAILED.value
        return self._finish(result)

    def _process_session(
        self,
        *,
        ip: str,
        result: AuditResult,
        credentials: Credentials,
        auth_method: AuthMethod,
        status_builder: StatusBuilderFn,
        include_radius: bool,
    ) -> AuditResult | None:
        session_ctx = self.ssh.open_session(ip, credentials)
        if session_ctx is None:
            return None

        with session_ctx as session:
            collected = self.collector.collect_router_data(session)
            if collected is None:
                return None

            result.apply_device_info(collected)
            result.set_auth_method(auth_method)
            self._inspect_firmware(result)

            if include_radius:
                self._inspect_radius(session, result)

            self._inspect_ntp(result)
            self._inspect_watchdog(result)
            self._inspect_scheduler(session=session, result=result)
            result.status = status_builder(result)
            return result

    def _inspect_radius(self, session: Any, result: AuditResult) -> None:
        if not self.config.compliance.radius:
            return
        result.apply_radius(self.radius_remediator.inspect_radius(session))

    def _inspect_firmware(self, result: AuditResult) -> None:
        if not self.config.auto_upload_mmips:
            return
        result.apply_firmware(
            self.firmware_manager.inspect_status(
                architecture=result.architecture,
                current_version=result.version,
            )
        )

    def _inspect_ntp(self, result: AuditResult) -> None:
        if not self.config.compliance.ntp:
            return
        result.apply_ntp_policy(
            self.compliance_inspector.inspect_ntp(
                info=result.to_device_info(),
                config=self.config.ntp,
            )
        )

    def _inspect_watchdog(self, result: AuditResult) -> None:
        if not self.config.compliance.watchdog:
            return
        result.apply_watchdog_policy(
            self.compliance_inspector.inspect_watchdog(
                info=result.to_device_info(),
                config=self.config.watchdog,
            )
        )

    def _inspect_scheduler(self, *, session: Any, result: AuditResult) -> None:
        if not self.config.compliance.scheduler:
            return
        if self.scheduler_inspector is None:
            return

        scheduler_cfg = getattr(self.config, "scheduler", None)
        if scheduler_cfg is None or not getattr(scheduler_cfg, "enabled", False):
            return

        expected = getattr(scheduler_cfg, "expected", [])
        if not expected:
            return

        try:
            checks = self.scheduler_inspector.inspect_expected(
                session=session,
                expected_rules=expected,
                identity=result.identity,
            )
            result.apply_scheduler_policy(checks)
        except Exception as exc:
            self.logger.error("Scheduler inspection failed ip=%s err=%s", result.ip, exc)
            result.scheduler_policy_status = "ERROR"
            result.scheduler_policy_details = str(exc)

    def _finish(self, result: AuditResult) -> AuditResult:
        self.logger.info(
            "Audit finished ip=%s status=%s auth=%s identity=%s version=%s",
            result.ip,
            result.status,
            result.auth_method,
            result.identity,
            result.version,
        )
        return result


def inventory_row(result: AuditResult) -> dict[str, Any]:
    """Project one audit result into the curated inventory export schema."""
    return {header: getattr(result, header, "") for header in INVENTORY_HEADERS}


def raw_row(result: AuditResult) -> dict[str, Any]:
    """Project one audit result into the full raw export schema."""
    return {header: getattr(result, header, "") for header in AuditResult.EXPORT_HEADERS}


def topology_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    """Return topology export rows when the result contains neighbor evidence."""
    if not any(
        [
            result.uplink_interface,
            result.uplink_mac,
            result.neighbor_identity,
            result.neighbor_address,
            result.neighbor_interface,
            result.neighbor_mac,
        ]
    ):
        return []
    return [{header: getattr(result, header, "") for header in TOPOLOGY_HEADERS}]


def mismatch_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    """Return phpIPAM mismatch rows only for non-OK inventory states."""
    if (result.inventory_status or "OK") == "OK":
        return []
    return [{header: getattr(result, header, "") for header in PHPIPAM_MISMATCH_HEADERS}]


def issue_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    """Return issue rows when audit or compliance checks found actionable problems."""
    has_audit_issue = not (
        result.status.startswith("SSH_OK") or result.status.startswith("FALLBACK_OK")
    )
    has_inventory_issue = (result.inventory_severity or "").upper() in {"WARNING", "ERROR"}
    has_firmware_issue = bool(result.firmware_error)
    has_scheduler_issue = (result.scheduler_policy_status or "") not in {"", "OK"}
    has_ntp_issue = (result.ntp_policy_status or "") not in {"", "OK"}
    has_watchdog_issue = (result.watchdog_policy_status or "") not in {"", "OK"}

    if not any(
        [
            has_audit_issue,
            has_inventory_issue,
            has_firmware_issue,
            has_scheduler_issue,
            has_ntp_issue,
            has_watchdog_issue,
        ]
    ):
        return []

    return [{header: getattr(result, header, "") for header in ISSUE_HEADERS}]


def vlan_rows(result: AuditResult) -> Iterable[dict[str, Any]]:
    """Flatten the collected VLAN table into report-friendly export rows."""
    rows: list[dict[str, Any]] = []
    for vlan in result.vlan_table or []:
        rows.append(
            {
                "device_identity": result.identity,
                "device_ip": result.ip,
                "vlan_id": vlan.get("vlan_id", ""),
                "vlan_hex": vlan.get("vlan_hex", ""),
                "bridge": vlan.get("bridge", ""),
                "tagged_ports": ", ".join(vlan.get("tagged_ports", [])),
                "untagged_ports": ", ".join(vlan.get("untagged_ports", [])),
                "pvid_ports": ", ".join(vlan.get("pvid_ports", [])),
                "interfaces": ", ".join(
                    f"{item.get('name', '')}@{item.get('interface', '')}"
                    for item in vlan.get("vlan_interfaces", [])
                ),
            }
        )
    return rows


@dataclass(slots=True)
class SummaryAccumulator:
    """Collect report-wide counters while audit results stream in.

    The report pipeline writes rows incrementally, so summary metrics are
    accumulated alongside the stream instead of rebuilding the whole dataset at
    the end.
    """
    total: int = 0
    flags: Counter[str] = field(default_factory=Counter)
    statuses: Counter[str] = field(default_factory=Counter)
    inventory_statuses: Counter[str] = field(default_factory=Counter)
    inventory_severities: Counter[str] = field(default_factory=Counter)
    matches: Counter[str] = field(default_factory=Counter)
    firmware_errors: Counter[str] = field(default_factory=Counter)

    def add(self, result: AuditResult) -> None:
        """Fold one audit result into the running report summary."""
        self.total += 1

        if result.ping:
            self.flags["alive"] += 1

        if result.status.startswith(AuditStatus.SSH_OK.value):
            self.statuses["ssh_ok"] += 1
        elif result.status.startswith(AuditStatus.FALLBACK_OK.value):
            self.statuses["fallback_ok"] += 1
        elif result.status:
            self.statuses[result.status.lower()] += 1

        if result.inventory_status:
            self.inventory_statuses[result.inventory_status] += 1
        if result.inventory_severity:
            self.inventory_severities[result.inventory_severity] += 1
        if result.phpipam_match_type:
            self.matches[result.phpipam_match_type] += 1
        if result.firmware_error:
            self.firmware_errors[result.firmware_error] += 1

    def rows(self) -> list[dict[str, object]]:
        """Return export-ready summary rows for the final report section."""
        alive = self.flags["alive"]
        inventory_ok = self.inventory_statuses["OK"]
        return [
            {"metric": "total_hosts", "value": self.total},
            {"metric": "alive", "value": alive},
            {"metric": "alive_percent", "value": round(alive / self.total * 100, 2) if self.total else 0},
            {"metric": "ssh_ok", "value": self.statuses["ssh_ok"]},
            {"metric": "fallback_ok", "value": self.statuses["fallback_ok"]},
            {"metric": "inventory_ok", "value": inventory_ok},
            {
                "metric": "inventory_compliance_percent",
                "value": round(inventory_ok / self.total * 100, 2) if self.total else 0,
            },
            {"metric": "severity_info", "value": self.inventory_severities["INFO"]},
            {"metric": "severity_warning", "value": self.inventory_severities["WARNING"]},
            {"metric": "severity_error", "value": self.inventory_severities["ERROR"]},
            {"metric": "match_ip", "value": self.matches["ip"]},
            {"metric": "match_hostname", "value": self.matches["hostname"]},
            {"metric": "match_not_found", "value": self.matches["not_found"]},
        ]


class ReportPipeline:
    """Write audit results to one or more report writers in a single pass.

    Writers for Excel, NDJSON, and Google Sheets all receive the same section
    lifecycle events so export formats stay aligned without duplicating report
    assembly logic in each command.
    """
    def __init__(self, writers: list[ReportWriter]) -> None:
        self.writers = writers
        self.summary = SummaryAccumulator()

    async def run(self, results: AsyncIterable[AuditResult]) -> None:
        """Stream audit results into the standard multi-section report."""
        try:
            self._open()
            self._begin_sections()
            async for result in results:
                self.summary.add(result)
                self._write("mikrotik_inventory", inventory_row(result))
                self._write("raw_inventory", raw_row(result))
                for row in topology_rows(result):
                    self._write("topology", row)
                for row in mismatch_rows(result):
                    self._write("phpipam_mismatches", row)
                for row in issue_rows(result):
                    self._write("issues", row)
                for row in vlan_rows(result):
                    self._write("vlans", row)

            self._begin_summary()
            for row in self.summary.rows():
                self._write("summary", row)
        finally:
            self._close_sections()
            self._close()

    def _open(self) -> None:
        for writer in self.writers:
            writer.open()

    def _begin_sections(self) -> None:
        for name, headers in REPORT_SECTIONS.items():
            for writer in self.writers:
                writer.begin_section(name, headers)

    def _begin_summary(self) -> None:
        for writer in self.writers:
            writer.begin_section("summary", ["metric", "value"])

    def _write(self, section: str, row: dict[str, Any]) -> None:
        for writer in self.writers:
            writer.write_row(section, row)

    def _close_sections(self) -> None:
        for name in [*REPORT_SECTION_ORDER, "summary"]:
            for writer in self.writers:
                try:
                    writer.close_section(name)
                except Exception:
                    pass

    def _close(self) -> None:
        for writer in self.writers:
            writer.close()

    def write_sections(self, sections: dict[str, tuple[list[str], list[dict[str, Any]]]]) -> None:
        """Write ad-hoc export sections used by remediation-style commands."""
        try:
            self._open()
            for section_name, (headers, _) in sections.items():
                for writer in self.writers:
                    writer.begin_section(section_name, headers)

            for section_name, (_, rows) in sections.items():
                for row in rows:
                    self._write(section_name, row)
        finally:
            for section_name in sections:
                for writer in self.writers:
                    try:
                        writer.close_section(section_name)
                    except Exception:
                        pass
            self._close()


@dataclass(slots=True)
class RuntimeDependencies:
    """Bundle service objects used to construct the application runtime."""
    ssh: SSHService
    collector: MikroTikCollector
    compliance_inspector: DevicePolicyInspector
    firmware_manager: FirmwareManager
    radius_remediator: RadiusRemediator
    scheduler_inspector: SchedulerPolicyInspector
    targeted_remediator: TargetedRemediator | None = None
    config_backup: ConfigBackupService | None = None


class AuditApplication:
    """High-level application facade used by CLI and API entry points.

    The class exposes task-oriented methods such as audit, export, remediation,
    topology collection, and service loops. It intentionally hides the wiring
    between collectors, report writers, phpIPAM integration, and SSH-based
    remediators so higher layers can stay focused on user interaction.
    """
    def __init__(
        self,
        *,
        config: AppConfig,
        logger: logging.Logger,
        target_provider: TargetProvider,
        auditor: DeviceAuditor,
        report_pipeline: ReportPipeline,
        firmware_manager: FirmwareManager,
        phpipam_registry: AsyncPHPIPAMRegistryService | None = None,
        targeted_remediator: TargetedRemediator | None = None,
        config_backup: ConfigBackupService | None = None,
    ) -> None:
        self.config = config
        self.logger = logger
        self.target_provider = target_provider
        self.auditor = auditor
        self.report_pipeline = report_pipeline
        self.firmware_manager = firmware_manager
        self.phpipam_registry = phpipam_registry
        self.targeted_remediator = targeted_remediator
        self.config_backup = config_backup
        self._scanned_results_by_ip: dict[str, AuditResult] = {}
        self._last_generate_script_failures: list[str] = []

    def _resolve_target_ips(
        self,
        ips: list[str] | None = None,
        *,
        ip: str | None = None,
    ) -> list[str]:
        target_ips = [ip] if ip else list(ips or self.get_target_ips())
        if self.config.max_targets > 0 and ip is None and ips is None:
            target_ips = target_ips[: self.config.max_targets]
        return target_ips

    @staticmethod
    def _progress(total: int, description: str, show_progress: bool):
        if show_progress:
            return tqdm(total=total, desc=description)
        return contextlib.nullcontext()

    async def run_audit_command(self, *, show_progress: bool = True) -> None:
        """Run the standard full-inventory audit and stream results to exports."""
        ips = self._resolve_target_ips()
        if not ips:
            self.logger.warning("No target IPs")
            return

        self.logger.info("Streaming audit started total=%s", len(ips))
        await self._ensure_phpipam_cache_ready()
        await self.report_pipeline.run(self._audit_stream(ips, show_progress=show_progress))
        self.logger.info("Streaming audit finished")

    async def run_export_command(self, *, show_progress: bool = True) -> None:
        """Run the current export workflow.

        Today this is intentionally equivalent to a full audit followed by
        writing configured outputs, not replaying a cached dataset.
        """
        await self.run_audit_command(show_progress=show_progress)

    async def run_phpipam_report_command(self, *, show_progress: bool = True) -> None:
        """Run the audit path used to build a phpIPAM comparison report."""
        await self.run_audit_command(show_progress=show_progress)

    async def run_single_audit_command(
        self,
        ip: str,
        *,
        export: bool = True,
    ) -> AuditResult:
        """Audit one device and optionally export it through the shared pipeline."""
        result = await asyncio.to_thread(self.auditor.audit_device, ip)
        if self.phpipam_registry and self.config.compliance.phpipam:
            await self._ensure_phpipam_cache_ready()
            self.phpipam_registry.enrich_report_only_from_cache(result)
        if export:
            await self.report_pipeline.run(self._single_result_stream(result))
        self._remember_result(result)
        return result

    def get_target_ips(self) -> list[str]:
        return self.target_provider.get_target_ips()

    async def generate_script_for_ip(self, ip: str) -> str | None:
        if self.targeted_remediator is None or not self.config.remediation.allow_generate_script:
            return None
        result = await asyncio.to_thread(
            self.targeted_remediator.remediate_ip,
            ip=ip,
            domains=None,
            apply=False,
        )
        return result.script_path or None

    async def generate_scripts_for_targets(
        self,
        ips: list[str] | None = None,
        *,
        show_progress: bool = False,
    ) -> list[str]:
        """Generate remediation scripts for a target list and remember skipped hosts."""
        if self.targeted_remediator is None:
            return []

        target_ips = self._resolve_target_ips(ips)

        self._last_generate_script_failures = []
        generated: list[str] = []
        progress = self._progress(len(target_ips), "Generating remediation scripts", show_progress)
        with progress as pbar:
            for ip in target_ips:
                try:
                    script_path = await self.generate_script_for_ip(ip)
                except Exception as exc:
                    self.logger.warning("Generate script skipped ip=%s error=%s", ip, exc)
                    self._last_generate_script_failures.append(f"{ip}: {exc}")
                    if show_progress and pbar is not None:
                        pbar.update(1)
                    continue
                if script_path:
                    generated.append(script_path)
                if show_progress and pbar is not None:
                    pbar.update(1)
        return generated

    def get_last_generate_script_failures(self) -> list[str]:
        return list(self._last_generate_script_failures)

    async def remediate_device(
        self,
        *,
        ip: str,
        domains: list[str] | None = None,
        apply: bool = False,
    ) -> TargetedRemediationResult:
        """Plan or apply targeted remediation for one device.

        The returned object is shared by CLI renderers and export builders so
        remediation flows do not need separate formatting logic per surface.
        """
        if self.targeted_remediator is None:
            raise RuntimeError("Targeted remediator is not configured")
        return await asyncio.to_thread(
            self.targeted_remediator.remediate_ip,
            ip=ip,
            domains=domains,
            apply=apply,
        )

    async def backup_config_for_ip(self, ip: str) -> ConfigBackupResult:
        if self.config_backup is None:
            raise RuntimeError("Config backup service is not configured")
        return await asyncio.to_thread(self.config_backup.backup_ip, ip)

    async def backup_configs_for_targets(
        self,
        ips: list[str] | None = None,
        *,
        show_progress: bool = True,
    ) -> list[str]:
        """Back up configs for a target set and return the written file paths."""
        if self.config_backup is None:
            return []

        target_ips = self._resolve_target_ips(ips)

        written: list[str] = []
        progress = self._progress(len(target_ips), "Backing up configs", show_progress)
        with progress as pbar:
            for ip in target_ips:
                try:
                    result = await self.backup_config_for_ip(ip)
                    written.append(result.path)
                except Exception as exc:
                    self.logger.warning(
                        "Config backup failed ip=%s error=%s",
                        ip,
                        exc,
                    )
                finally:
                    if show_progress and pbar is not None:
                        pbar.update(1)

        if self.config_backup is not None:
            try:
                await asyncio.to_thread(self.config_backup.finalize_batch_commit, written)
            except Exception as exc:
                self.logger.warning("Config backup batch commit failed error=%s", exc)
        return written

    async def upload_firmware_for_ip(self, ip: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._upload_firmware_for_ip, ip)

    async def upload_firmware_for_targets(
        self,
        ips: list[str] | None = None,
        *,
        show_progress: bool = True,
    ) -> list[dict[str, Any]]:
        target_ips = self._resolve_target_ips(ips)

        results: list[dict[str, Any]] = []
        progress = self._progress(len(target_ips), "Uploading firmware", show_progress)
        with progress as pbar:
            for ip in target_ips:
                results.append(await self.upload_firmware_for_ip(ip))
                if show_progress and pbar is not None:
                    pbar.update(1)
        return results

    async def export_custom_report(
        self,
        sections: dict[str, tuple[list[str], list[dict[str, Any]]]],
        *,
        output_xlsx: str | None = None,
        output_json: str | None = None,
    ) -> None:
        """Write ad-hoc report sections through the same writer stack as audits."""
        writers = _build_custom_report_writers(
            self.config,
            self.logger,
            output_xlsx=output_xlsx,
            output_json=output_json,
        )
        if not writers:
            self.logger.warning("No report writers configured; custom export skipped")
            return

        pipeline = ReportPipeline(writers)
        pipeline.write_sections(sections)

    async def run_topology_command(
        self,
        *,
        ip: str | None = None,
        export: bool = True,
        show_progress: bool = True,
    ) -> list["TopologyAnalysisResult"]:
        """Collect live topology data and optionally export the resulting sections."""
        from app.topology.analyzer import TopologyAnalyzer
        from app.topology.report import build_sections_from_topology

        ips = self._resolve_target_ips(ip=ip)

        if not ips:
            self.logger.warning("No topology scan targets")
            return []

        analyzer = TopologyAnalyzer(self.auditor.collector)
        results: list["TopologyAnalysisResult"] = []

        progress = self._progress(len(ips), "Collecting topology", show_progress)
        with progress as pbar:
            for target_ip in ips:
                result = await asyncio.to_thread(self._collect_topology_result, target_ip, analyzer)
                results.append(result)
                if show_progress and pbar is not None:
                    pbar.update(1)

        links = analyzer.infer_links(results)
        for result in results:
            result.edges = [link for link in links if link.source_ip == result.device.ip or link.target_ip == result.device.ip]

        if export:
            sections = build_sections_from_topology(results, links)
            await self.export_custom_report(sections)

        return results

    def _collect_topology_result(
        self,
        ip: str,
        analyzer: "TopologyAnalyzer",
    ) -> "TopologyAnalysisResult":
        if not self.auditor.ssh.ping_host(ip):
            return analyzer.build_offline_result(ip=ip, status="offline", error="ping_failed")

        if not self.auditor.ssh.check_ssh_port(ip):
            return analyzer.build_offline_result(ip=ip, status="ssh_closed", error="ssh_port_closed")

        session_data = self._open_session_for_ip(ip)
        if session_data is None:
            return analyzer.build_offline_result(ip=ip, status="auth_failed", error="ssh_auth_failed")

        session, auth_method = session_data
        status = "ssh_ok" if auth_method == "primary" else "fallback_ok"
        with session:
            return analyzer.analyze_session(session=session, ip=ip, status=status)

    async def fix_radius_for_ip(self, ip: str, apply: bool = False) -> dict[str, Any]:
        session_data = self._open_session_for_ip(ip)
        if session_data is None:
            raise RuntimeError(f"Could not open SSH session to {ip}")

        session, auth_method = session_data
        payload: dict[str, Any] = {
            "ip": ip,
            "identity": "",
            "auth_method": auth_method,
            "dry_run": not apply,
            "radius_fix_needed": False,
            "radius_present_before": False,
            "aaa_enabled_before": False,
            "radius_present_after": False,
            "aaa_present_after": False,
            "radius_added": False,
            "radius_recreated": False,
            "aaa_enabled": False,
        }

        with session:
            device_info = self.auditor.collector.collect_router_data(session)
            if device_info is not None:
                payload["identity"] = device_info.identity

            current = self.auditor.radius_remediator.inspect_radius(session)
            payload["radius_present_before"] = current.radius_present_after
            payload["aaa_enabled_before"] = current.aaa_present_after
            payload["radius_fix_needed"] = not (
                current.radius_present_after and current.aaa_present_after
            )

            if apply:
                fixed = self.auditor.radius_remediator.ensure_radius(session)
                payload["radius_present_after"] = fixed.radius_present_after
                payload["aaa_present_after"] = fixed.aaa_present_after
                payload["radius_added"] = fixed.radius_added
                payload["radius_recreated"] = fixed.radius_recreated
                payload["aaa_enabled"] = fixed.aaa_enabled
            else:
                payload["radius_present_after"] = current.radius_present_after
                payload["aaa_present_after"] = current.aaa_present_after

        return payload

    async def create_ospf_script_for_ip(self, ip: str) -> str | None:
        session_data = self._open_session_for_ip(ip)
        if session_data is None:
            raise RuntimeError(f"Could not open SSH session to {ip}")

        session, _ = session_data
        with session:
            device_info = self.auditor.collector.collect_router_data(session)
            if device_info is None:
                raise RuntimeError(f"Could not collect device data from {ip}")

            result = AuditResult(ip=ip, subnet=network_of_ip(ip))
            result.apply_device_info(device_info)

        generator = self._build_routeros_script_generator()
        return generator.generate_for_result(
            result=result,
            scanned_results=list(self._scanned_results_by_ip.values()),
        )

    async def create_ospf_scripts_for_targets(
        self,
        ips: list[str] | None = None,
        *,
        show_progress: bool = True,
    ) -> list[str]:
        target_ips = list(ips or self.get_target_ips())
        if self.config.max_targets > 0 and ips is None:
            target_ips = target_ips[: self.config.max_targets]

        generated: list[str] = []
        progress = (
            tqdm(total=len(target_ips), desc="Generating OSPF scripts")
            if show_progress
            else contextlib.nullcontext()
        )
        with progress as pbar:
            for ip in target_ips:
                try:
                    script_path = await self.create_ospf_script_for_ip(ip)
                except Exception as exc:
                    self.logger.warning("OSPF script generation skipped ip=%s error=%s", ip, exc)
                    if show_progress and pbar is not None:
                        pbar.update(1)
                    continue
                if script_path:
                    generated.append(script_path)
                if show_progress and pbar is not None:
                    pbar.update(1)
        return generated

    def _build_routeros_script_generator(self) -> RouterOSScriptGenerator:
        gateway_credentials = Credentials(
            self.config.username,
            self.config.password,
        )
        return RouterOSScriptGenerator(
            config=self.config,
            ssh=self.auditor.ssh,
            collector=self.auditor.collector,
            logger=self.logger,
            gateway_credentials=gateway_credentials,
        )

    def _open_session_for_ip(self, ip: str) -> tuple[SSHSession, str] | None:
        for index, cred in enumerate(self.config.mikrotik_credentials):
            if not cred.is_valid:
                continue
            session = self.auditor.ssh.open_session(
                ip,
                Credentials(cred.username, cred.password),
            )
            if session is None:
                continue
            auth_method = cred.name or ("primary" if index == 0 else f"fallback_{index}")
            return session, auth_method
        return None

    def _build_firmware_credentials(self) -> Credentials:
        firmware_cfg = getattr(self.config, "firmware", None)
        if firmware_cfg is not None and firmware_cfg.credentials.is_valid:
            return Credentials(
                firmware_cfg.credentials.username,
                firmware_cfg.credentials.password,
            )
        return Credentials(self.config.username, self.config.password)

    def _upload_firmware_for_ip(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ip": ip,
            "identity": "",
            "architecture": "",
            "current_version": "",
            "firmware_candidate": "",
            "firmware_target_version": "",
            "firmware_upload_needed": False,
            "firmware_uploaded": False,
            "firmware_already_present": False,
            "firmware_reboot_sent": False,
            "firmware_error": "",
        }

        credentials = self._build_firmware_credentials()
        if not credentials.username or not credentials.password:
            result["firmware_error"] = "firmware_credentials_missing"
            return result

        session = self.auditor.ssh.open_session(ip, credentials)
        if session is None:
            result["firmware_error"] = "ssh_connection_failed"
            return result

        with session:
            device_info = self.auditor.collector.collect_router_data(session)
            if device_info is None:
                result["firmware_error"] = "device_data_collection_failed"
                return result

            result["identity"] = device_info.identity
            result["architecture"] = device_info.architecture
            result["current_version"] = device_info.version

            firmware_result = self.firmware_manager.ensure_uploaded(
                session=session,
                architecture=device_info.architecture,
                current_version=device_info.version,
            )

            result["firmware_candidate"] = firmware_result.firmware_candidate
            result["firmware_target_version"] = firmware_result.firmware_target_version
            result["firmware_upload_needed"] = firmware_result.firmware_upload_needed
            result["firmware_uploaded"] = firmware_result.firmware_uploaded
            result["firmware_already_present"] = firmware_result.firmware_already_present
            result["firmware_reboot_sent"] = firmware_result.firmware_reboot_sent
            result["firmware_error"] = firmware_result.firmware_error

        return result

    async def run_service_action(
        self,
        *,
        action: str,
        show_progress: bool = False,
    ) -> list[str]:
        """Dispatch one service cycle to an existing application workflow."""
        normalized_action = (action or "").strip().lower()

        if normalized_action == "audit":
            await self.run_audit_command(show_progress=show_progress)
            return []
        if normalized_action == "export":
            await self.run_export_command(show_progress=show_progress)
            return []
        if normalized_action == "phpipam-report":
            await self.run_phpipam_report_command(show_progress=show_progress)
            return []
        if normalized_action == "topology":
            await self.run_topology_command(show_progress=show_progress)
            return []
        if normalized_action == "generate-script":
            return await self.generate_scripts_for_targets()
        if normalized_action == "backup-configs":
            return await self.backup_configs_for_targets()

        raise ValueError(f"Unsupported service action: {action}")

    async def run_service_loop(
        self,
        *,
        action: str,
        interval_seconds: int,
        once: bool = False,
        show_progress: bool = False,
    ) -> None:
        """Repeat a service action until stopped or until one cycle completes."""
        cycle = 0

        while True:
            cycle += 1
            started_at = time.monotonic()
            self.logger.info(
                "Service cycle started cycle=%s action=%s interval_seconds=%s",
                cycle,
                action,
                interval_seconds,
            )

            generated = await self.run_service_action(
                action=action,
                show_progress=show_progress,
            )
            if generated:
                self.logger.info(
                    "Service cycle generated scripts cycle=%s count=%s",
                    cycle,
                    len(generated),
                )

            elapsed = round(time.monotonic() - started_at, 2)
            self.logger.info(
                "Service cycle finished cycle=%s action=%s elapsed_seconds=%s",
                cycle,
                action,
                elapsed,
            )

            if once:
                return

            self.logger.info(
                "Service sleeping cycle=%s sleep_seconds=%s",
                cycle,
                interval_seconds,
            )
            await asyncio.sleep(interval_seconds)

    async def shutdown(self) -> None:
        if self.phpipam_registry:
            await self.phpipam_registry.client.close()

    async def _audit_stream(
        self,
        ips: list[str],
        *,
        show_progress: bool = True,
    ) -> AsyncIterable[AuditResult]:
        loop = asyncio.get_running_loop()
        stats = {"alive": 0, "ssh_ok": 0, "fallback": 0, "fail": 0}

        with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
            tasks = [loop.run_in_executor(executor, self.auditor.audit_device, ip) for ip in ips]
            progress = (
                tqdm(total=len(tasks), desc="Streaming MikroTik audit")
                if show_progress
                else contextlib.nullcontext()
            )
            with progress as pbar:
                for future in asyncio.as_completed(tasks):
                    try:
                        result: AuditResult = await future
                    except Exception as exc:
                        self.logger.exception("Audit failed error=%s", exc)
                        if show_progress and pbar is not None:
                            pbar.update(1)
                        continue

                    self._update_stats(result, stats)
                    if self.phpipam_registry and self.config.compliance.phpipam:
                        self.phpipam_registry.enrich_report_only_from_cache(result)

                    self._log_result(result)
                    self._remember_result(result)
                    if show_progress and pbar is not None:
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

    async def _single_result_stream(self, result: AuditResult) -> AsyncIterable[AuditResult]:
        yield result

    async def _ensure_phpipam_cache_ready(self) -> None:
        if self.phpipam_registry and self.config.preload_phpipam_cache and self.config.compliance.phpipam:
            await self.phpipam_registry.preload()

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

    def _remember_result(self, result: AuditResult) -> None:
        if result.ip:
            self._scanned_results_by_ip[result.ip] = result


def _build_auth_credentials(config: AppConfig) -> list[Credentials]:
    """Build the ordered authentication chain used for audit attempts."""
    return [
        Credentials(cred.username, cred.password)
        for cred in config.mikrotik_credentials
        if cred.is_valid
    ]


def _build_dependencies(config: AppConfig, logger: logging.Logger) -> RuntimeDependencies:
    """Instantiate shared service objects for the application runtime."""
    ssh = SSHService(config, logger)
    collector = MikroTikCollector(logger=logger)
    compliance_inspector = DevicePolicyInspector()
    scheduler_inspector = SchedulerPolicyInspector(logger=logger)

    return RuntimeDependencies(
        ssh=ssh,
        collector=collector,
        compliance_inspector=compliance_inspector,
        firmware_manager=FirmwareManager(config=config, logger=logger),
        radius_remediator=RadiusRemediator(config=config, logger=logger),
        scheduler_inspector=scheduler_inspector,
        targeted_remediator=TargetedRemediator(
            config=config,
            ssh=ssh,
            collector=collector,
            compliance_inspector=compliance_inspector,
            scheduler_inspector=scheduler_inspector,
            logger=logger,
        ),
        config_backup=ConfigBackupService(
            config=config,
            ssh=ssh,
            logger=logger,
        ),
    )


def _build_phpipam_registry(
    config: AppConfig,
    logger: logging.Logger,
) -> AsyncPHPIPAMRegistryService | None:
    """Create the phpIPAM registry service only when the integration is enabled."""
    if not config.phpipam.enabled:
        return None
    client = AsyncPHPIPAMClient(config.phpipam, logger)
    return AsyncPHPIPAMRegistryService(config=config.phpipam, client=client, logger=logger)


def _build_report_writers(config: AppConfig, logger: logging.Logger) -> list[ReportWriter]:
    """Create the default report writers for audit-style exports."""
    writers: list[ReportWriter] = []

    if config.report.write_excel:
        writers.append(ExcelWriter(config.output_xlsx))
    if config.report.write_ndjson:
        writers.append(JsonWriter(config.output_json or str(config.output_xlsx).replace(".xlsx", ".ndjson")))

    google = getattr(config, "google", None)
    if (
        config.report.write_google_sheets
        and google
        and google.enabled
        and google.credentials_file
        and google.spreadsheet
    ):
        try:
            import gspread
            from google.oauth2.service_account import Credentials as GoogleCredentials

            creds = GoogleCredentials.from_service_account_file(
                google.credentials_file,
                scopes=[
                    "https://www.googleapis.com/auth/spreadsheets",
                    "https://www.googleapis.com/auth/drive",
                ],
            )
            client = gspread.authorize(creds)
            spreadsheet = client.open(google.spreadsheet)
            writers.append(
                GSheetWriter(
                    spreadsheet=spreadsheet,
                    batch_size=500,
                    max_batch_cells=google.max_batch_cells,
                    suppress_cell_limit_errors=google.suppress_cell_limit_errors,
                )
            )
        except Exception as exc:
            logger.exception("Google Sheets writer disabled: %s", exc)

    return writers


def _build_custom_report_writers(
    config: AppConfig,
    logger: logging.Logger,
    *,
    output_xlsx: str | None = None,
    output_json: str | None = None,
) -> list[ReportWriter]:
    """Create report writers for ad-hoc exports with optional output overrides."""
    writers: list[ReportWriter] = []

    excel_path = output_xlsx or config.output_xlsx
    json_path = output_json or str(Path(excel_path).with_suffix(".ndjson"))

    if config.report.write_excel:
        writers.append(ExcelWriter(excel_path))
    if config.report.write_ndjson:
        writers.append(JsonWriter(json_path))

    google = getattr(config, "google", None)
    if (
        config.report.write_google_sheets
        and google
        and google.enabled
        and google.credentials_file
        and google.spreadsheet
    ):
        try:
            import gspread
            from google.oauth2.service_account import Credentials as GoogleCredentials

            creds = GoogleCredentials.from_service_account_file(
                google.credentials_file,
                scopes=[
                    "https://www.googleapis.com/auth/spreadsheets",
                    "https://www.googleapis.com/auth/drive",
                ],
            )
            client = gspread.authorize(creds)
            spreadsheet = client.open(google.spreadsheet)
            writers.append(
                GSheetWriter(
                    spreadsheet=spreadsheet,
                    batch_size=500,
                    max_batch_cells=google.max_batch_cells,
                    suppress_cell_limit_errors=google.suppress_cell_limit_errors,
                )
            )
        except Exception as exc:
            logger.exception("Google Sheets writer disabled: %s", exc)

    return writers


def _build_report_pipeline(config: AppConfig, logger: logging.Logger) -> ReportPipeline:
    """Construct the default report pipeline used by audit workflows."""
    return ReportPipeline(_build_report_writers(config, logger))


def build_app() -> AuditApplication:
    """Build the fully wired application runtime from environment-backed config."""
    config = AppConfig.from_env()
    logger = setup_logging(config)
    auth_credentials = _build_auth_credentials(config)
    deps = _build_dependencies(config, logger)

    auditor = DeviceAuditor(
        config=config,
        ssh=deps.ssh,
        collector=deps.collector,
        compliance_inspector=deps.compliance_inspector,
        firmware_manager=deps.firmware_manager,
        radius_remediator=deps.radius_remediator,
        logger=logger,
        auth_credentials=auth_credentials,
        scheduler_inspector=deps.scheduler_inspector,
    )

    return AuditApplication(
        config=config,
        logger=logger,
        target_provider=TargetProvider(config),
        auditor=auditor,
        report_pipeline=_build_report_pipeline(config, logger),
        firmware_manager=deps.firmware_manager,
        phpipam_registry=_build_phpipam_registry(config, logger),
        targeted_remediator=deps.targeted_remediator,
        config_backup=deps.config_backup,
    )


__all__ = [
    "AuditApplication",
    "DeviceAuditor",
    "ReportPipeline",
    "RuntimeDependencies",
    "SummaryAccumulator",
    "TargetProvider",
    "build_app",
    "inventory_row",
    "issue_rows",
    "mismatch_rows",
    "raw_row",
    "topology_rows",
    "vlan_rows",
]
