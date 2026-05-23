"""Implementation details for platform_api command_runner."""

from __future__ import annotations

import asyncio
import contextlib
import io
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from mikrotik_audit.runtime.bootstrap import build_app


CommandName = Literal[
    "audit",
    "export",
    "phpipam-report",
    "topology",
    "generate-script",
    "backup-configs",
    "upload-firmware",
    "ospf-create",
    "remediate",
    "radius-fix",
    "scheduler-fix",
    "targets",
]


@dataclass(slots=True)
class CommandJob:
    """Represent commandjob."""
    job_id: UUID
    command: CommandName
    parameters: dict[str, Any]
    status: str = "queued"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: str = ""
    output: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True, slots=True)
class CommandDefinition:
    """Represent commanddefinition."""
    name: CommandName
    title: str
    description: str
    requires_ip: bool = False
    supports_ip: bool = False
    supports_export: bool = False
    supports_progress: bool = False
    supports_apply: bool = False
    supports_domains: bool = False


COMMAND_DEFINITIONS: tuple[CommandDefinition, ...] = (
    CommandDefinition("audit", "Audit", "Полный аудит inventory или одного устройства.", supports_ip=True, supports_export=True, supports_progress=True),
    CommandDefinition("export", "Export", "Полный аудит с экспортом отчетов.", supports_progress=True),
    CommandDefinition("phpipam-report", "phpIPAM Report", "Сравнительный отчет с phpIPAM.", supports_progress=True),
    CommandDefinition("topology", "Topology", "Онлайн-сбор и анализ топологии.", supports_ip=True, supports_export=True, supports_progress=True),
    CommandDefinition("generate-script", "Generate Script", "Генерация remediation scripts.", supports_ip=True, supports_progress=True),
    CommandDefinition("backup-configs", "Backup Configs", "Снятие config backup с устройств.", supports_ip=True, supports_progress=True),
    CommandDefinition("upload-firmware", "Upload Firmware", "Проверка и upload firmware.", supports_ip=True, supports_progress=True),
    CommandDefinition("ospf-create", "OSPF Create", "Генерация OSPF scripts.", supports_ip=True, supports_export=True, supports_progress=True),
    CommandDefinition("remediate", "Remediate", "Планирование или применение targeted remediation.", requires_ip=True, supports_apply=True, supports_domains=True, supports_export=True),
    CommandDefinition("radius-fix", "Radius Fix", "Проверка и исправление RADIUS на одном устройстве.", requires_ip=True, supports_apply=True, supports_export=True),
    CommandDefinition("scheduler-fix", "Scheduler Fix", "Проверка и исправление scheduler policy.", requires_ip=True, supports_apply=True, supports_export=True),
    CommandDefinition("targets", "Targets", "Просмотр resolved target list.", supports_progress=False),
)


class _BufferingLogHandler(logging.Handler):
    """Represent bufferingloghandler."""
    def __init__(self, sink: list[str]) -> None:
        super().__init__(level=logging.INFO)
        self.sink = sink
        self.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink.append(self.format(record))
        except Exception:
            return


class CommandRunner:
    """Represent commandrunner."""
    def __init__(self) -> None:
        self._jobs: dict[UUID, CommandJob] = {}
        self._tasks: dict[UUID, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()

    def list_commands(self) -> list[CommandDefinition]:
        return list(COMMAND_DEFINITIONS)

    async def list_jobs(self) -> list[CommandJob]:
        async with self._lock:
            jobs = list(self._jobs.values())
        return sorted(jobs, key=lambda item: item.created_at, reverse=True)

    async def get_job(self, job_id: UUID) -> CommandJob | None:
        async with self._lock:
            return self._jobs.get(job_id)

    async def submit(self, command: CommandName, parameters: dict[str, Any]) -> CommandJob:
        job = CommandJob(job_id=uuid4(), command=command, parameters=dict(parameters))
        async with self._lock:
            self._jobs[job.job_id] = job
        self._tasks[job.job_id] = asyncio.create_task(self._run_job(job.job_id))
        return job

    async def _run_job(self, job_id: UUID) -> None:
        job = await self.get_job(job_id)
        if job is None:
            return

        await self._update_job(job_id, status="running", started_at=datetime.now(timezone.utc))
        app = build_app()
        handler = _BufferingLogHandler(job.output)
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        app.logger.addHandler(handler)

        try:
            with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
                summary, artifacts = await self._execute(app, job.command, job.parameters, job.output)

            output_parts = [stdout_buffer.getvalue().strip(), stderr_buffer.getvalue().strip()]
            for part in output_parts:
                if part:
                    job.output.extend(line for line in part.splitlines() if line.strip())

            await self._update_job(
                job_id,
                status="succeeded",
                completed_at=datetime.now(timezone.utc),
                summary=summary,
                artifacts=artifacts,
            )
        except Exception as exc:
            job.output.append(f"ERROR: {exc}")
            await self._update_job(
                job_id,
                status="failed",
                completed_at=datetime.now(timezone.utc),
                summary=f"Command {job.command} failed",
                error=str(exc),
            )
        finally:
            app.logger.removeHandler(handler)
            await app.shutdown()

    async def _update_job(self, job_id: UUID, **changes: Any) -> None:
        async with self._lock:
            job = self._jobs[job_id]
            for key, value in changes.items():
                setattr(job, key, value)

    async def _execute(
        self,
        app: Any,
        command: CommandName,
        parameters: dict[str, Any],
        output: list[str],
    ) -> tuple[str, list[str]]:
        handler = self._command_handlers().get(command)
        if handler is None:
            raise ValueError(f"Unsupported command: {command}")

        ip = self._optional_str(parameters.get("ip"))
        show_progress = bool(parameters.get("show_progress", False))
        export_report = bool(parameters.get("export_report", False))
        apply_changes = bool(parameters.get("apply_changes", False))
        domains = self._list_of_str(parameters.get("domains"))
        return await handler(
            app,
            output,
            ip=ip,
            show_progress=show_progress,
            export_report=export_report,
            apply_changes=apply_changes,
            domains=domains,
            parameters=parameters,
        )

    def _command_handlers(self) -> dict[
        CommandName,
        Callable[..., Awaitable[tuple[str, list[str]]]],
    ]:
        return {
            "audit": self._run_audit,
            "export": self._run_export,
            "phpipam-report": self._run_phpipam_report,
            "topology": self._run_topology,
            "generate-script": self._run_generate_script,
            "backup-configs": self._run_backup_configs,
            "upload-firmware": self._run_upload_firmware,
            "ospf-create": self._run_ospf_create,
            "remediate": self._run_remediate,
            "radius-fix": self._run_radius_fix,
            "scheduler-fix": self._run_scheduler_fix,
            "targets": self._run_targets,
        }

    async def _run_audit(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = kwargs["ip"]
        export_report = kwargs["export_report"]
        show_progress = kwargs["show_progress"]
        if ip:
            result = await app.run_single_audit_command(ip, export=export_report)
            output.append(f"{result.ip} | {result.identity} | {result.status}")
            return f"Single-device audit completed for {result.ip}", []
        await app.run_audit_command(show_progress=show_progress)
        return "Inventory audit completed", []

    async def _run_export(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        await app.run_export_command(show_progress=kwargs["show_progress"])
        return "Export command completed", []

    async def _run_phpipam_report(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        await app.run_phpipam_report_command(show_progress=kwargs["show_progress"])
        return "phpIPAM report completed", []

    async def _run_topology(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        results = await app.run_topology_command(
            ip=kwargs["ip"],
            export=kwargs["export_report"],
            show_progress=kwargs["show_progress"],
        )
        edge_count = sum(len(item.edges) for item in results)
        output.append(f"devices={len(results)} edges={edge_count}")
        return f"Topology collection completed for {len(results)} devices", []

    async def _run_generate_script(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = kwargs["ip"]
        show_progress = kwargs["show_progress"]
        if ip:
            return await self._run_single_path_command(
                output,
                ip,
                lambda target_ip: app.generate_script_for_ip(target_ip),
                "Script generation completed for {ip}",
            )

        paths = await app.generate_scripts_for_targets(show_progress=show_progress)
        output.extend(paths)
        failures = app.get_last_generate_script_failures()
        output.extend(f"SKIPPED: {item}" for item in failures)
        return f"Generated {len(paths)} remediation scripts", paths

    async def _run_backup_configs(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = kwargs["ip"]
        show_progress = kwargs["show_progress"]
        if ip:
            result = await app.backup_config_for_ip(ip)
            output.append(result.path)
            return f"Config backup completed for {ip}", [result.path]
        paths = await app.backup_configs_for_targets(show_progress=show_progress)
        output.extend(paths)
        return f"Backed up {len(paths)} configs", paths

    async def _run_upload_firmware(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = kwargs["ip"]
        show_progress = kwargs["show_progress"]
        if ip:
            result = await app.upload_firmware_for_ip(ip)
            output.append(str(result))
            return f"Firmware inspection completed for {ip}", []
        results = await app.upload_firmware_for_targets(show_progress=show_progress)
        output.extend(str(item) for item in results[:50])
        return f"Firmware inspection completed for {len(results)} devices", []

    async def _run_ospf_create(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = kwargs["ip"]
        show_progress = kwargs["show_progress"]
        if ip:
            return await self._run_single_path_command(
                output,
                ip,
                lambda target_ip: app.create_ospf_script_for_ip(target_ip),
                "OSPF script generation completed for {ip}",
            )

        paths = await app.create_ospf_scripts_for_targets(show_progress=show_progress)
        output.extend(paths)
        return f"Generated {len(paths)} OSPF scripts", paths

    async def _run_remediate(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = self._require_ip(kwargs["ip"], "remediate")
        result = await app.remediate_device(
            ip=ip,
            domains=kwargs["domains"] or None,
            apply=kwargs["apply_changes"],
        )
        return self._finalize_payload_command(
            output,
            payload=result.to_dict(),
            summary=f"Remediation planning completed for {ip}",
        )

    async def _run_radius_fix(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = self._require_ip(kwargs["ip"], "radius-fix")
        payload = await app.fix_radius_for_ip(ip=ip, apply=kwargs["apply_changes"])
        output.append(str(payload))
        return f"RADIUS fix workflow completed for {ip}", []

    async def _run_scheduler_fix(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ip = self._require_ip(kwargs["ip"], "scheduler-fix")
        result = await app.remediate_device(
            ip=ip,
            domains=["scheduler"],
            apply=kwargs["apply_changes"],
        )
        return self._finalize_payload_command(
            output,
            payload=result.to_dict(),
            summary=f"Scheduler remediation completed for {ip}",
        )

    async def _run_targets(
        self,
        app: Any,
        output: list[str],
        **kwargs: Any,
    ) -> tuple[str, list[str]]:
        ips = app.get_target_ips()
        limit = int(kwargs["parameters"].get("limit", 20) or 20)
        output.append(f"count={len(ips)}")
        output.extend(ips[:limit])
        return f"Resolved {len(ips)} targets", []

    async def _run_single_path_command(
        self,
        output: list[str],
        ip: str,
        producer: Callable[[str], Awaitable[str | None]],
        summary_template: str,
    ) -> tuple[str, list[str]]:
        path = await producer(ip)
        artifacts = [path] if path else []
        if path:
            output.append(path)
        return summary_template.format(ip=ip), artifacts

    def _finalize_payload_command(
        self,
        output: list[str],
        *,
        payload: dict[str, Any],
        summary: str,
    ) -> tuple[str, list[str]]:
        output.append(str(payload))
        script_path = payload.get("script_path")
        artifacts = [script_path] if script_path else []
        return summary, artifacts

    @staticmethod
    def _require_ip(ip: str | None, command: str) -> str:
        if ip:
            return ip
        raise ValueError(f"Command '{command}' requires ip")

    @staticmethod
    def _optional_str(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _list_of_str(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]
