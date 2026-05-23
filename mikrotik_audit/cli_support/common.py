"""Implementation details for cli_support common."""

from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import subprocess
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

import click

if TYPE_CHECKING:
    from mikrotik_audit.config import AppConfig
    from mikrotik_audit.runner import AuditRunner


CommandOperation = Callable[["AuditRunner"], Awaitable[None]]
CommandResultT = TypeVar("CommandResultT")
OutputFormat = click.Choice(["text", "json"], case_sensitive=False)
RemediationDomain = click.Choice(["ntp", "watchdog", "scheduler"], case_sensitive=False)
ServiceAction = click.Choice(
    ["audit", "export", "phpipam-report", "topology", "generate-script", "backup-configs"],
    case_sensitive=False,
)


def build_app() -> "AuditRunner":
    """Build app."""
    from mikrotik_audit.runtime.bootstrap import build_app as _build_app

    try:
        return _build_app()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


async def shutdown_app(app: "AuditRunner") -> None:
    """Handle shutdown app."""
    from mikrotik_audit.logging_setup import shutdown_logging

    try:
        await app.shutdown()
    finally:
        shutdown_logging(app.logger)


@contextlib.asynccontextmanager
async def managed_app(command_name: str) -> AsyncIterator["AuditRunner"]:
    """Handle managed app."""
    app = build_app()
    try:
        app.logger.info("Application started command=%s", command_name)
        yield app
    finally:
        app.logger.info("Application finished command=%s", command_name)
        await shutdown_app(app)


@contextlib.contextmanager
def captured_app_logger(logger: logging.Logger) -> Iterator[io.StringIO]:
    """Handle captured app logger."""
    log_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(threadName)s | %(message)s")
    )

    old_handlers = list(logger.handlers)
    old_propagate = logger.propagate
    logger.handlers = [handler]
    logger.propagate = False

    try:
        yield log_buffer
    finally:
        logger.handlers = old_handlers
        logger.propagate = old_propagate
        handler.close()


async def run_with_managed_app(
    command_name: str,
    operation: Callable[["AuditRunner"], Awaitable[CommandResultT]],
) -> CommandResultT:
    """Run with managed app."""
    async with managed_app(command_name) as app:
        return await operation(app)


def run_async_command(command_name: str, operation: CommandOperation) -> None:
    """Run async command."""
    asyncio.run(run_with_managed_app(command_name, operation))


def run_async_text_command(
    command_name: str,
    operation: Callable[["AuditRunner"], Awaitable[str]],
) -> str:
    """Run async text command."""
    return asyncio.run(run_with_managed_app(command_name, operation))


async def run_with_app_captured_output(
    command_name: str,
    operation: CommandOperation,
) -> str:
    """Run with app captured output."""
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    app = build_app()

    try:
        with captured_app_logger(app.logger) as log_buffer:
            app.logger.info("Application started command=%s", command_name)
            with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(
                stderr_buffer
            ):
                await operation(app)
            app.logger.info("Application finished command=%s", command_name)
    finally:
        await shutdown_app(app)

    parts = []
    for part in (
        stdout_buffer.getvalue(),
        stderr_buffer.getvalue(),
        log_buffer.getvalue(),
    ):
        cleaned = normalize_captured_output(part.strip())
        if cleaned:
            parts.append(cleaned)
    return "\n\n".join(parts) or "Command completed without textual output."


def run_async_captured_output(
    command_name: str,
    operation: CommandOperation,
) -> str:
    """Run async captured output."""
    return asyncio.run(run_with_app_captured_output(command_name, operation))


def normalize_captured_output(text: str) -> str:
    """Normalize captured output."""
    if not text:
        return ""

    normalized_lines: list[str] = []
    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.split("\r")[-1].rstrip()
        if not line:
            if normalized_lines and normalized_lines[-1] == "":
                continue
            normalized_lines.append("")
            continue
        normalized_lines.append(line)

    while normalized_lines and normalized_lines[0] == "":
        normalized_lines.pop(0)
    while normalized_lines and normalized_lines[-1] == "":
        normalized_lines.pop()

    return "\n".join(normalized_lines)


def load_app_config() -> "AppConfig":
    """Load app config."""
    try:
        from mikrotik_audit.config import AppConfig

        return AppConfig.from_env()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


def offline_report_paths(config: "AppConfig", label: str) -> tuple[str, str]:
    """Handle offline report paths."""
    base_xlsx = Path(config.output_xlsx)
    output_dir = base_xlsx.parent
    safe_label = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in label).strip("_")
    if not safe_label:
        safe_label = "offline_analysis"
    excel_path = output_dir / f"{safe_label}_analysis.xlsx"
    json_path = excel_path.with_suffix(".ndjson")
    return str(excel_path), str(json_path)


def resolve_target_ips(config: "AppConfig") -> list[str]:
    """Resolve target ips."""
    from mikrotik_audit.app_runtime import TargetProvider

    return TargetProvider(config).get_target_ips()


def validate_config_files(*, cwd: Path) -> None:
    """Validate config files."""
    command = [
        sys.executable,
        "-c",
        "from mikrotik_audit.config import AppConfig; AppConfig.from_env().validate(); print('ok')",
    ]
    result = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip() or "Configuration validation failed."
        raise RuntimeError(message)
