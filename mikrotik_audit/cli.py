from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import subprocess
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

if TYPE_CHECKING:
    from config import AppConfig
    from runner import AuditRunner


CommandOperation = Callable[["AuditRunner"], Awaitable[None]]
OutputFormat = click.Choice(["text", "json"], case_sensitive=False)
RemediationDomain = click.Choice(["ntp", "watchdog", "scheduler"], case_sensitive=False)
ServiceAction = click.Choice(
    ["audit", "export", "phpipam-report", "topology", "generate-script", "backup-configs"],
    case_sensitive=False,
)

CLI_HELP = """MikroTik audit and remediation tool.

Use this CLI to inspect the inventory, audit one router or the whole target
set, generate remediation scripts, and build a phpIPAM comparison report.\n\n

Typical workflow:\n
  1. doctor          Validate environment and required files\n
  2. targets         Inspect the resolved target IP list\n
  3. audit           Run the full audit and export Excel/JSON results\n
  4. phpipam-report  Build the inventory comparison report\n
\n\n
Examples:
  mikrotik-audit doctor
  mikrotik-audit targets --limit 10
  mikrotik-audit audit --ip 10.216.92.10 --no-export
  mikrotik-audit generate-script --ip 10.216.94.100
  mikrotik-audit config --format json
"""


def _build_app() -> "AuditRunner":
    from bootstrap import build_app

    try:
        return build_app()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


async def _shutdown_app(app: "AuditRunner") -> None:
    from logging_setup import shutdown_logging

    try:
        await app.shutdown()
    finally:
        shutdown_logging(app.logger)


@contextlib.asynccontextmanager
async def _managed_app(command_name: str) -> AsyncIterator["AuditRunner"]:
    app = _build_app()
    try:
        app.logger.info("Application started command=%s", command_name)
        yield app
    finally:
        app.logger.info("Application finished command=%s", command_name)
        await _shutdown_app(app)


@contextlib.contextmanager
def _captured_app_logger(logger: logging.Logger) -> Iterator[io.StringIO]:
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


async def _run_with_app(command_name: str, operation: CommandOperation) -> None:
    async with _managed_app(command_name) as app:
        await operation(app)


async def _run_with_app_result(
    command_name: str,
    operation: Callable[["AuditRunner"], Awaitable[str]],
) -> str:
    async with _managed_app(command_name) as app:
        return await operation(app)


def _run_async_command(command_name: str, operation: CommandOperation) -> None:
    asyncio.run(_run_with_app(command_name, operation))


def _run_async_text_command(
    command_name: str,
    operation: Callable[["AuditRunner"], Awaitable[str]],
) -> str:
    return asyncio.run(_run_with_app_result(command_name, operation))


async def _run_with_app_captured_output(
    command_name: str,
    operation: CommandOperation,
) -> str:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    log_buffer = io.StringIO()
    app = _build_app()

    try:
        with _captured_app_logger(app.logger) as log_buffer:
            app.logger.info("Application started command=%s", command_name)
            with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(
                stderr_buffer
            ):
                await operation(app)
            app.logger.info("Application finished command=%s", command_name)
    finally:
        await _shutdown_app(app)

    parts = []
    for part in (
        stdout_buffer.getvalue(),
        stderr_buffer.getvalue(),
        log_buffer.getvalue(),
    ):
        cleaned = _normalize_captured_output(part.strip())
        if cleaned:
            parts.append(cleaned)
    return "\n\n".join(parts) or "Command completed without textual output."


def _run_async_captured_output(
    command_name: str,
    operation: CommandOperation,
) -> str:
    return asyncio.run(_run_with_app_captured_output(command_name, operation))


def _normalize_captured_output(text: str) -> str:
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


def _load_app_config() -> "AppConfig":
    try:
        from config import AppConfig

        return AppConfig.from_env()
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


def _redact(value: str, show_secrets: bool) -> str:
    if show_secrets:
        return value
    if not value:
        return ""
    return "***"


def _build_config_snapshot(
    config: AppConfig,
    *,
    show_secrets: bool,
) -> dict[str, Any]:
    snapshot = asdict(config)
    snapshot["inventory_path"] = str(config.inventory_path.resolve())
    snapshot["secrets_path"] = str(config.secrets_path.resolve())
    snapshot["phpipam"] = dict(snapshot["phpipam"])
    snapshot["google"] = dict(snapshot["google"])
    snapshot["workers"] = config.workers
    snapshot["ssh_port"] = config.ssh_port
    snapshot["timeout"] = config.timeout
    snapshot["auth_timeout"] = config.auth_timeout
    snapshot["banner_timeout"] = config.banner_timeout
    snapshot["command_timeout"] = config.command_timeout
    snapshot["ping_timeout"] = config.ping_timeout
    snapshot["ping_count"] = config.ping_count
    snapshot["max_targets"] = config.max_targets
    snapshot["output_xlsx"] = config.output_xlsx
    snapshot["output_json"] = config.output_json
    snapshot["service"] = dict(snapshot["service"])
    snapshot["backup"] = dict(snapshot["backup"])

    snapshot["password"] = _redact(config.password, show_secrets)
    snapshot["fallback_password"] = _redact(config.fallback_password, show_secrets)
    snapshot["firmware_password"] = _redact(config.firmware_password, show_secrets)
    snapshot["radius_secret"] = _redact(config.radius_secret, show_secrets)
    snapshot["phpipam"]["password"] = _redact(config.phpipam.password, show_secrets)

    return snapshot


def _emit_json(payload: Any) -> None:
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))


def _format_table(rows: list[dict[str, Any]], headers: list[str]) -> str:
    if not rows:
        return ""

    column_widths: dict[str, int] = {}
    for header in headers:
        column_widths[header] = len(header)
    for row in rows:
        for header in headers:
            value = str(row.get(header, ""))
            column_widths[header] = max(column_widths[header], len(value))

    separators = ["-" * column_widths[header] for header in headers]
    header_row = " | ".join(header.ljust(column_widths[header]) for header in headers)
    separator_row = "-+-".join(separators)

    lines = [header_row, separator_row]
    for row in rows:
        lines.append(
            " | ".join(str(row.get(header, "")).ljust(column_widths[header]) for header in headers)
        )

    return "\n".join(lines)


def _print_table(rows: list[dict[str, Any]], headers: list[str]) -> None:
    table = _format_table(rows, headers)
    if table:
        click.echo(table)


def _capture_text_output(renderer: Callable[[], None]) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        renderer()
    text = buffer.getvalue().strip()
    return text or "<no output>"


def _print_section(title: str) -> None:
    click.echo(title)


def _print_key_value(key: str, value: Any) -> None:
    click.echo(f"- {key}: {value}")


def _print_remediation_result(payload: dict[str, Any]) -> None:
    _print_section("Targeted Remediation")
    _print_key_value("ip", payload.get("ip", ""))
    _print_key_value("identity", payload.get("identity", ""))
    _print_key_value("auth_method", payload.get("auth_method", ""))
    _print_key_value("dry_run", payload.get("dry_run", True))
    _print_key_value("has_changes", payload.get("has_changes", False))
    _print_key_value("command_count", payload.get("command_count", 0))
    if payload.get("script_path"):
        _print_key_value("script_path", payload.get("script_path"))

    click.echo("")
    _print_section("Domains")
    for item in payload.get("domains", []):
        click.echo(
            "- "
            f"{item.get('domain', '')}: "
            f"compliant={item.get('compliant', False)} "
            f"commands={len(item.get('commands', []))} "
            f"applied={item.get('applied', 0)} "
            f"failed={item.get('failed', 0)}"
        )
        details = item.get("details", "")
        if details:
            click.echo(f"  details: {details}")
        commands = item.get("commands", [])
        if commands:
            click.echo("  commands:")
            for command in commands:
                click.echo(f"  - {command}")


def _print_radius_fix_result(payload: dict[str, Any]) -> None:
    _print_section("RADIUS Fix")
    _print_key_value("ip", payload.get("ip", ""))
    _print_key_value("identity", payload.get("identity", ""))
    _print_key_value("auth_method", payload.get("auth_method", ""))
    _print_key_value("dry_run", payload.get("dry_run", True))
    _print_key_value("radius_fix_needed", payload.get("radius_fix_needed", False))
    _print_key_value("radius_present_before", payload.get("radius_present_before", False))
    _print_key_value("aaa_enabled_before", payload.get("aaa_enabled_before", False))
    _print_key_value("radius_present_after", payload.get("radius_present_after", False))
    _print_key_value("aaa_present_after", payload.get("aaa_present_after", False))
    _print_key_value("radius_added", payload.get("radius_added", False))
    _print_key_value("radius_recreated", payload.get("radius_recreated", False))
    _print_key_value("aaa_enabled", payload.get("aaa_enabled", False))


def _print_ospf_script_result(paths: list[str]) -> None:
    _print_section("OSPF Creation")
    if not paths:
        click.echo("No OSPF scripts were generated.")
        return
    _print_key_value("generated_scripts", len(paths))
    for path in paths:
        click.echo(f"- {path}")


def _build_radius_fix_export_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "ip": payload.get("ip", ""),
            "identity": payload.get("identity", ""),
            "auth_method": payload.get("auth_method", ""),
            "dry_run": payload.get("dry_run", True),
            "radius_fix_needed": payload.get("radius_fix_needed", False),
            "radius_present_before": payload.get("radius_present_before", False),
            "aaa_enabled_before": payload.get("aaa_enabled_before", False),
            "radius_present_after": payload.get("radius_present_after", False),
            "aaa_present_after": payload.get("aaa_present_after", False),
            "radius_added": payload.get("radius_added", False),
            "radius_recreated": payload.get("radius_recreated", False),
            "aaa_enabled": payload.get("aaa_enabled", False),
        }
    ]


def _build_scheduler_fix_export_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    domain = (payload.get("domains") or [{}])[0]
    return [
        {
            "ip": payload.get("ip", ""),
            "identity": payload.get("identity", ""),
            "auth_method": payload.get("auth_method", ""),
            "dry_run": payload.get("dry_run", True),
            "domain": domain.get("domain", "scheduler"),
            "compliant": domain.get("compliant", False),
            "command_count": payload.get("command_count", 0),
            "applied": domain.get("applied", 0),
            "failed": domain.get("failed", 0),
            "details": domain.get("details", ""),
        }
    ]


def _build_remediation_export_sections(payload: dict[str, Any]) -> dict[str, tuple[list[str], list[dict[str, Any]]]]:
    summary_headers = [
        "ip",
        "identity",
        "auth_method",
        "dry_run",
        "script_path",
        "command_count",
        "has_changes",
    ]
    summary_rows = [
        {
            "ip": payload.get("ip", ""),
            "identity": payload.get("identity", ""),
            "auth_method": payload.get("auth_method", ""),
            "dry_run": payload.get("dry_run", True),
            "script_path": payload.get("script_path", ""),
            "command_count": payload.get("command_count", 0),
            "has_changes": payload.get("has_changes", False),
        }
    ]

    domain_headers = [
        "ip",
        "identity",
        "auth_method",
        "domain",
        "compliant",
        "applied",
        "failed",
        "details",
        "command_count",
    ]
    domain_rows: list[dict[str, Any]] = []
    command_headers = [
        "ip",
        "identity",
        "auth_method",
        "domain",
        "command_index",
        "command",
    ]
    command_rows: list[dict[str, Any]] = []

    for domain in payload.get("domains", []) or []:
        domain_rows.append(
            {
                "ip": payload.get("ip", ""),
                "identity": payload.get("identity", ""),
                "auth_method": payload.get("auth_method", ""),
                "domain": domain.get("domain", ""),
                "compliant": domain.get("compliant", False),
                "applied": domain.get("applied", 0),
                "failed": domain.get("failed", 0),
                "details": domain.get("details", ""),
                "command_count": len(domain.get("commands", [])),
            }
        )
        for index, command in enumerate(domain.get("commands", []) or [], start=1):
            command_rows.append(
                {
                    "ip": payload.get("ip", ""),
                    "identity": payload.get("identity", ""),
                    "auth_method": payload.get("auth_method", ""),
                    "domain": domain.get("domain", ""),
                    "command_index": index,
                    "command": command,
                }
            )

    return {
        "remediation_summary": (summary_headers, summary_rows),
        "remediation_domains": (domain_headers, domain_rows),
        "remediation_commands": (command_headers, command_rows),
    }


def _build_ospf_script_export_rows(paths: list[str], ip: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not paths:
        return [
            {
                "ip": ip or "",
                "generated": False,
                "script_path": "",
            }
        ]

    for path in paths:
        path_str = str(path)
        stem = Path(path_str).stem
        ip_from_path = ""
        if "__" in stem:
            ip_from_path = stem.split("__", 1)[0].replace("_", ".")
        rows.append(
            {
                "ip": ip or ip_from_path,
                "generated": True,
                "script_path": path_str,
            }
        )
    return rows


def _print_targets_summary(limit: int = 20) -> None:
    config = _load_app_config()
    ips = _resolve_target_ips(config)

    _print_section("Target Inventory")
    _print_key_value("inventory_file", config.inventory_file)
    _print_key_value("inventory_path", config.inventory_path.resolve())
    _print_key_value("exclude_gateways", config.exclude_gateways)
    _print_key_value("count", len(ips))

    click.echo("")
    _print_section("Resolved IPs")
    for ip in ips[:limit]:
        click.echo(f"- {ip}")

    if limit < len(ips):
        click.echo(f"- ... truncated, showing {limit} of {len(ips)}")


def _build_targets_output_payload(
    *,
    limit: int = 20,
) -> tuple[str, str, list[str]]:
    config = _load_app_config()
    ips = _resolve_target_ips(config)
    shown = ips[:limit]

    summary_lines = [
        "Target Inventory",
        f"- inventory_file: {config.inventory_file}",
        f"- inventory_path: {config.inventory_path.resolve()}",
        f"- exclude_gateways: {config.exclude_gateways}",
        f"- count: {len(ips)}",
        "",
        "Resolved IPs",
        f"- showing: {len(shown)} of {len(ips)}",
    ]

    if limit < len(ips):
        summary_lines.append(f"- truncated: yes ({limit}/{len(ips)})")
    else:
        summary_lines.append("- truncated: no")

    return "Targets Summary", "\n".join(summary_lines), shown


def _resolve_target_ips(config: "AppConfig") -> list[str]:
    from app_runtime import TargetProvider

    return TargetProvider(config).get_target_ips()


def _build_doctor_output_payload(payload: dict[str, Any]) -> dict[str, Any]:
    checks = payload.get("checks", [])
    warnings = payload.get("warnings", [])
    errors = payload.get("errors", [])

    ok_count = sum(1 for item in checks if item.get("status") == "ok")
    fail_count = sum(1 for item in checks if item.get("status") == "fail")
    skip_count = sum(1 for item in checks if item.get("status") == "skip")

    summary_lines = [
        f"Overall status: {'OK' if payload.get('ok') else 'Issues found'}",
        f"Checks: ok={ok_count} fail={fail_count} skip={skip_count}",
        f"Warnings: {len(warnings)}",
        f"Errors: {len(errors)}",
    ]

    items = [
        f"[{item['status']}] {item['name']}: {item['detail']}"
        for item in checks
    ]

    if warnings:
        items.append("")
        items.append("Warnings")
        items.extend(f"- {warning}" for warning in warnings)

    if errors:
        items.append("")
        items.append("Errors")
        items.extend(f"- {error}" for error in errors)

    return {
        "summary_lines": summary_lines,
        "list_title": "Checks",
        "list_items": items,
    }


def _build_config_output_payload(snapshot: dict[str, Any]) -> dict[str, Any]:
    summary_lines = [
        f"Inventory: {snapshot['inventory_file']}",
        f"Workers: {snapshot['workers']}",
        f"Max targets: {snapshot['max_targets']}",
        f"phpIPAM: {'enabled' if snapshot['phpipam']['enabled'] else 'disabled'}",
        f"Google Sheets: {'enabled' if snapshot['google']['enabled'] else 'disabled'}",
    ]

    items = [
        "Core",
        f"- log_level: {snapshot['log_level']}",
        f"- log_console_level: {snapshot['log_console_level']}",
        f"- log_file_level: {snapshot['log_file_level']}",
        f"- inventory_path: {snapshot['inventory_path']}",
        f"- secrets_path: {snapshot['secrets_path']}",
        "",
        "Runtime",
        f"- workers: {snapshot['workers']}",
        f"- ssh_port: {snapshot['ssh_port']}",
        f"- timeout: {snapshot['timeout']}",
        f"- auth_timeout: {snapshot['auth_timeout']}",
        f"- banner_timeout: {snapshot['banner_timeout']}",
        f"- command_timeout: {snapshot['command_timeout']}",
        f"- ping_timeout: {snapshot['ping_timeout']}",
        f"- ping_count: {snapshot['ping_count']}",
        f"- max_targets: {snapshot['max_targets']}",
        "",
        "Integrations",
        f"- phpipam_enabled: {snapshot['phpipam']['enabled']}",
        f"- google_enabled: {snapshot['google']['enabled']}",
        "",
        "Report",
        f"- output_xlsx: {snapshot['output_xlsx']}",
        f"- output_json: {snapshot['output_json']}",
        f"- write_excel: {snapshot['report']['write_excel']}",
        f"- write_ndjson: {snapshot['report']['write_ndjson']}",
        f"- write_google_sheets: {snapshot['report']['write_google_sheets']}",
        "",
        "Service",
        f"- enabled: {snapshot['service']['enabled']}",
        f"- action: {snapshot['service']['action']}",
        f"- interval_seconds: {snapshot['service']['interval_seconds']}",
        f"- progress: {snapshot['service']['progress']}",
        "",
        "Backup",
        f"- enabled: {snapshot['backup']['enabled']}",
        f"- output_dir: {snapshot['backup']['output_dir']}",
        f"- git_enabled: {snapshot['backup']['git_enabled']}",
        f"- git_repo_dir: {snapshot['backup']['git_repo_dir']}",
        f"- export_command: {snapshot['backup']['export_command']}",
        f"- filename_mode: {snapshot['backup']['filename_mode']}",
    ]

    return {
        "summary_lines": summary_lines,
        "list_title": "Settings",
        "list_items": items,
    }


def _build_setup_summary(payload: dict[str, Any], inventory_path: str) -> str:
    lines = [
        "Setup settings saved.",
        f"- inventory_path: {inventory_path}",
        f"- workers: {payload.get('workers')}",
        f"- max_targets: {payload.get('max_targets')}",
        f"- preload_phpipam_cache: {payload.get('preload_phpipam_cache')}",
        f"- compliance_phpipam: {payload.get('compliance_phpipam')}",
        f"- compliance_scheduler: {payload.get('compliance_scheduler')}",
        f"- compliance_ntp: {payload.get('compliance_ntp')}",
        f"- compliance_watchdog: {payload.get('compliance_watchdog')}",
        f"- remediation_enabled: {payload.get('remediation_enabled')}",
        f"- remediation_allow_apply: {payload.get('remediation_allow_apply')}",
        f"- remediation_allow_generate_script: {payload.get('remediation_allow_generate_script')}",
        f"- report_write_excel: {payload.get('report_write_excel')}",
        f"- report_write_ndjson: {payload.get('report_write_ndjson')}",
        f"- report_write_google_sheets: {payload.get('report_write_google_sheets')}",
    ]
    return "\n".join(lines)


def _build_inventory_settings_output_payload(
    setup_defaults: dict[str, Any],
    *,
    inventory_path: str,
) -> dict[str, Any]:
    summary_lines = [
        f"Inventory settings file: {inventory_path}",
        f"Workers: {setup_defaults.get('workers')}",
        f"Max targets: {setup_defaults.get('max_targets')}",
        f"phpIPAM preload: {setup_defaults.get('preload_phpipam_cache')}",
    ]

    items = [
        "Runtime",
        f"- workers: {setup_defaults.get('workers')}",
        f"- max_targets: {setup_defaults.get('max_targets')}",
        "",
        "Audit",
        f"- preload_phpipam_cache: {setup_defaults.get('preload_phpipam_cache')}",
        "",
        "Compliance",
        f"- phpipam: {setup_defaults.get('compliance_phpipam')}",
        f"- scheduler: {setup_defaults.get('compliance_scheduler')}",
        f"- ntp: {setup_defaults.get('compliance_ntp')}",
        f"- watchdog: {setup_defaults.get('compliance_watchdog')}",
        "",
        "Remediation",
        f"- enabled: {setup_defaults.get('remediation_enabled')}",
        f"- allow_apply: {setup_defaults.get('remediation_allow_apply')}",
        f"- allow_generate_script: {setup_defaults.get('remediation_allow_generate_script')}",
        "",
        "Report",
        f"- write_excel: {setup_defaults.get('report_write_excel')}",
        f"- write_ndjson: {setup_defaults.get('report_write_ndjson')}",
        f"- write_google_sheets: {setup_defaults.get('report_write_google_sheets')}",
    ]

    return {
        "summary_lines": summary_lines,
        "list_title": "Inventory YAML Settings",
        "list_items": items,
    }


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _validate_config_files(*, cwd: Path) -> None:
    command = [
        sys.executable,
        "-c",
        "from config import AppConfig; AppConfig.from_env().validate(); print('ok')",
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


def _print_config_summary(show_secrets: bool = False) -> None:
    config = _load_app_config()
    snapshot = _build_config_snapshot(config, show_secrets=show_secrets)

    _print_section("Core")
    for key in (
        "log_level",
        "log_console_level",
        "log_file_level",
        "inventory_file",
        "inventory_path",
        "secrets_file",
        "test_mode",
    ):
        _print_key_value(key, snapshot[key])

    click.echo("")
    _print_section("Runtime")
    for key in (
        "workers",
        "ssh_port",
        "timeout",
        "auth_timeout",
        "banner_timeout",
        "command_timeout",
        "ping_timeout",
        "ping_count",
        "max_targets",
    ):
        _print_key_value(key, snapshot[key])

    click.echo("")
    _print_section("Integrations")
    _print_key_value("phpipam_enabled", snapshot["phpipam"]["enabled"])
    _print_key_value("google_enabled", snapshot["google"]["enabled"])

    click.echo("")
    _print_section("Service")
    for key, value in snapshot["service"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Backup")
    for key, value in snapshot["backup"].items():
        _print_key_value(key, value)


def _run_doctor_checks() -> tuple[dict[str, Any], int]:
    config = _load_app_config()
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, str]] = []

    def add_check(name: str, ok: bool, detail: str) -> None:
        checks.append(
            {
                "name": name,
                "status": "ok" if ok else "fail",
                "detail": detail,
            }
        )

    inventory_path = config.inventory_path.resolve()
    inventory_exists = inventory_path.exists()
    add_check("inventory_file", inventory_exists, str(inventory_path))
    if not inventory_exists:
        errors.append(f"Inventory file not found: {inventory_path}")

    secrets_path = config.secrets_path.resolve()
    secrets_exists = secrets_path.exists()
    add_check("secrets_file", secrets_exists, str(secrets_path))
    if not secrets_exists:
        warnings.append(f"Secrets file not found: {secrets_path}")

    primary_credentials_ok = bool(config.username and config.password)
    add_check(
        "primary_credentials",
        primary_credentials_ok,
        f"user={config.username or '<empty>'}",
    )
    if not primary_credentials_ok:
        warnings.append("Primary MikroTik credentials are incomplete")

    fallback_credentials_ok = bool(
        config.fallback_username and config.fallback_password
    )
    add_check(
        "fallback_credentials",
        fallback_credentials_ok,
        f"user={config.fallback_username or '<empty>'}",
    )
    if not fallback_credentials_ok:
        errors.append("Fallback credentials are incomplete")

    firmware_dir = Path(config.firmware_dir).resolve()
    firmware_dir_exists = firmware_dir.exists() and firmware_dir.is_dir()
    add_check("firmware_dir", firmware_dir_exists, str(firmware_dir))
    if not firmware_dir_exists:
        warnings.append(f"Firmware directory not found: {firmware_dir}")

    report_outputs_ok = config.report.write_excel or config.report.write_ndjson or (
        config.report.write_google_sheets and config.google.enabled
    )
    add_check(
        "report_outputs",
        report_outputs_ok,
        (
            f"excel={config.report.write_excel} "
            f"ndjson={config.report.write_ndjson} "
            f"gsheet={config.report.write_google_sheets and config.google.enabled}"
        ),
    )

    if config.phpipam.enabled:
        phpipam_ok = all(
            [
                config.phpipam.base_url,
                config.phpipam.app_id,
                config.phpipam.username,
                config.phpipam.password,
            ]
        )
        add_check("phpipam", phpipam_ok, config.phpipam.base_url or "<empty>")
        if not phpipam_ok:
            errors.append("phpIPAM is enabled but required settings are incomplete")
    else:
        checks.append({"name": "phpipam", "status": "skip", "detail": "disabled"})

    if config.google.enabled:
        google_creds = Path(config.google.credentials_file).resolve()
        google_ok = bool(
            config.google.credentials_file
            and google_creds.exists()
            and config.google.spreadsheet
        )
        add_check("google", google_ok, str(google_creds))
        if not google_ok:
            errors.append(
                "Google export is enabled but credentials file or spreadsheet is missing"
            )
    else:
        checks.append({"name": "google", "status": "skip", "detail": "disabled"})

    try:
        config.validate()
        checks.append(
            {
                "name": "config_validation",
                "status": "ok",
                "detail": "validated",
            }
        )
    except RuntimeError as exc:
        checks.append(
            {
                "name": "config_validation",
                "status": "fail",
                "detail": "invalid",
            }
        )
        for line in str(exc).splitlines()[1:]:
            line = line.strip()
            if line:
                errors.append(line.lstrip("- ").strip())

    payload = {
        "ok": not errors,
        "checks": checks,
        "warnings": warnings,
        "errors": errors,
    }
    exit_code = 1 if errors else 0
    return payload, exit_code


def _print_doctor_summary(payload: dict[str, Any]) -> None:
    _print_section("Doctor")
    for item in payload["checks"]:
        click.echo(f"  [{item['status']}] {item['name']}: {item['detail']}")

    if payload["warnings"]:
        click.echo("")
        _print_section("Warnings")
        for warning in payload["warnings"]:
            click.echo(f"  - {warning}")

    if payload["errors"]:
        click.echo("")
        _print_section("Errors")
        for error in payload["errors"]:
            click.echo(f"  - {error}")


@click.group(
    name="mikrotik-audit",
    no_args_is_help=True,
    context_settings={
        "help_option_names": ["-h", "--help"],
        "max_content_width": 100,
    },
    help=CLI_HELP,
)
def cli() -> None:
    pass


@cli.command(
    "audit",
    short_help="Audit one device or the full inventory.",
    help="""Run audit against one device or the full target list.

When --ip is omitted, the command resolves all target IPs from the YAML
inventory file and exports the final results to Excel and JSON.

When --ip is provided, only that device is audited. Export for a single device
can be skipped with --no-export.
""",
)
@click.option(
    "--ip",
    metavar="ADDRESS",
    help="Audit exactly one device instead of the whole inventory.",
)
@click.option(
    "--no-export",
    is_flag=True,
    help="Skip Excel/JSON export for a single-device audit.",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during audit.",
)
def audit_command(ip: str | None, no_export: bool, show_progress: bool) -> None:
    async def operation(app: AuditRunner) -> None:
        if ip:
            await app.run_single_audit_command(ip, export=not no_export)
            return

        await app.run_audit_command(show_progress=show_progress)

    _run_async_command("audit", operation)


@cli.command(
    "export",
    short_help="Run the full audit and export results.",
    help="""Run the full audit and write the configured Excel/JSON outputs.

This command currently behaves like a full inventory audit followed by export.
It does not read previously cached results from disk.
""",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during export.",
)
def export_command(show_progress: bool) -> None:
    async def operation(app: AuditRunner) -> None:
        await app.run_export_command(show_progress=show_progress)

    _run_async_command("export", operation)


@cli.command(
    "firmware-update",
    short_help="Upload firmware to one device or the full inventory.",
    help="""Upload RouterOS firmware from the configured firmware directory for one
device or the full target set. The command prints results as a table or JSON.
""",
)
@click.option(
    "--ip",
    metavar="ADDRESS",
    help="Target device IP address. If omitted, the full target set is processed.",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during firmware upload.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def firmware_update_command(
    ip: str | None,
    show_progress: bool,
    output_format: str,
) -> None:
    async def operation(app: AuditRunner) -> None:
        if ip:
            rows = [await app.upload_firmware_for_ip(ip)]
        else:
            rows = await app.upload_firmware_for_targets(show_progress=show_progress)

        if output_format.lower() == "json":
            _emit_json(rows)
            return

        headers = [
            "ip",
            "identity",
            "architecture",
            "current_version",
            "firmware_candidate",
            "firmware_target_version",
            "firmware_upload_needed",
            "firmware_uploaded",
            "firmware_already_present",
            "firmware_reboot_sent",
            "firmware_error",
        ]
        _print_table(rows, headers)

    _run_async_command("firmware-update", operation)


@cli.command(
    "generate-script",
    short_help="Generate RouterOS remediation scripts for one IP or target set.",
    help="""Audit one device or the full target set and generate RouterOS
remediation scripts when devices match the script generator rules.

The generated file is written into the configured logs/scripts directory. If no
changes are needed, the command reports that no script was generated.
""",
)
@click.option(
    "--ip",
    metavar="ADDRESS",
    help="Target device IP address. If omitted, the full target set is processed.",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during script generation.",
)
def generate_script_command(ip: str | None, show_progress: bool) -> None:
    async def operation(app: AuditRunner) -> None:
        if ip:
            script = await app.generate_script_for_ip(ip)
            if script:
                click.echo(script)
                return

            click.echo("No remediation script was generated for this device.")
            return

        scripts = await app.generate_scripts_for_targets(show_progress=show_progress)
        failures = app.get_last_generate_script_failures()
        if scripts:
            click.echo("\n".join(scripts))
            click.echo("")
            click.echo(f"Generated scripts: {len(scripts)}")
            if failures:
                click.echo(f"Skipped targets: {len(failures)}")
                for failure in failures:
                    click.echo(f"- {failure}")
            return

        click.echo("No remediation scripts were generated for the current target set.")
        if failures:
            click.echo(f"Skipped targets: {len(failures)}")
            for failure in failures:
                click.echo(f"- {failure}")

    _run_async_command("generate-script", operation)


@cli.command(
    "backup-configs",
    short_help="Backup RouterOS configs from one device or the full target set.",
    help="""Collect RouterOS text exports over SSH and store them on disk.

When backup git mode is enabled, changed backups are also committed into the
configured local git repository, similar to Oxidized-style history tracking.
""",
)
@click.option(
    "--ip",
    metavar="ADDRESS",
    help="Target device IP address. If omitted, the full target set is processed.",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during config backup.",
)
def backup_configs_command(ip: str | None, show_progress: bool) -> None:
    async def operation(app: AuditRunner) -> None:
        if ip:
            result = await app.backup_config_for_ip(ip)
            click.echo(result.path)
            return

        paths = await app.backup_configs_for_targets(show_progress=show_progress)
        if paths:
            click.echo("\n".join(paths))
            click.echo("")
            click.echo(f"Backed up configs: {len(paths)}")
            return

        click.echo("No config backups were written for the current target set.")

    _run_async_command("backup-configs", operation)


def _run_phpipam_report(command_name: str, show_progress: bool) -> None:
    async def operation(app: AuditRunner) -> None:
        await app.run_phpipam_report_command(show_progress=show_progress)

    _run_async_command(command_name, operation)


@cli.command(
    "analyze-file",
    short_help="Analyze a RouterOS .rsc file offline.",
    help="""Analyze a single RouterOS export (.rsc) and optionally export results
to configured Excel/JSON writers via the existing pipeline.""",
)
@click.option(
    "--path",
    "path",
    required=True,
    metavar="FILE",
    help="Path to .rsc file to analyze.",
)
@click.option(
    "--export",
    "export_report",
    is_flag=True,
    help="Export the analysis result to Excel/JSON via the configured pipeline.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def analyze_file_command(path: str, export_report: bool, output_format: str) -> None:
    async def operation(app: AuditRunner) -> None:
        from app.analyzer import analyze_paths
        from app.report import to_json, to_markdown, build_sections_from_analysis
        import json as _json

        result = analyze_paths([path])

        if export_report:
            sections = build_sections_from_analysis(result)
            await app.export_custom_report(sections)

        if output_format == "json":
            _emit_json(_json.loads(to_json(result)))
            return
        click.echo(to_markdown(result))

    _run_async_command("analyze-file", operation)


@cli.command(
    "analyze-dir",
    short_help="Analyze all .rsc files in a directory.",
    help="""Scan a directory for .rsc files, analyze every match, and optionally
export combined results via the existing pipeline. By default the command scans
`logs/config-backup-history/configs` inside the application directory.
""",
)
@click.option(
    "--dir",
    "dirpath",
    required=False,
    metavar="DIR",
    help="Directory containing .rsc files (optional).",
)
@click.option(
    "--export",
    "export_report",
    is_flag=True,
    help="Export the analysis result to Excel/JSON via the configured pipeline.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def analyze_dir_command(dirpath: str, export_report: bool, output_format: str) -> None:
    async def operation(app: AuditRunner) -> None:
        from pathlib import Path
        from app.analyzer import analyze_paths
        from app.report import (
            to_json,
            to_markdown,
            build_sections_from_analyses,
        )
        import json as _json

        if dirpath:
            p = Path(dirpath)
        else:
            # default to logs/config-backup-history/configs within package
            p = Path(__file__).resolve().parent / "logs" / "config-backup-history" / "configs"

        files = sorted(p.rglob("*.rsc"), key=lambda p: str(p).lower())
        if not files:
            click.echo("No .rsc files found in directory")
            return

        results = [analyze_paths([str(path)]) for path in files]

        if export_report:
            sections = build_sections_from_analyses(results)
            await app.export_custom_report(sections)

        if output_format == "json":
            _emit_json([_json.loads(to_json(result)) for result in results])
            return

        for index, result in enumerate(results, start=1):
            if index > 1:
                click.echo("")
            click.echo(to_markdown(result))

    _run_async_command("analyze-dir", operation)


@cli.command(
    "topology",
    short_help="Collect an online topology snapshot from live MikroTik routers.",
    help="""Connect to one device or the full target set, collect live neighbor and uplink
information, infer topology links, and optionally export results through the configured
report pipeline.""",
)
@click.option(
    "--ip",
    required=False,
    metavar="ADDRESS",
    help="Target device IP address. If omitted, the full target set is scanned.",
)
@click.option(
    "--export",
    "export_report",
    is_flag=True,
    help="Export the topology results through the configured Excel/JSON writers.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during topology collection.",
)
def topology_command(
    ip: str | None,
    export_report: bool,
    output_format: str,
    show_progress: bool,
) -> None:
    async def operation(app: AuditRunner) -> None:
        from app.topology.report import to_json, to_markdown

        results = await app.run_topology_command(
            ip=ip,
            export=export_report,
            show_progress=show_progress,
        )
        all_links = [edge for result in results for edge in result.edges]

        if output_format == "json":
            _emit_json(json.loads(to_json(results, all_links)))
            return

        click.echo(to_markdown(results, all_links))

    _run_async_command("topology", operation)


@cli.command(
    "remediate",
    short_help="Plan or apply targeted non-critical fixes for one device.",
    help="""Build a targeted remediation plan for one device and optionally apply
the selected non-critical fixes.

The command is dry-run by default and writes a RouterOS script with the planned
changes into the configured remediation output directory. Pass --apply only
when live remediation is explicitly enabled in the configuration.
""",
)
@click.option(
    "--ip",
    required=True,
    metavar="ADDRESS",
    help="Target device IP address.",
)
@click.option(
    "--domain",
    "domains",
    type=RemediationDomain,
    multiple=True,
    help="Limit remediation to one or more domains: ntp, watchdog, scheduler.",
)
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Apply the generated commands over SSH instead of dry-run planning.",
)
@click.option(
    "--export",
    "export_report",
    is_flag=True,
    help="Export the remediation result to Excel/JSON/Google Sheets.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def remediate_command(
    ip: str,
    domains: tuple[str, ...],
    apply_changes: bool,
    export_report: bool,
    output_format: str,
) -> None:
    async def operation(app: AuditRunner) -> None:
        result = await app.remediate_device(
            ip=ip,
            domains=list(domains) if domains else None,
            apply=apply_changes,
        )
        payload = result.to_dict()

        if export_report:
            sections = _build_remediation_export_sections(payload)
            await app.export_custom_report(sections)

        if output_format == "json":
            _emit_json(payload)
            return

        _print_remediation_result(payload)

    _run_async_command("remediate", operation)


@cli.command(
    "radius-fix",
    short_help="Inspect and optionally fix RouterOS RADIUS settings on one device.",
    help="""Validate the configured RADIUS entry and AAA RADIUS state.
By default the command reports whether a fix is needed; pass --apply to execute the remediation.""",
)
@click.option(
    "--ip",
    required=True,
    metavar="ADDRESS",
    help="Target device IP address.",
)
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Apply the RADIUS fix over SSH instead of dry-run.",
)
@click.option(
    "--export",
    "export_report",
    is_flag=True,
    help="Export the RADIUS fix result to Excel/JSON.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def radius_fix_command(ip: str, apply_changes: bool, export_report: bool, output_format: str) -> None:
    async def operation(app: AuditRunner) -> None:
        payload = await app.fix_radius_for_ip(ip=ip, apply=apply_changes)
        if export_report:
            sections = {
                "radius_fix": (
                    [
                        "ip",
                        "identity",
                        "auth_method",
                        "dry_run",
                        "radius_fix_needed",
                        "radius_present_before",
                        "aaa_enabled_before",
                        "radius_present_after",
                        "aaa_present_after",
                        "radius_added",
                        "radius_recreated",
                        "aaa_enabled",
                    ],
                    _build_radius_fix_export_rows(payload),
                )
            }
            await app.export_custom_report(sections)

        if output_format == "json":
            _emit_json(payload)
            return
        _print_radius_fix_result(payload)

    _run_async_command("radius-fix", operation)


@cli.command(
    "scheduler-fix",
    short_help="Plan or apply scheduler remediation for one device.",
    help="""Build and optionally apply scheduler remediation commands for a single RouterOS device.
Use --apply to execute the planned scheduler changes.""",
)
@click.option(
    "--ip",
    required=True,
    metavar="ADDRESS",
    help="Target device IP address.",
)
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Apply the scheduler remediation over SSH instead of dry-run.",
)
@click.option(
    "--export",
    "export_report",
    is_flag=True,
    help="Export the scheduler fix result to Excel/JSON.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def scheduler_fix_command(ip: str, apply_changes: bool, export_report: bool, output_format: str) -> None:
    async def operation(app: AuditRunner) -> None:
        result = await app.remediate_device(
            ip=ip,
            domains=["scheduler"],
            apply=apply_changes,
        )
        payload = result.to_dict()

        if export_report:
            sections = {
                "scheduler_fix": (
                    [
                        "ip",
                        "identity",
                        "auth_method",
                        "dry_run",
                        "domain",
                        "compliant",
                        "command_count",
                        "applied",
                        "failed",
                        "details",
                    ],
                    _build_scheduler_fix_export_rows(payload),
                )
            }
            await app.export_custom_report(sections)

        if output_format == "json":
            _emit_json(payload)
            return
        _print_remediation_result(payload)

    _run_async_command("scheduler-fix", operation)


@cli.command(
    "ospf-create",
    short_help="Generate OSPF creation scripts for one device or the target set.",
    help="""Generate RouterOS OSPF configuration scripts based on inventory objects
and the current target or IP. If --ip is omitted, scripts are generated for the
resolved target set.""",
)
@click.option(
    "--ip",
    metavar="ADDRESS",
    help="Target device IP address. If omitted, all resolved targets are processed.",
)
@click.option(
    "--export",
    "export_report",
    is_flag=True,
    help="Export the OSPF creation result to Excel/JSON.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def ospf_create_command(ip: str | None, export_report: bool, output_format: str) -> None:
    async def operation(app: AuditRunner) -> None:
        if ip:
            path = await app.create_ospf_script_for_ip(ip)
            payload = [path] if path else []
        else:
            payload = await app.create_ospf_scripts_for_targets()

        if export_report:
            sections = {
                "ospf_create": (
                    ["ip", "generated", "script_path"],
                    _build_ospf_script_export_rows(payload, ip),
                )
            }
            await app.export_custom_report(sections)

        if output_format == "json":
            _emit_json(payload)
            return

        _print_ospf_script_result(payload)

    _run_async_command("ospf-create", operation)


@cli.command(
    "phpipam-report",
    short_help="Build a phpIPAM comparison report.",
    help="""Run the inventory audit, enrich results from phpIPAM cache, and
export a comparison report to the configured outputs.

This command is read-only relative to phpIPAM in the current implementation.
""",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during phpIPAM report generation.",
)
def phpipam_report_command(show_progress: bool) -> None:
    _run_phpipam_report("phpipam-report", show_progress)


@cli.command(
    "sync-phpipam",
    short_help="Legacy alias for phpipam-report.",
    help="""Legacy command name kept for backward compatibility.

It runs the same read-only phpIPAM comparison report as phpipam-report.
""",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during phpIPAM report generation.",
)
def sync_phpipam_command(show_progress: bool) -> None:
    _run_phpipam_report("sync-phpipam", show_progress)


@cli.command(
    "service",
    short_help="Run the audit tool as a foreground service or daemon loop.",
    help="""Run one of the existing audit workflows in a long-lived foreground
process suitable for systemd, supervisord, NSSM, or another service manager.

By default, the command uses the configured service settings from inventory or
environment. Pass --once for a single cycle, or override the action and
interval directly on the command line.
""",
)
@click.option(
    "--action",
    "service_action",
    type=ServiceAction,
    default=None,
    help="Workflow to run each cycle: audit, export, phpipam-report, generate-script.",
)
@click.option(
    "--interval",
    "interval_seconds",
    type=click.IntRange(min=1),
    default=None,
    help="Seconds to wait between cycles. Defaults to SERVICE_INTERVAL_SECONDS.",
)
@click.option(
    "--once",
    is_flag=True,
    help="Run exactly one cycle and exit.",
)
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during audit-style actions.",
)
def service_command(
    service_action: str | None,
    interval_seconds: int | None,
    once: bool,
    show_progress: bool,
) -> None:
    config = _load_app_config()
    action = service_action or config.service.action
    interval = interval_seconds or config.service.interval_seconds
    progress = show_progress

    async def operation(app: AuditRunner) -> None:
        app.logger.info(
            "Service mode starting action=%s interval_seconds=%s once=%s progress=%s",
            action,
            interval,
            once,
            progress,
        )
        await app.run_service_loop(
            action=action,
            interval_seconds=interval,
            once=once,
            show_progress=progress,
        )

    try:
        _run_async_command("service", operation)
    except KeyboardInterrupt:
        click.echo("Service interrupted. Shutting down cleanly.")


@cli.command(
    "targets",
    short_help="Show resolved target IP addresses.",
    help="""Resolve target IPs from the configured inventory file and print them.

Use --stats-only for a short summary or --format json for machine-readable
output.
""",
)
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=20,
    show_default=True,
    help="How many IPs to print in text mode.",
)
@click.option(
    "--stats-only",
    is_flag=True,
    help="Print only inventory statistics instead of individual IPs.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def targets_command(limit: int, stats_only: bool, output_format: str) -> None:
    config = _load_app_config()
    ips = _resolve_target_ips(config)

    payload = {
        "inventory_file": config.inventory_file,
        "inventory_path": str(config.inventory_path.resolve()),
        "exclude_gateways": config.exclude_gateways,
        "count": len(ips),
        "ips": ips if not stats_only else [],
    }

    if output_format == "json":
        if not stats_only and limit < len(ips):
            payload["ips"] = ips[:limit]
            payload["truncated"] = True
        _emit_json(payload)
        return

    _print_section("Target Inventory")
    _print_key_value("inventory_file", config.inventory_file)
    _print_key_value("inventory_path", config.inventory_path.resolve())
    _print_key_value("exclude_gateways", config.exclude_gateways)
    _print_key_value("count", len(ips))

    if stats_only:
        return

    click.echo("")
    _print_section("Resolved IPs")
    for ip in ips[:limit]:
        click.echo(f"  {ip}")

    if limit < len(ips):
        click.echo(f"  ... truncated, showing {limit} of {len(ips)}")


@cli.command(
    "config",
    short_help="Show the effective runtime configuration.",
    help="""Print the effective application configuration loaded from the
environment.

Secrets are redacted by default. Pass --show-secrets only when you explicitly
want to inspect the raw values in a safe local environment.
""",
)
@click.option(
    "--show-secrets",
    is_flag=True,
    help="Show raw secret values instead of redacting them.",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def config_command(show_secrets: bool, output_format: str) -> None:
    config = _load_app_config()
    snapshot = _build_config_snapshot(config, show_secrets=show_secrets)

    if output_format == "json":
        _emit_json(snapshot)
        return

    _print_section("Core")
    for key in (
        "log_level",
        "log_console_level",
        "log_file_level",
        "log_dir",
        "log_file",
        "error_log_file",
        "inventory_file",
        "inventory_path",
        "secrets_file",
        "secrets_path",
        "output_xlsx",
        "output_json",
        "workers",
        "ssh_port",
        "timeout",
        "auth_timeout",
        "banner_timeout",
        "command_timeout",
        "ping_timeout",
        "ping_count",
        "max_targets",
        "test_mode",
        "test_limit",
        "exclude_gateways",
        "prefer_devices_over_networks",
    ):
        _print_key_value(key, snapshot[key])

    click.echo("")
    _print_section("Credentials")
    for key in (
        "username",
        "password",
        "fallback_username",
        "fallback_password",
        "firmware_username",
        "firmware_password",
    ):
        _print_key_value(key, snapshot[key])

    click.echo("")
    _print_section("Firmware")
    for key in (
        "firmware_dir",
        "auto_upload_mmips",
        "auto_reboot_after_upload",
        "only_if_version_diff",
    ):
        _print_key_value(key, snapshot[key])

    click.echo("")
    _print_section("RADIUS")
    for key in ("radius_addr", "radius_secret", "radius_service"):
        _print_key_value(key, snapshot[key])

    click.echo("")
    _print_section("phpIPAM")
    for key, value in snapshot["phpipam"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Google")
    for key, value in snapshot["google"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Audit")
    for key, value in snapshot["audit"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Compliance")
    for key, value in snapshot["compliance"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Remediation")
    for key, value in snapshot["remediation"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Report")
    for key, value in snapshot["report"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Runtime")
    for key, value in snapshot["runtime"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("NTP")
    for key, value in snapshot["ntp"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Scheduler")
    for key, value in snapshot["scheduler"].items():
        _print_key_value(key, value)

    click.echo("")
    _print_section("Watchdog")
    for key, value in snapshot["watchdog"].items():
        _print_key_value(key, value)


@cli.command(
    "doctor",
    short_help="Validate files, credentials, and integration settings.",
    help="""Run quick validation checks for the local environment.

The command verifies the inventory file, key credentials, firmware directory,
and optional integration settings for phpIPAM and Google Sheets. It exits with
code 1 when critical issues are found.
""",
)
@click.option(
    "--format",
    "output_format",
    type=OutputFormat,
    default="text",
    show_default=True,
    help="Output format.",
)
def doctor_command(output_format: str) -> None:
    payload, exit_code = _run_doctor_checks()

    if output_format == "json":
        _emit_json(payload)
    else:
        _print_doctor_summary(payload)

    if exit_code:
        raise click.exceptions.Exit(1)



def main() -> None:
    cli()
