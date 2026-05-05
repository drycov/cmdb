from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

if TYPE_CHECKING:
    from config import AppConfig
    from runner import AuditRunner


CommandOperation = Callable[["AuditRunner"], Awaitable[None]]
OutputFormat = click.Choice(["text", "json"], case_sensitive=False)

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


async def _run_with_app(command_name: str, operation: CommandOperation) -> None:
    from bootstrap import build_app
    from logging_setup import shutdown_logging

    app = build_app()
    app.logger.info("Application started command=%s", command_name)

    try:
        await operation(app)
    finally:
        try:
            await app.shutdown()
            app.logger.info("Application finished command=%s", command_name)
        finally:
            shutdown_logging(app.logger)


def _run_async_command(command_name: str, operation: CommandOperation) -> None:
    asyncio.run(_run_with_app(command_name, operation))


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
    snapshot["phpipam"] = dict(snapshot["phpipam"])
    snapshot["google"] = dict(snapshot["google"])

    snapshot["password"] = _redact(config.password, show_secrets)
    snapshot["fallback_password"] = _redact(config.fallback_password, show_secrets)
    snapshot["firmware_password"] = _redact(config.firmware_password, show_secrets)
    snapshot["radius_secret"] = _redact(config.radius_secret, show_secrets)
    snapshot["phpipam"]["password"] = _redact(config.phpipam.password, show_secrets)

    return snapshot


def _emit_json(payload: Any) -> None:
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))


def _print_section(title: str) -> None:
    click.echo(title)


def _print_key_value(key: str, value: Any) -> None:
    click.echo(f"  {key}: {value}")


def _print_targets_summary(limit: int = 20) -> None:
    from config import AppConfig
    from domain.targets import TargetProvider

    config = AppConfig.from_env()
    ips = TargetProvider(config).get_target_ips()

    _print_section("Target Inventory")
    _print_key_value("inventory_file", config.inventory_file)
    _print_key_value("inventory_path", config.inventory_path.resolve())
    _print_key_value("exclude_gateways", config.exclude_gateways)
    _print_key_value("count", len(ips))

    click.echo("")
    _print_section("Resolved IPs")
    for ip in ips[:limit]:
        click.echo(f"  {ip}")

    if limit < len(ips):
        click.echo(f"  ... truncated, showing {limit} of {len(ips)}")


def _print_config_summary(show_secrets: bool = False) -> None:
    from config import AppConfig

    config = AppConfig.from_env()
    snapshot = _build_config_snapshot(config, show_secrets=show_secrets)

    _print_section("Core")
    for key in (
        "log_level",
        "log_console_level",
        "log_file_level",
        "inventory_file",
        "inventory_path",
        "output_xlsx",
        "workers",
        "ssh_port",
        "timeout",
        "banner_timeout",
        "test_mode",
    ):
        _print_key_value(key, snapshot[key])

    click.echo("")
    _print_section("Integrations")
    _print_key_value("phpipam_enabled", snapshot["phpipam"]["enabled"])
    _print_key_value("google_enabled", snapshot["google"]["enabled"])


def _run_doctor_checks() -> tuple[dict[str, Any], int]:
    from config import AppConfig

    config = AppConfig.from_env()
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
def audit_command(ip: str | None, no_export: bool) -> None:
    async def operation(app: AuditRunner) -> None:
        if ip:
            await app.run_single_audit_command(ip, export=not no_export)
            return

        await app.run_audit_command()

    _run_async_command("audit", operation)


@cli.command(
    "export",
    short_help="Run the full audit and export results.",
    help="""Run the full audit and write the configured Excel/JSON outputs.

This command currently behaves like a full inventory audit followed by export.
It does not read previously cached results from disk.
""",
)
def export_command() -> None:
    async def operation(app: AuditRunner) -> None:
        await app.run_export_command()

    _run_async_command("export", operation)


@cli.command(
    "generate-script",
    short_help="Generate a RouterOS remediation script for one IP.",
    help="""Audit one device and generate a RouterOS remediation script when the
device matches the script generator rules.

The generated file is written into the configured logs/scripts directory. If no
changes are needed, the command reports that no script was generated.
""",
)
@click.option(
    "--ip",
    required=True,
    metavar="ADDRESS",
    help="Target device IP address.",
)
def generate_script_command(ip: str) -> None:
    async def operation(app: AuditRunner) -> None:
        script = await app.generate_script_for_ip(ip)
        if script:
            click.echo(script)
            return

        click.echo("No remediation script was generated for this device.")

    _run_async_command("generate-script", operation)


def _run_phpipam_report(command_name: str) -> None:
    async def operation(app: AuditRunner) -> None:
        await app.run_phpipam_report_command()

    _run_async_command(command_name, operation)


@cli.command(
    "phpipam-report",
    short_help="Build a phpIPAM comparison report.",
    help="""Run the inventory audit, enrich results from phpIPAM cache, and
export a comparison report to the configured outputs.

This command is read-only relative to phpIPAM in the current implementation.
""",
)
def phpipam_report_command() -> None:
    _run_phpipam_report("phpipam-report")


@cli.command(
    "sync-phpipam",
    short_help="Legacy alias for phpipam-report.",
    help="""Legacy command name kept for backward compatibility.

It runs the same read-only phpIPAM comparison report as phpipam-report.
""",
)
def sync_phpipam_command() -> None:
    _run_phpipam_report("sync-phpipam")


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
    from config import AppConfig
    from domain.targets import TargetProvider

    config = AppConfig.from_env()
    ips = TargetProvider(config).get_target_ips()

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
    from config import AppConfig

    config = AppConfig.from_env()
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
        "output_xlsx",
        "workers",
        "ssh_port",
        "timeout",
        "banner_timeout",
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


@cli.command(
    "interactive",
    short_help="Launch interactive terminal UI.",
    help="""Launch an interactive text UI based on npyscreen.

The form lets you choose a command, optionally provide a target IP, and then
executes the selected action using the existing application workflow.
""",
)
def interactive_command() -> None:
    try:
        from interactive_ui import run_interactive_ui
    except ImportError as exc:
        raise click.ClickException(
            "npyscreen is not installed. Install dependencies from reqqurements.txt."
        ) from exc

    selection = run_interactive_ui()
    action = selection.get("action", "quit")

    if action == "quit":
        click.echo("Interactive mode finished.")
        return

    if action == "audit_full":
        _run_async_command(
            "interactive-audit",
            lambda app: app.run_audit_command(),
        )
        return

    if action == "audit_single":
        ip = str(selection.get("ip", "")).strip()
        export = bool(selection.get("export", True))
        _run_async_command(
            "interactive-audit-single",
            lambda app, ip=ip, export=export: app.run_single_audit_command(
                ip,
                export=export,
            ),
        )
        return

    if action == "generate_script":
        ip = str(selection.get("ip", "")).strip()

        async def operation(app: AuditRunner) -> None:
            script = await app.generate_script_for_ip(ip)
            if script:
                click.echo(script)
            else:
                click.echo("No remediation script was generated for this device.")

        _run_async_command("interactive-generate-script", operation)
        return

    if action == "phpipam_report":
        _run_async_command(
            "interactive-phpipam-report",
            lambda app: app.run_phpipam_report_command(),
        )
        return

    if action == "targets":
        _print_targets_summary()
        return

    if action == "config":
        _print_config_summary()
        return

    if action == "doctor":
        payload, exit_code = _run_doctor_checks()
        _print_doctor_summary(payload)
        if exit_code:
            raise click.exceptions.Exit(exit_code)
        return

    raise click.ClickException(f"Unsupported interactive action: {action}")


def main() -> None:
    cli()
