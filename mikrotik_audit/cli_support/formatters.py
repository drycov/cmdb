"""Implementation details for cli_support formatters."""

from __future__ import annotations

import contextlib
import io
import json
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

if TYPE_CHECKING:
    from config import AppConfig


def redact(value: str, show_secrets: bool) -> str:
    """Handle redact."""
    if show_secrets:
        return value
    if not value:
        return ""
    return "***"


def build_config_snapshot(
    config: "AppConfig",
    *,
    show_secrets: bool,
) -> dict[str, Any]:
    """Build config snapshot."""
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

    snapshot["password"] = redact(config.password, show_secrets)
    snapshot["firmware_password"] = redact(config.firmware_password, show_secrets)
    snapshot["radius_secret"] = redact(config.radius_secret, show_secrets)
    snapshot["phpipam"]["password"] = redact(config.phpipam.password, show_secrets)
    snapshot["mikrotik_credentials"] = [
        {
            "name": cred.name or ("primary" if index == 0 else f"fallback_{index}"),
            "username": cred.username,
            "password": redact(cred.password, show_secrets),
        }
        for index, cred in enumerate(config.mikrotik_credentials)
    ]
    snapshot["mikrotik_fallback_count"] = max(0, len(snapshot["mikrotik_credentials"]) - 1)
    return snapshot


def emit_json(payload: Any) -> None:
    """Emit json."""
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))


def format_table(rows: list[dict[str, Any]], headers: list[str]) -> str:
    """Handle format table."""
    if not rows:
        return ""

    column_widths: dict[str, int] = {header: len(header) for header in headers}
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


def print_table(rows: list[dict[str, Any]], headers: list[str]) -> None:
    """Print table."""
    table = format_table(rows, headers)
    if table:
        click.echo(table)


def capture_text_output(renderer) -> str:
    """Handle capture text output."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        renderer()
    text = buffer.getvalue().strip()
    return text or "<no output>"


def print_section(title: str) -> None:
    """Print section."""
    click.echo(title)


def print_key_value(key: str, value: Any) -> None:
    """Print key value."""
    click.echo(f"- {key}: {value}")


def print_credentials_chain(credentials: list[dict[str, Any]]) -> None:
    """Print credentials chain."""
    if not credentials:
        print_key_value("mikrotik_credentials", "<none>")
        return

    click.echo("- mikrotik_credentials:")
    for item in credentials:
        click.echo(
            "  - "
            + f"{item.get('name', '')}: "
            + f"{item.get('username', '<empty>')} / {item.get('password', '')}"
        )


def print_remediation_result(payload: dict[str, Any]) -> None:
    """Print remediation result."""
    print_section("Targeted Remediation")
    print_key_value("ip", payload.get("ip", ""))
    print_key_value("identity", payload.get("identity", ""))
    print_key_value("auth_method", payload.get("auth_method", ""))
    print_key_value("dry_run", payload.get("dry_run", True))
    print_key_value("has_changes", payload.get("has_changes", False))
    print_key_value("command_count", payload.get("command_count", 0))
    if payload.get("script_path"):
        print_key_value("script_path", payload.get("script_path"))

    click.echo("")
    print_section("Domains")
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


def print_radius_fix_result(payload: dict[str, Any]) -> None:
    """Print radius fix result."""
    print_section("RADIUS Fix")
    for key in (
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
    ):
        print_key_value(key, payload.get(key, False if key not in {"ip", "identity", "auth_method"} else ""))


def print_ospf_script_result(paths: list[str]) -> None:
    """Print ospf script result."""
    print_section("OSPF Creation")
    if not paths:
        click.echo("No OSPF scripts were generated.")
        return
    print_key_value("generated_scripts", len(paths))
    for path in paths:
        click.echo(f"- {path}")


def build_radius_fix_export_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Build radius fix export rows."""
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


def build_scheduler_fix_export_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Build scheduler fix export rows."""
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


def build_remediation_export_sections(payload: dict[str, Any]) -> dict[str, tuple[list[str], list[dict[str, Any]]]]:
    """Build remediation export sections."""
    summary_headers = ["ip", "identity", "auth_method", "dry_run", "script_path", "command_count", "has_changes"]
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

    domain_headers = ["ip", "identity", "auth_method", "domain", "compliant", "applied", "failed", "details", "command_count"]
    domain_rows: list[dict[str, Any]] = []
    command_headers = ["ip", "identity", "auth_method", "domain", "command_index", "command"]
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


def build_ospf_script_export_rows(paths: list[str], ip: str | None = None) -> list[dict[str, Any]]:
    """Build ospf script export rows."""
    if not paths:
        return [{"ip": ip or "", "generated": False, "script_path": ""}]

    rows: list[dict[str, Any]] = []
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


def print_config_snapshot(snapshot: dict[str, Any]) -> None:
    """Print config snapshot."""
    print_section("Core")
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
        print_key_value(key, snapshot[key])

    click.echo("")
    print_section("Credentials")
    for key in ("username", "password", "firmware_username", "firmware_password"):
        print_key_value(key, snapshot[key])
    print_key_value("mikrotik_fallback_count", snapshot["mikrotik_fallback_count"])
    print_credentials_chain(snapshot["mikrotik_credentials"])

    for section_name in ("Firmware", "RADIUS", "phpIPAM", "Google", "Audit", "Compliance", "Remediation", "Report", "Runtime", "NTP", "Scheduler", "Watchdog"):
        click.echo("")
        print_section(section_name)
        source_key = section_name.lower() if section_name not in {"RADIUS", "phpIPAM", "NTP", "Watchdog"} else {
            "RADIUS": None,
            "phpIPAM": "phpipam",
            "NTP": "ntp",
            "Watchdog": "watchdog",
        }.get(section_name)
        if section_name == "Firmware":
            for key in ("firmware_dir", "auto_upload_mmips", "auto_reboot_after_upload", "only_if_version_diff"):
                print_key_value(key, snapshot[key])
        elif section_name == "RADIUS":
            for key in ("radius_addr", "radius_secret", "radius_service"):
                print_key_value(key, snapshot[key])
        else:
            for key, value in snapshot[(source_key or section_name.lower())].items():
                print_key_value(key, value)


def print_doctor_summary(payload: dict[str, Any]) -> None:
    """Print doctor summary."""
    print_section("Doctor")
    for item in payload["checks"]:
        click.echo(f"  [{item['status']}] {item['name']}: {item['detail']}")

    if payload["warnings"]:
        click.echo("")
        print_section("Warnings")
        for warning in payload["warnings"]:
            click.echo(f"  - {warning}")

    if payload["errors"]:
        click.echo("")
        print_section("Errors")
        for error in payload["errors"]:
            click.echo(f"  - {error}")
