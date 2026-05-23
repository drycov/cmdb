"""Implementation details for cli_support inspection."""

from __future__ import annotations

from pathlib import Path

import click

from mikrotik_audit.cli_support.common import load_app_config, resolve_target_ips
from mikrotik_audit.cli_support.formatters import (
    build_config_snapshot,
    emit_json,
    print_config_snapshot,
    print_doctor_summary,
    print_key_value,
    print_section,
)


def run_targets_command(limit: int, stats_only: bool, output_format: str) -> None:
    """Run targets command."""
    config = load_app_config()
    ips = resolve_target_ips(config)

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
        emit_json(payload)
        return

    print_section("Target Inventory")
    print_key_value("inventory_file", config.inventory_file)
    print_key_value("inventory_path", config.inventory_path.resolve())
    print_key_value("exclude_gateways", config.exclude_gateways)
    print_key_value("count", len(ips))

    if stats_only:
        return

    click.echo("")
    print_section("Resolved IPs")
    for ip in ips[:limit]:
        click.echo(f"  {ip}")

    if limit < len(ips):
        click.echo(f"  ... truncated, showing {limit} of {len(ips)}")


def run_config_command(show_secrets: bool, output_format: str) -> None:
    """Run config command."""
    config = load_app_config()
    snapshot = build_config_snapshot(config, show_secrets=show_secrets)

    if output_format == "json":
        emit_json(snapshot)
        return

    print_config_snapshot(snapshot)


def run_doctor_command(output_format: str) -> None:
    """Run doctor command."""
    payload, exit_code = _run_doctor_checks()

    if output_format == "json":
        emit_json(payload)
    else:
        print_doctor_summary(payload)

    if exit_code:
        raise click.exceptions.Exit(1)


def _run_doctor_checks() -> tuple[dict[str, object], int]:
    """Internal helper for run doctor checks."""
    config = load_app_config()
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

    credential_chain = list(config.mikrotik_credentials)
    primary_credentials_ok = bool(credential_chain and credential_chain[0].is_valid)
    add_check(
        "primary_credentials",
        primary_credentials_ok,
        f"user={(credential_chain[0].username if credential_chain else '<empty>')}",
    )
    if not primary_credentials_ok:
        warnings.append("Primary MikroTik credentials are incomplete")

    fallback_credentials_ok = all(cred.is_valid for cred in credential_chain[1:])
    fallback_detail = (
        ", ".join(cred.username or "<empty>" for cred in credential_chain[1:])
        if len(credential_chain) > 1
        else "<none>"
    )
    add_check(
        "fallback_credentials",
        fallback_credentials_ok,
        f"count={max(0, len(credential_chain) - 1)} users={fallback_detail}",
    )
    if len(credential_chain) > 1 and not fallback_credentials_ok:
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
        checks.append({"name": "config_validation", "status": "ok", "detail": "validated"})
    except RuntimeError as exc:
        checks.append({"name": "config_validation", "status": "fail", "detail": "invalid"})
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
    return payload, 1 if errors else 0
