"""Human-facing command-line interface for the MikroTik audit toolkit.

The CLI stays intentionally thin: commands validate user intent, call the
runtime facade, and present results in a friendly format. Most business logic
belongs in the application layer so the same workflows remain reusable from
the API and future automations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from mikrotik_audit.cli_support.analysis import (
    run_analyze_dir_command,
    run_analyze_file_command,
    run_topology_command,
)
from mikrotik_audit.cli_support.common import (
    OutputFormat,
    RemediationDomain,
    ServiceAction,
    load_app_config,
    run_async_command,
)
from mikrotik_audit.cli_support.formatters import (
    build_ospf_script_export_rows,
    build_radius_fix_export_rows,
    build_remediation_export_sections,
    build_scheduler_fix_export_rows,
    emit_json,
    print_ospf_script_result,
    print_radius_fix_result,
    print_remediation_result,
    print_table,
)
from mikrotik_audit.cli_support.inspection import (
    run_config_command,
    run_doctor_command,
    run_targets_command,
)

if TYPE_CHECKING:
    from mikrotik_audit.runner import AuditRunner


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
    """Register the top-level Click command group for all audit workflows."""
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
@click.option("--ip", metavar="ADDRESS", help="Audit exactly one device instead of the whole inventory.")
@click.option("--no-export", is_flag=True, help="Skip Excel/JSON export for a single-device audit.")
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during audit.",
)
def audit_command(ip: str | None, no_export: bool, show_progress: bool) -> None:
    """Run either a single-device audit or the full inventory audit workflow."""
    async def operation(app: "AuditRunner") -> None:
        if ip:
            await app.run_single_audit_command(ip, export=not no_export)
            return
        await app.run_audit_command(show_progress=show_progress)

    run_async_command("audit", operation)


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
    """Run the export workflow that currently maps to a full audit pass."""
    async def operation(app: "AuditRunner") -> None:
        await app.run_export_command(show_progress=show_progress)

    run_async_command("export", operation)


@cli.command(
    "firmware-update",
    short_help="Upload firmware to one device or the full inventory.",
    help="""Upload RouterOS firmware from the configured firmware directory for one
device or the full target set. The command prints results as a table or JSON.
""",
)
@click.option("--ip", metavar="ADDRESS", help="Target device IP address. If omitted, the full target set is processed.")
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during firmware upload.",
)
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def firmware_update_command(ip: str | None, show_progress: bool, output_format: str) -> None:
    """Upload firmware to one device or the resolved target set and render the result."""
    async def operation(app: "AuditRunner") -> None:
        rows = [await app.upload_firmware_for_ip(ip)] if ip else await app.upload_firmware_for_targets(show_progress=show_progress)
        if output_format.lower() == "json":
            emit_json(rows)
            return
        print_table(
            rows,
            [
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
            ],
        )

    run_async_command("firmware-update", operation)


@cli.command(
    "generate-script",
    short_help="Generate RouterOS remediation scripts for one IP or target set.",
    help="""Audit one device or the full target set and generate RouterOS
remediation scripts when devices match the script generator rules.

The generated file is written into the configured logs/scripts directory. If no
changes are needed, the command reports that no script was generated.
""",
)
@click.option("--ip", metavar="ADDRESS", help="Target device IP address. If omitted, the full target set is processed.")
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during script generation.",
)
def generate_script_command(ip: str | None, show_progress: bool) -> None:
    """Generate remediation scripts for one device or the full target set."""
    async def operation(app: "AuditRunner") -> None:
        if ip:
            script = await app.generate_script_for_ip(ip)
            click.echo(script or "No remediation script was generated for this device.")
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

    run_async_command("generate-script", operation)


@cli.command(
    "backup-configs",
    short_help="Backup RouterOS configs from one device or the full target set.",
    help="""Collect RouterOS text exports over SSH and store them on disk.

When backup git mode is enabled, changed backups are also committed into the
configured local git repository, similar to Oxidized-style history tracking.
""",
)
@click.option("--ip", metavar="ADDRESS", help="Target device IP address. If omitted, the full target set is processed.")
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during config backup.",
)
def backup_configs_command(ip: str | None, show_progress: bool) -> None:
    """Back up RouterOS configs and print the written artifact paths."""
    async def operation(app: "AuditRunner") -> None:
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

    run_async_command("backup-configs", operation)


def _run_phpipam_report(command_name: str, show_progress: bool) -> None:
    """Run the shared phpIPAM comparison workflow for current and legacy aliases."""
    async def operation(app: "AuditRunner") -> None:
        await app.run_phpipam_report_command(show_progress=show_progress)

    run_async_command(command_name, operation)


@cli.command(
    "analyze-file",
    short_help="Analyze a RouterOS .rsc file offline.",
    help="""Analyze a single RouterOS export (.rsc) and optionally export results
to configured Excel/JSON writers via the existing pipeline.""",
)
@click.option("--path", "path", required=True, metavar="FILE", help="Path to .rsc file to analyze.")
@click.option("--export", "export_report", is_flag=True, help="Export the analysis result to Excel/JSON via the configured pipeline.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def analyze_file_command(path: str, export_report: bool, output_format: str) -> None:
    """Analyze one RouterOS export file without contacting live devices."""
    run_analyze_file_command(path, export_report, output_format)


@cli.command(
    "analyze-dir",
    short_help="Analyze all .rsc files in a directory.",
    help="""Scan a directory for .rsc files, analyze every match, and optionally
export combined results via the existing pipeline. By default the command scans
`logs/config-backup-history/configs` inside the application directory.
""",
)
@click.option("--dir", "dirpath", required=False, metavar="DIR", help="Directory containing .rsc files (optional).")
@click.option("--export", "export_report", is_flag=True, help="Export the analysis result to Excel/JSON via the configured pipeline.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def analyze_dir_command(dirpath: str | None, export_report: bool, output_format: str) -> None:
    """Analyze every matching RouterOS export file in a directory tree."""
    run_analyze_dir_command(dirpath, export_report, output_format)


@cli.command(
    "topology",
    short_help="Collect an online topology snapshot from live MikroTik routers.",
    help="""Connect to one device or the full target set, collect live neighbor and uplink
information, infer topology links, and optionally export results through the configured
report pipeline.""",
)
@click.option("--ip", required=False, metavar="ADDRESS", help="Target device IP address. If omitted, the full target set is scanned.")
@click.option("--export", "export_report", is_flag=True, help="Export the topology results through the configured Excel/JSON writers.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
@click.option(
    "--progress/--no-progress",
    "show_progress",
    default=True,
    help="Show or suppress the tqdm progress bar during topology collection.",
)
def topology_command(ip: str | None, export_report: bool, output_format: str, show_progress: bool) -> None:
    """Collect a live topology snapshot and render or export the result."""
    run_topology_command(ip, export_report, output_format, show_progress)


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
@click.option("--ip", required=True, metavar="ADDRESS", help="Target device IP address.")
@click.option("--domain", "domains", type=RemediationDomain, multiple=True, help="Limit remediation to one or more domains: ntp, watchdog, scheduler.")
@click.option("--apply", "apply_changes", is_flag=True, help="Apply the generated commands over SSH instead of dry-run planning.")
@click.option("--export", "export_report", is_flag=True, help="Export the remediation result to Excel/JSON/Google Sheets.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def remediate_command(ip: str, domains: tuple[str, ...], apply_changes: bool, export_report: bool, output_format: str) -> None:
    """Plan or apply targeted non-critical remediation for one device."""
    async def operation(app: "AuditRunner") -> None:
        result = await app.remediate_device(ip=ip, domains=list(domains) if domains else None, apply=apply_changes)
        payload = result.to_dict()
        if export_report:
            await app.export_custom_report(build_remediation_export_sections(payload))
        if output_format == "json":
            emit_json(payload)
            return
        print_remediation_result(payload)

    run_async_command("remediate", operation)


@cli.command(
    "radius-fix",
    short_help="Inspect and optionally fix RouterOS RADIUS settings on one device.",
    help="""Validate the configured RADIUS entry and AAA RADIUS state.
By default the command reports whether a fix is needed; pass --apply to execute the remediation.""",
)
@click.option("--ip", required=True, metavar="ADDRESS", help="Target device IP address.")
@click.option("--apply", "apply_changes", is_flag=True, help="Apply the RADIUS fix over SSH instead of dry-run.")
@click.option("--export", "export_report", is_flag=True, help="Export the RADIUS fix result to Excel/JSON.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def radius_fix_command(ip: str, apply_changes: bool, export_report: bool, output_format: str) -> None:
    """Inspect and optionally fix the RADIUS configuration for one device."""
    async def operation(app: "AuditRunner") -> None:
        payload = await app.fix_radius_for_ip(ip=ip, apply=apply_changes)
        if export_report:
            await app.export_custom_report(
                {
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
                        build_radius_fix_export_rows(payload),
                    )
                }
            )
        if output_format == "json":
            emit_json(payload)
            return
        print_radius_fix_result(payload)

    run_async_command("radius-fix", operation)


@cli.command(
    "scheduler-fix",
    short_help="Plan or apply scheduler remediation for one device.",
    help="""Build and optionally apply scheduler remediation commands for a single RouterOS device.
Use --apply to execute the planned scheduler changes.""",
)
@click.option("--ip", required=True, metavar="ADDRESS", help="Target device IP address.")
@click.option("--apply", "apply_changes", is_flag=True, help="Apply the scheduler remediation over SSH instead of dry-run.")
@click.option("--export", "export_report", is_flag=True, help="Export the scheduler fix result to Excel/JSON.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def scheduler_fix_command(ip: str, apply_changes: bool, export_report: bool, output_format: str) -> None:
    """Plan or apply scheduler remediation for one RouterOS device."""
    async def operation(app: "AuditRunner") -> None:
        result = await app.remediate_device(ip=ip, domains=["scheduler"], apply=apply_changes)
        payload = result.to_dict()
        if export_report:
            await app.export_custom_report(
                {
                    "scheduler_fix": (
                        ["ip", "identity", "auth_method", "dry_run", "domain", "compliant", "command_count", "applied", "failed", "details"],
                        build_scheduler_fix_export_rows(payload),
                    )
                }
            )
        if output_format == "json":
            emit_json(payload)
            return
        print_remediation_result(payload)

    run_async_command("scheduler-fix", operation)


@cli.command(
    "ospf-create",
    short_help="Generate OSPF creation scripts for one device or the target set.",
    help="""Generate RouterOS OSPF configuration scripts based on inventory objects
and the current target or IP. If --ip is omitted, scripts are generated for the
resolved target set.""",
)
@click.option("--ip", metavar="ADDRESS", help="Target device IP address. If omitted, all resolved targets are processed.")
@click.option("--export", "export_report", is_flag=True, help="Export the OSPF creation result to Excel/JSON.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def ospf_create_command(ip: str | None, export_report: bool, output_format: str) -> None:
    """Generate OSPF creation scripts from inventory and current device data."""
    async def operation(app: "AuditRunner") -> None:
        payload = [await app.create_ospf_script_for_ip(ip)] if ip else await app.create_ospf_scripts_for_targets()
        payload = [item for item in payload if item]
        if export_report:
            await app.export_custom_report(
                {
                    "ospf_create": (
                        ["ip", "generated", "script_path"],
                        build_ospf_script_export_rows(payload, ip),
                    )
                }
            )
        if output_format == "json":
            emit_json(payload)
            return
        print_ospf_script_result(payload)

    run_async_command("ospf-create", operation)


@cli.command(
    "phpipam-report",
    short_help="Build a phpIPAM comparison report.",
    help="""Run the inventory audit, enrich results from phpIPAM cache, and
export a comparison report to the configured outputs.

This command is read-only relative to phpIPAM in the current implementation.
""",
)
@click.option("--progress/--no-progress", "show_progress", default=True, help="Show or suppress the tqdm progress bar during phpIPAM report generation.")
def phpipam_report_command(show_progress: bool) -> None:
    """Build the phpIPAM comparison report using the shared runtime workflow."""
    _run_phpipam_report("phpipam-report", show_progress)


@cli.command(
    "sync-phpipam",
    short_help="Legacy alias for phpipam-report.",
    help="""Legacy command name kept for backward compatibility.

It runs the same read-only phpIPAM comparison report as phpipam-report.
""",
)
@click.option("--progress/--no-progress", "show_progress", default=True, help="Show or suppress the tqdm progress bar during phpIPAM report generation.")
def sync_phpipam_command(show_progress: bool) -> None:
    """Provide the legacy phpIPAM command name without duplicating behavior."""
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
@click.option("--action", "service_action", type=ServiceAction, default=None, help="Workflow to run each cycle: audit, export, phpipam-report, generate-script.")
@click.option("--interval", "interval_seconds", type=click.IntRange(min=1), default=None, help="Seconds to wait between cycles. Defaults to SERVICE_INTERVAL_SECONDS.")
@click.option("--once", is_flag=True, help="Run exactly one cycle and exit.")
@click.option("--progress/--no-progress", "show_progress", default=True, help="Show or suppress the tqdm progress bar during audit-style actions.")
def service_command(service_action: str | None, interval_seconds: int | None, once: bool, show_progress: bool) -> None:
    """Run one of the audit workflows in a foreground service loop."""
    config = load_app_config()
    action = service_action or config.service.action
    interval = interval_seconds or config.service.interval_seconds

    async def operation(app: "AuditRunner") -> None:
        app.logger.info(
            "Service mode starting action=%s interval_seconds=%s once=%s progress=%s",
            action,
            interval,
            once,
            show_progress,
        )
        await app.run_service_loop(
            action=action,
            interval_seconds=interval,
            once=once,
            show_progress=show_progress,
        )

    try:
        run_async_command("service", operation)
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
@click.option("--limit", type=click.IntRange(min=1), default=20, show_default=True, help="How many IPs to print in text mode.")
@click.option("--stats-only", is_flag=True, help="Print only inventory statistics instead of individual IPs.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def targets_command(limit: int, stats_only: bool, output_format: str) -> None:
    """Print resolved target IPs or inventory statistics for operator review."""
    run_targets_command(limit, stats_only, output_format)


@cli.command(
    "config",
    short_help="Show the effective runtime configuration.",
    help="""Print the effective application configuration loaded from the
environment.

Secrets are redacted by default. Pass --show-secrets only when you explicitly
want to inspect the raw values in a safe local environment.
""",
)
@click.option("--show-secrets", is_flag=True, help="Show raw secret values instead of redacting them.")
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def config_command(show_secrets: bool, output_format: str) -> None:
    """Show the effective runtime configuration with optional secret disclosure."""
    run_config_command(show_secrets, output_format)


@cli.command(
    "doctor",
    short_help="Validate files, credentials, and integration settings.",
    help="""Run quick validation checks for the local environment.

The command verifies the inventory file, key credentials, firmware directory,
and optional integration settings for phpIPAM and Google Sheets. It exits with
code 1 when critical issues are found.
""",
)
@click.option("--format", "output_format", type=OutputFormat, default="text", show_default=True, help="Output format.")
def doctor_command(output_format: str) -> None:
    """Validate local files, credentials, and integration configuration."""
    run_doctor_command(output_format)


def main() -> None:
    """Launch the Click CLI entry point."""
    cli()
