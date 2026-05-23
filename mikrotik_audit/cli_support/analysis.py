"""Implementation details for cli_support analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mikrotik_audit.cli_support.common import offline_report_paths, run_async_command
from mikrotik_audit.cli_support.formatters import emit_json

if TYPE_CHECKING:
    from mikrotik_audit.runner import AuditRunner


def run_analyze_file_command(path: str, export_report: bool, output_format: str) -> None:
    """Run analyze file command."""
    async def operation(app: "AuditRunner") -> None:
        from mikrotik_audit.app.analyzer import analyze_path
        from mikrotik_audit.app.report import (
            build_sections_from_analysis,
            to_json,
            to_markdown,
        )

        result = analyze_path(path)

        if export_report:
            sections = build_sections_from_analysis(result)
            output_xlsx, output_json = offline_report_paths(app.config, Path(path).stem)
            await app.export_custom_report(
                sections,
                output_xlsx=output_xlsx,
                output_json=output_json,
            )

        if output_format == "json":
            emit_json(json.loads(to_json(result)))
            return
        click.echo(to_markdown(result))

    run_async_command("analyze-file", operation)


def run_analyze_dir_command(dirpath: str | None, export_report: bool, output_format: str) -> None:
    """Run analyze dir command."""
    async def operation(app: "AuditRunner") -> None:
        from mikrotik_audit.app.analyzer import analyze_paths
        from mikrotik_audit.app.report import (
            build_sections_from_analyses,
            to_json,
            to_markdown,
        )

        if dirpath:
            directory = Path(dirpath)
        else:
            directory = Path(__file__).resolve().parent.parent / "logs" / "config-backup-history" / "configs"

        files = sorted(directory.rglob("*.rsc"), key=lambda item: str(item).lower())
        if not files:
            click.echo("No .rsc files found in directory")
            return

        results = analyze_paths([str(path) for path in files])

        if export_report:
            sections = build_sections_from_analyses(results)
            output_xlsx, output_json = offline_report_paths(app.config, directory.name or "offline_analysis")
            await app.export_custom_report(
                sections,
                output_xlsx=output_xlsx,
                output_json=output_json,
            )

        if output_format == "json":
            emit_json([json.loads(to_json(result)) for result in results])
            return

        for index, result in enumerate(results, start=1):
            if index > 1:
                click.echo("")
            click.echo(to_markdown(result))

    run_async_command("analyze-dir", operation)


def run_topology_command(
    ip: str | None,
    export_report: bool,
    output_format: str,
    show_progress: bool,
) -> None:
    """Run topology command."""
    async def operation(app: "AuditRunner") -> None:
        from app.topology.report import to_json, to_markdown

        results = await app.run_topology_command(
            ip=ip,
            export=export_report,
            show_progress=show_progress,
        )
        all_links = [edge for result in results for edge in result.edges]

        if output_format == "json":
            emit_json(json.loads(to_json(results, all_links)))
            return

        click.echo(to_markdown(results, all_links))

    run_async_command("topology", operation)
