"""Implementation details for app cli."""

from __future__ import annotations

from pathlib import Path
from typing import List

import typer

from .analyzer import analyze_path, analyze_paths
from .report import to_json, to_markdown
from .remediation import generate_safe_fixes

app = typer.Typer(help="Offline RouterOS .rsc analyzer CLI")


@app.command()
def analyze_file(path: Path):
    """Analyze a single .rsc file and print JSON result."""
    res = analyze_path(str(path))
    print(to_json(res))


@app.command()
def analyze_dir(dir: Path):
    """Analyze all .rsc files in directory and print JSON results."""
    files = list(dir.rglob("*.rsc"))
    if not files:
        raise typer.Exit(code=1)
    results = analyze_paths([str(path) for path in files])
    print("[" + ",\n".join(to_json(result) for result in results) + "]")


@app.command()
def report(dir: Path, format: str = "markdown"):
    """Handle report."""
    files = list(dir.rglob("*.rsc"))
    if not files:
        raise typer.Exit(code=1)
    results = analyze_paths([str(path) for path in files])
    if format == "json":
        print("[" + ",\n".join(to_json(result) for result in results) + "]")
    else:
        print("\n\n".join(to_markdown(result) for result in results))


@app.command()
def generate_fix(path: Path, safe_only: bool = True):
    """Handle generate fix."""
    if not safe_only:
        typer.echo("Only safe fixes supported in offline mode")
    lines = generate_safe_fixes()
    for l in lines:
        print(l)
