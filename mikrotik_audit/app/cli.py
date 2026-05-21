from __future__ import annotations

from pathlib import Path
from typing import List

import typer

from .analyzer import analyze_paths
from .report import to_json, to_markdown
from .remediation import generate_safe_fixes

app = typer.Typer(help="Offline RouterOS .rsc analyzer CLI")


@app.command()
def analyze_file(path: Path):
    """Analyze a single .rsc file and print JSON result."""
    res = analyze_paths([str(path)])
    print(to_json(res))


@app.command()
def analyze_dir(dir: Path):
    """Analyze first .rsc file in directory (simple)."""
    files = list(dir.rglob("*.rsc"))
    if not files:
        raise typer.Exit(code=1)
    res = analyze_paths([str(files[0])])
    print(to_json(res))


@app.command()
def report(dir: Path, format: str = "markdown"):
    files = list(dir.rglob("*.rsc"))
    if not files:
        raise typer.Exit(code=1)
    res = analyze_paths([str(files[0])])
    if format == "json":
        print(to_json(res))
    else:
        print(to_markdown(res))


@app.command()
def generate_fix(path: Path, safe_only: bool = True):
    if not safe_only:
        typer.echo("Only safe fixes supported in offline mode")
    lines = generate_safe_fixes()
    for l in lines:
        print(l)
