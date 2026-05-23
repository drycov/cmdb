"""Module entry point for running the MikroTik audit package with python -m."""

from __future__ import annotations

from mikrotik_audit.entrypoints.cli import main


if __name__ == "__main__":
    main()
