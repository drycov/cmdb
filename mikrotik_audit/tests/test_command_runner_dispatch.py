"""Test cases for command runner dispatch behavior."""

from __future__ import annotations

from mikrotik_audit.platform_api.command_runner import CommandRunner


def test_command_runner_registers_all_supported_commands() -> None:
    """Test that test command runner registers all supported commands."""
    runner = CommandRunner()

    handlers = runner._command_handlers()

    assert sorted(handlers) == sorted(definition.name for definition in runner.list_commands())


def test_command_runner_requires_ip_for_ip_only_commands() -> None:
    """Test that test command runner requires ip for ip only commands."""
    runner = CommandRunner()

    try:
        runner._require_ip(None, "remediate")
    except ValueError as exc:
        assert "requires ip" in str(exc)
    else:
        raise AssertionError("Expected ValueError for missing ip")
