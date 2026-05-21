from __future__ import annotations

import logging
from dataclasses import dataclass

from commands.mikrotik import MikroTikCommands
from config import SchedulerRule
from services.ssh import SSHSession
from utils import parse_detail_blocks


@dataclass(slots=True, frozen=True)
class SchedulerPolicyCheck:
    name: str
    status: str
    expected_start_time: str
    actual_start_time: str
    message: str = ""


class SchedulerPolicyInspector:
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def inspect_expected(
        self,
        *,
        session: SSHSession,
        expected_rules: list[SchedulerRule],
        identity: str = "",
    ) -> list[SchedulerPolicyCheck]:
        if not expected_rules:
            return []

        raw = session.exec(MikroTikCommands.SYSTEM_SCHEDULER_DETAIL) or ""
        blocks = parse_detail_blocks(raw)
        checks: list[SchedulerPolicyCheck] = []

        for rule in expected_rules:
            checks.append(
                self._inspect_rule(
                    session=session,
                    blocks=blocks,
                    rule=rule,
                    identity=identity,
                )
            )

        return checks

    def build_remediation_commands(
        self,
        *,
        session: SSHSession,
        expected_rules: list[SchedulerRule],
        identity: str = "",
    ) -> list[str]:
        if not expected_rules:
            return []

        raw = session.exec(MikroTikCommands.SYSTEM_SCHEDULER_DETAIL) or ""
        blocks = parse_detail_blocks(raw)
        commands: list[str] = []

        for rule in expected_rules:
            commands.extend(
                self._build_rule_commands(
                    session=session,
                    blocks=blocks,
                    rule=rule,
                    identity=identity,
                )
            )

        return commands

    def _inspect_rule(
        self,
        *,
        session: SSHSession,
        blocks: list[dict[str, str]],
        rule: SchedulerRule,
        identity: str,
    ) -> SchedulerPolicyCheck:
        expected_start_time = rule.resolve_device_start_time(
            ip=session.ip,
            identity=identity,
        )
        matches = [
            block
            for block in blocks
            if str(block.get("name", "")).strip() == rule.name
        ]

        if not matches:
            return SchedulerPolicyCheck(
                name=rule.name,
                status="MISSING",
                expected_start_time=expected_start_time,
                actual_start_time="",
                message="scheduler entry not found",
            )

        if len(matches) > 1:
            return SchedulerPolicyCheck(
                name=rule.name,
                status="DUPLICATE",
                expected_start_time=expected_start_time,
                actual_start_time=self._actual_start_times(matches),
                message=f"expected one entry, found {len(matches)}",
            )

        current = matches[0]
        actual_start_time = str(current.get("start_time", "")).strip()
        mismatches = self._diff_fields(
            current=current,
            rule=rule,
            expected_start_time=expected_start_time,
        )

        if mismatches:
            return SchedulerPolicyCheck(
                name=rule.name,
                status="MISMATCH",
                expected_start_time=expected_start_time,
                actual_start_time=actual_start_time,
                message=", ".join(mismatches),
            )

        return SchedulerPolicyCheck(
            name=rule.name,
            status="OK",
            expected_start_time=expected_start_time,
            actual_start_time=actual_start_time,
        )

    @staticmethod
    def _actual_start_times(blocks: list[dict[str, str]]) -> str:
        values = [
            str(block.get("start_time", "")).strip()
            for block in blocks
            if str(block.get("start_time", "")).strip()
        ]
        return ", ".join(values)

    @staticmethod
    def _diff_fields(
        *,
        current: dict[str, str],
        rule: SchedulerRule,
        expected_start_time: str,
    ) -> list[str]:
        checks = [
            ("interval", rule.interval),
            ("on_event", rule.on_event),
            ("policy", rule.policy),
            ("disabled", rule.disabled),
        ]
        mismatches: list[str] = []

        if rule.start_date:
            checks.append(("start_date", rule.start_date))

        if expected_start_time:
            checks.append(("start_time", expected_start_time))

        for key, expected in checks:
            actual = str(current.get(key, "")).strip()
            if actual != expected:
                mismatches.append(f"{key}={actual or '<empty>'} != {expected}")

        return mismatches

    @staticmethod
    def _build_rule_commands(
        *,
        session: SSHSession,
        blocks: list[dict[str, str]],
        rule: SchedulerRule,
        identity: str,
    ) -> list[str]:
        expected_start_time = rule.resolve_device_start_time(
            ip=session.ip,
            identity=identity,
        )
        matches = [
            block
            for block in blocks
            if str(block.get("name", "")).strip() == rule.name
        ]

        if len(matches) > 1:
            return [
                MikroTikCommands.scheduler_remove_by_name(rule.name),
                MikroTikCommands.scheduler_add(
                    name=rule.name,
                    start_time=expected_start_time,
                    start_date=rule.start_date,
                    interval=rule.interval,
                    on_event=rule.on_event,
                    policy=rule.policy,
                    disabled=rule.disabled,
                ),
            ]

        if len(matches) == 1:
            mismatches = SchedulerPolicyInspector._diff_fields(
                current=matches[0],
                rule=rule,
                expected_start_time=expected_start_time,
            )
            if not mismatches:
                return []

            return [
                MikroTikCommands.scheduler_set(
                    name=rule.name,
                    start_time=expected_start_time,
                    start_date=rule.start_date,
                    interval=rule.interval,
                    on_event=rule.on_event,
                    policy=rule.policy,
                    disabled=rule.disabled,
                )
            ]

        return [
            MikroTikCommands.scheduler_add(
                name=rule.name,
                start_time=expected_start_time,
                start_date=rule.start_date,
                interval=rule.interval,
                on_event=rule.on_event,
                policy=rule.policy,
                disabled=rule.disabled,
            )
        ]
