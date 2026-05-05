from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from commands.mikrotik import MikroTikCommands
from services.ssh import SSHSession
from utils import parse_detail_blocks


@dataclass(slots=True)
class SchedulerSpec:
    name: str
    interval: str
    on_event: str
    policy: str
    disabled: str = "no"
    start_time_mode: str = "fixed"
    start_time: str = ""
    time_window_start: str = ""
    time_window_end: str = ""
    slot_minutes: int = 10
    seed_by: str = "ip"


@dataclass(slots=True)
class SchedulerApplyResult:
    name: str
    action: str  # unchanged | created | updated | error
    expected_start_time: str
    message: str = ""


class SchedulerRemediator:
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def apply_expected(
        self,
        *,
        session: SSHSession,
        specs: list[SchedulerSpec],
    ) -> list[SchedulerApplyResult]:
        results: list[SchedulerApplyResult] = []

        for spec in specs:
            results.append(self._apply_one(session=session, spec=spec))

        return results

    def _apply_one(
        self,
        *,
        session: SSHSession,
        spec: SchedulerSpec,
    ) -> SchedulerApplyResult:
        expected_start_time = self._resolve_start_time(
            ip=session.ip,
            spec=spec,
        )

        raw = session.exec(MikroTikCommands.scheduler_find_by_name(spec.name)) or ""
        existing = parse_detail_blocks(raw)

        if len(existing) > 1:
            session.exec(MikroTikCommands.scheduler_remove_by_name(spec.name))
            session.exec(
                MikroTikCommands.scheduler_add(
                    name=spec.name,
                    start_time=expected_start_time,
                    interval=spec.interval,
                    on_event=spec.on_event,
                    policy=spec.policy,
                    disabled=spec.disabled,
                )
            )
            return SchedulerApplyResult(
                name=spec.name,
                action="updated",
                expected_start_time=expected_start_time,
                message="duplicates removed and scheduler recreated",
            )

        if len(existing) == 1:
            current = existing[0]
            if self._is_same(current=current, spec=spec, start_time=expected_start_time):
                return SchedulerApplyResult(
                    name=spec.name,
                    action="unchanged",
                    expected_start_time=expected_start_time,
                )

            session.exec(
                MikroTikCommands.scheduler_set(
                    name=spec.name,
                    start_time=expected_start_time,
                    interval=spec.interval,
                    on_event=spec.on_event,
                    policy=spec.policy,
                    disabled=spec.disabled,
                )
            )
            return SchedulerApplyResult(
                name=spec.name,
                action="updated",
                expected_start_time=expected_start_time,
            )

        session.exec(
            MikroTikCommands.scheduler_add(
                name=spec.name,
                start_time=expected_start_time,
                interval=spec.interval,
                on_event=spec.on_event,
                policy=spec.policy,
                disabled=spec.disabled,
            )
        )
        return SchedulerApplyResult(
            name=spec.name,
            action="created",
            expected_start_time=expected_start_time,
        )

    @staticmethod
    def _is_same(
        *,
        current: dict[str, str],
        spec: SchedulerSpec,
        start_time: str,
    ) -> bool:
        return all(
            [
                current.get("name", "") == spec.name,
                current.get("start_time", "") == start_time,
                current.get("interval", "") == spec.interval,
                current.get("on_event", "") == spec.on_event,
                current.get("policy", "") == spec.policy,
                current.get("disabled", "") == spec.disabled,
            ]
        )

    @classmethod
    def _resolve_start_time(cls, *, ip: str, spec: SchedulerSpec) -> str:
        if spec.start_time_mode == "staggered":
            return cls._calc_stagger_time(
                seed=ip if spec.seed_by == "ip" else f"{ip}:{spec.name}",
                start=spec.time_window_start,
                end=spec.time_window_end,
                slot_minutes=spec.slot_minutes,
            )

        return spec.start_time or spec.time_window_start

    @staticmethod
    def _calc_stagger_time(
        *,
        seed: str,
        start: str,
        end: str,
        slot_minutes: int,
    ) -> str:
        start_dt = datetime.strptime(start, "%H:%M:%S")
        end_dt = datetime.strptime(end, "%H:%M:%S")

        window_minutes = int((end_dt - start_dt).total_seconds() // 60)
        slots = max(1, window_minutes // max(1, slot_minutes))

        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        slot = int(digest, 16) % slots

        result = start_dt + timedelta(minutes=slot * slot_minutes)
        return result.strftime("%H:%M:%S")