from __future__ import annotations

import logging

from commands.mikrotik import MikroTikCommands
from config import AppConfig
from models import RadiusResult
from services.ssh import SSHSession


class RadiusRemediator:
    def __init__(self, config: AppConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger

    @staticmethod
    def _parse_count(raw: str | None) -> int:
        if not raw:
            return 0

        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        if not lines:
            return 0

        try:
            return int(lines[-1])
        except ValueError:
            return 0

    @staticmethod
    def _aaa_use_radius_enabled(raw: str | None) -> bool:
        return bool(raw and "use-radius: yes" in raw.lower())

    def _get_radius_count(self, session: SSHSession) -> int:
        count_cmd = MikroTikCommands.radius_count(
            service=self.config.radius_service,
            address=self.config.radius_addr,
        )
        raw = session.exec(count_cmd)
        return self._parse_count(raw)

    def _add_radius_entry(self, session: SSHSession) -> bool:
        add_cmd = MikroTikCommands.radius_add(
            service=self.config.radius_service,
            address=self.config.radius_addr,
            secret=self.config.radius_secret,
        )
        return session.exec_ok(add_cmd)

    def _remove_radius_entries(self, session: SSHSession) -> bool:
        remove_cmd = MikroTikCommands.radius_remove(
            service=self.config.radius_service,
            address=self.config.radius_addr,
        )
        return session.exec_ok(remove_cmd)

    def _get_aaa_state(self, session: SSHSession) -> bool:
        raw = session.exec(MikroTikCommands.USER_AAA_PRINT)
        return self._aaa_use_radius_enabled(raw)

    def _enable_aaa_radius(self, session: SSHSession) -> bool:
        return session.exec_ok(MikroTikCommands.USER_AAA_ENABLE_RADIUS)

    def _ensure_single_radius_entry(self, session: SSHSession, radius_count: int) -> tuple[bool, bool]:
        if radius_count == 0:
            return self._add_radius_entry(session), False
        if radius_count > 1:
            removed = self._remove_radius_entries(session)
            added = self._add_radius_entry(session)
            return False, removed and added
        return False, False

    def ensure_radius(self, session: SSHSession) -> RadiusResult:
        result = RadiusResult()

        self.logger.info("RADIUS remediation started ip=%s", session.ip)

        radius_count = self._get_radius_count(session)
        self.logger.info("RADIUS entries before remediation ip=%s count=%s", session.ip, radius_count)

        result.radius_added, result.radius_recreated = self._ensure_single_radius_entry(
            session,
            radius_count,
        )

        radius_verify_count = self._get_radius_count(session)
        result.radius_present_after = radius_verify_count == 1

        aaa_enabled_before = self._get_aaa_state(session)
        if not aaa_enabled_before:
            if self._enable_aaa_radius(session):
                result.aaa_enabled = True

        result.aaa_present_after = self._get_aaa_state(session)
        return result
