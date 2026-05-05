from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from config import AppConfig
from constants.auth_methods import AuthMethod
from constants.statuses import AuditStatus
from services.scheduler import SchedulerRemediator
from models import AuditResult, Credentials
from services.collector import MikroTikCollector
from services.firmware import FirmwareManager
from services.radius import RadiusRemediator
from services.ssh import SSHService
from utils import network_of_ip

from .status_builder import StatusBuilder


class DeviceAuditor:
    StatusBuilderFn = Callable[[AuditResult], str]

    def __init__(
        self,
        config: AppConfig,
        ssh: SSHService,
        collector: MikroTikCollector,
        firmware_manager: FirmwareManager,
        radius_remediator: RadiusRemediator,
        logger: logging.Logger,
        primary_credentials: Credentials,
        fallback_credentials: Credentials,
        scheduler_remediator: SchedulerRemediator | None = None,
    ) -> None:
        self.config = config
        self.ssh = ssh
        self.collector = collector
        self.firmware_manager = firmware_manager
        self.radius_remediator = radius_remediator
        self.logger = logger
        self.primary_credentials = primary_credentials
        self.fallback_credentials = fallback_credentials
        self.scheduler_remediator = scheduler_remediator

    def audit_device(self, ip: str) -> AuditResult:
        self.logger.info("Audit started ip=%s", ip)

        result = AuditResult(
            ip=ip,
            subnet=network_of_ip(ip),
        )

        if not self.ssh.ping_host(ip):
            result.status = AuditStatus.OFFLINE.value
            return self._finish(result)

        result.ping = True

        if not self.ssh.check_ssh_port(ip):
            result.status = AuditStatus.SSH_CLOSED.value
            return self._finish(result)

        result.ssh_port = True

        primary_result = self._process_primary_session(ip=ip, result=result)
        if primary_result is not None:
            return self._finish(primary_result)

        fallback_result = self._process_fallback_session(ip=ip, result=result)
        if fallback_result is not None:
            return self._finish(fallback_result)

        result.status = AuditStatus.AUTH_FAILED.value
        return self._finish(result)

    # ------------------------------
    # SESSIONS
    # ------------------------------

    def _process_primary_session(
        self,
        *,
        ip: str,
        result: AuditResult,
    ) -> AuditResult | None:
        return self._process_session(
            ip=ip,
            result=result,
            credentials=self.primary_credentials,
            auth_method=AuthMethod.PRIMARY,
            status_builder=StatusBuilder.build_primary,
            include_radius=False,
        )

    def _process_fallback_session(
        self,
        *,
        ip: str,
        result: AuditResult,
    ) -> AuditResult | None:
        return self._process_session(
            ip=ip,
            result=result,
            credentials=self.fallback_credentials,
            auth_method=AuthMethod.FALLBACK,
            status_builder=StatusBuilder.build_fallback,
            include_radius=True,
        )

    def _process_session(
        self,
        *,
        ip: str,
        result: AuditResult,
        credentials: Credentials,
        auth_method: AuthMethod,
        status_builder: StatusBuilderFn,
        include_radius: bool,
    ) -> AuditResult | None:
        session_ctx = self.ssh.open_session(ip, credentials)
        if session_ctx is None:
            return None

        with session_ctx as session:
            collected = self.collector.collect_router_data(session)
            if collected is None:
                return None

            result.apply_device_info(collected)
            result.set_auth_method(auth_method)

            self._inspect_firmware(result)

            if include_radius:
                self._inspect_radius(session, result)

            # 🔥 НОВОЕ — scheduler remediation
            self._apply_scheduler(session=session, result=result)

            result.status = status_builder(result)
            return result

    # ------------------------------
    # FEATURE BLOCKS
    # ------------------------------

    def _inspect_radius(self, session: Any, result: AuditResult) -> None:
        radius_result = self.radius_remediator.inspect_radius(session)
        result.apply_radius(radius_result)

    def _inspect_firmware(self, result: AuditResult) -> None:
        if not self.config.auto_upload_mmips:
            return

        fw_result = self.firmware_manager.inspect_status(
            architecture=result.architecture,
            current_version=result.version,
        )
        result.apply_firmware(fw_result)

    def _apply_scheduler(self, *, session: Any, result: AuditResult) -> None:
        # 1. выключено
        if self.scheduler_remediator is None:
            return

        scheduler_cfg = getattr(self.config, "scheduler", None)
        if scheduler_cfg is None:
            return

        if not getattr(scheduler_cfg, "enabled", False):
            return

        expected = getattr(scheduler_cfg, "expected", [])
        if not expected:
            return

        try:
            actions = self.scheduler_remediator.apply_expected(
                session=session,
                specs=expected,
            )

            # сохраняем результат (для Excel / логов)
            result.scheduler_remediation = [
                {
                    "name": a.name,
                    "action": a.action,  # unchanged / created / updated
                    "expected_start_time": a.expected_start_time,
                    "message": a.message,
                }
                for a in actions
            ]

        except Exception as e:
            self.logger.error("Scheduler apply failed ip=%s err=%s", result.ip, e)
            result.scheduler_remediation = [
                {"error": str(e)}
            ]

    # ------------------------------
    # FINALIZE
    # ------------------------------

    def _finish(self, result: AuditResult) -> AuditResult:
        self.logger.info(
            "Audit finished ip=%s status=%s auth=%s identity=%s version=%s",
            result.ip,
            result.status,
            result.auth_method,
            result.identity,
            result.version,
        )
        return result