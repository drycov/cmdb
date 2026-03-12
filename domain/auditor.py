from __future__ import annotations

import logging

from config import AppConfig
from constants.auth_methods import AuthMethod
from constants.statuses import AuditStatus
from models import AuditResult, Credentials
from services.collector import MikroTikCollector
from services.firmware import FirmwareManager
from services.radius import RadiusRemediator
from services.ssh import SSHService, SSHSession
from utils import network_of_ip
from .status_builder import StatusBuilder


class DeviceAuditor:
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
    ) -> None:
        self.config = config
        self.ssh = ssh
        self.collector = collector
        self.firmware_manager = firmware_manager
        self.radius_remediator = radius_remediator
        self.logger = logger
        self.primary_credentials = primary_credentials
        self.fallback_credentials = fallback_credentials

    def _apply_firmware_if_needed(self, session: SSHSession, result: AuditResult) -> None:
        if not self.config.auto_upload_mmips:
            return

        fw_result = self.firmware_manager.ensure_uploaded(
            session=session,
            architecture=result.architecture,
            current_version=result.version,
        )
        result.apply_firmware(fw_result)

    def audit_device(self, ip: str) -> AuditResult:
        self.logger.info("Audit started ip=%s", ip)

        result = AuditResult(
            ip=ip,
            subnet=network_of_ip(ip),
        )

        if not self.ssh.ping_host(ip):
            result.status = AuditStatus.OFFLINE.value
            self.logger.info("Audit finished ip=%s status=%s", ip, result.status)
            return result

        result.ping = True

        if not self.ssh.check_ssh_port(ip):
            result.status = AuditStatus.SSH_CLOSED.value
            self.logger.info("Audit finished ip=%s status=%s", ip, result.status)
            return result

        result.ssh_port = True

        primary_session = self.ssh.open_session(ip, self.primary_credentials)
        if primary_session is not None:
            with primary_session as session:
                primary_data = self.collector.collect_router_data(session)
                if primary_data is not None:
                    result.apply_device_info(primary_data)
                    result.set_auth_method(AuthMethod.PRIMARY)
                    self._apply_firmware_if_needed(session, result)
                    result.status = StatusBuilder.build_primary(result)

                    self.logger.info(
                        "Audit finished ip=%s status=%s auth=%s identity=%s version=%s",
                        ip,
                        result.status,
                        result.auth_method,
                        result.identity,
                        result.version,
                    )
                    return result

        fallback_session = self.ssh.open_session(ip, self.fallback_credentials)
        if fallback_session is None:
            result.status = AuditStatus.AUTH_FAILED.value
            self.logger.info("Audit finished ip=%s status=%s", ip, result.status)
            return result

        with fallback_session as session:
            fallback_data = self.collector.collect_router_data(session)
            if fallback_data is None:
                result.status = AuditStatus.AUTH_FAILED.value
                self.logger.info("Audit finished ip=%s status=%s", ip, result.status)
                return result

            result.apply_device_info(fallback_data)
            result.set_auth_method(AuthMethod.FALLBACK)

            self._apply_firmware_if_needed(session, result)

            radius_result = self.radius_remediator.ensure_radius(session)
            result.apply_radius(radius_result)

            result.status = StatusBuilder.build_fallback(result)

            self.logger.info(
                "Audit finished ip=%s status=%s auth=%s identity=%s version=%s",
                ip,
                result.status,
                result.auth_method,
                result.identity,
                result.version,
            )
            return result