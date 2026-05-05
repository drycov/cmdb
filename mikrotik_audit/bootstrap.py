from __future__ import annotations

from dataclasses import dataclass
import logging

from config import AppConfig
from domain.auditor import DeviceAuditor
from domain.exporter import ExcelExporter
from domain.targets import TargetProvider
from logging_setup import setup_logging
from models import Credentials
from runner import AuditRunner

from services.collector import MikroTikCollector
from services.firmware import FirmwareManager
from services.radius import RadiusRemediator
from services.routeros_script_generator import RouterOSScriptGenerator
from services.ssh import SSHService

from domain.phpipam_registry_async import AsyncPHPIPAMRegistryService
from services.phpipam_async import AsyncPHPIPAMClient
from services.google_sheets import GoogleSheetsExporter

@dataclass(slots=True)
class AuditDependencies:
    ssh: SSHService
    collector: MikroTikCollector
    firmware_manager: FirmwareManager
    radius_remediator: RadiusRemediator


def _build_credentials(config: AppConfig) -> tuple[Credentials, Credentials]:
    return (
        Credentials(config.username, config.password),
        Credentials(config.fallback_username, config.fallback_password),
    )


def _build_google_exporter(
    config: AppConfig,
    logger: logging.Logger,
) -> GoogleSheetsExporter | None:
    google = getattr(config, "google", None)

    if google is None or not google.enabled:
        return None

    if not google.credentials_file:
        logger.warning("Google exporter disabled: no credentials file")
        return None

    if not google.spreadsheet:
        logger.warning("Google exporter disabled: no spreadsheet name")
        return None

    try:
        return GoogleSheetsExporter(
            credentials_path=google.credentials_file,
            spreadsheet_name=google.spreadsheet,
            worksheet_name=google.worksheet,
            logger=logger,
        )
    except Exception as exc:
        logger.exception(
            "Google exporter initialization failed, fallback to Excel only: %s",
            exc,
        )
        return None


def _build_dependencies(
    config: AppConfig,
    logger: logging.Logger,
) -> AuditDependencies:
    return AuditDependencies(
        ssh=SSHService(config, logger),
        collector=MikroTikCollector(logger=logger),
        firmware_manager=FirmwareManager(config=config, logger=logger),
        radius_remediator=RadiusRemediator(config=config, logger=logger),
    )


def _build_phpipam_registry(
    config: AppConfig,
    logger: logging.Logger,
) -> AsyncPHPIPAMRegistryService | None:
    if not config.phpipam.enabled:
        return None

    client = AsyncPHPIPAMClient(config.phpipam, logger)

    return AsyncPHPIPAMRegistryService(
        config=config.phpipam,
        client=client,
        logger=logger,
    )


def build_app() -> AuditRunner:
    config = AppConfig.from_env()
    logger = setup_logging(config)

    primary, fallback = _build_credentials(config)
    deps = _build_dependencies(config, logger)

    auditor = DeviceAuditor(
        config=config,
        ssh=deps.ssh,
        collector=deps.collector,
        firmware_manager=deps.firmware_manager,
        radius_remediator=deps.radius_remediator,
        logger=logger,
        primary_credentials=primary,
        fallback_credentials=fallback,
    )

    return AuditRunner(
        config=config,
        logger=logger,
        target_provider=TargetProvider(config),
        auditor=auditor,
        exporter=ExcelExporter(config),
        phpipam_registry=_build_phpipam_registry(config, logger),
        google_exporter=_build_google_exporter(config, logger),
        script_generator=RouterOSScriptGenerator(config=config),
    )
