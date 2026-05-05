from __future__ import annotations

from dataclasses import dataclass
import logging

from config import AppConfig
from domain.auditor import DeviceAuditor
from domain.phpipam_registry_async import AsyncPHPIPAMRegistryService
from domain.targets import TargetProvider
from logging_setup import setup_logging
from models import Credentials
from runner import AuditRunner

from services.collector import MikroTikCollector
from services.firmware import FirmwareManager
from services.radius import RadiusRemediator
from services.routeros_script_generator import RouterOSScriptGenerator
from services.ssh import SSHService
from services.phpipam_async import AsyncPHPIPAMClient

from report.pipeline import ReportPipeline
from report.writers.excel import ExcelWriter
from report.writers.json import JsonWriter
from report.writers.gsheet import GSheetWriter


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


def _build_dependencies(config: AppConfig, logger: logging.Logger) -> AuditDependencies:
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


def _build_report_pipeline(
    config: AppConfig,
    logger: logging.Logger,
) -> ReportPipeline:
    writers = [
        ExcelWriter(config.output_xlsx),
        JsonWriter(
            config.output_json
            or str(config.output_xlsx).replace(".xlsx", ".ndjson")
        ),
    ]

    google = getattr(config, "google", None)

    if google and google.enabled and google.credentials_file and google.spreadsheet:
        try:
            import gspread
            from google.oauth2.service_account import Credentials as GoogleCredentials

            creds = GoogleCredentials.from_service_account_file(
                google.credentials_file,
                scopes=[
                    "https://www.googleapis.com/auth/spreadsheets",
                    "https://www.googleapis.com/auth/drive",
                ],
            )

            client = gspread.authorize(creds)
            spreadsheet = client.open(google.spreadsheet)

            writers.append(
                GSheetWriter(
                    spreadsheet=spreadsheet,
                    batch_size=500,
                )
            )

        except Exception as exc:
            logger.exception("Google Sheets writer disabled: %s", exc)

    return ReportPipeline(writers=writers)
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
        report_pipeline=_build_report_pipeline(config, logger),
        phpipam_registry=_build_phpipam_registry(config, logger),
        script_generator=RouterOSScriptGenerator(config=config),
    )