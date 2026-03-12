from __future__ import annotations

import asyncio

from config import AppConfig
from domain.auditor import DeviceAuditor
from domain.exporter import ExcelExporter
from domain.phpipam_registry import PHPIPAMRegistryService
from domain.targets import TargetProvider
from logging_setup import setup_logging
from models import Credentials
from runner import AuditRunner
from services.collector import MikroTikCollector
from services.firmware import FirmwareManager
from services.phpipam import PHPIPAMClient
from services.radius import RadiusRemediator
from services.ssh import SSHService
from services.routeros_script_generator import RouterOSScriptGenerator

def build_app() -> AuditRunner:
    config = AppConfig.from_env()
    logger = setup_logging(config)

    primary_credentials = Credentials(
        username=config.username,
        password=config.password,
    )
    fallback_credentials = Credentials(
        username=config.fallback_username,
        password=config.fallback_password,
    )

    ssh = SSHService(config, logger)

    collector = MikroTikCollector(logger=logger)
    firmware_manager = FirmwareManager(
        config=config,
        logger=logger,
    )
    radius_remediator = RadiusRemediator(
        config=config,
        logger=logger,
    )

    auditor = DeviceAuditor(
        config=config,
        ssh=ssh,
        collector=collector,
        firmware_manager=firmware_manager,
        radius_remediator=radius_remediator,
        logger=logger,
        primary_credentials=primary_credentials,
        fallback_credentials=fallback_credentials,
    )

    target_provider = TargetProvider(config)
    exporter = ExcelExporter(config)

    phpipam_registry = None
    if config.phpipam.enabled:
        phpipam_client = PHPIPAMClient(config.phpipam, logger)
        phpipam_registry = PHPIPAMRegistryService(
            config=config.phpipam,
            client=phpipam_client,
            logger=logger,
        )
    script_generator = RouterOSScriptGenerator(config=config)

    return AuditRunner(
        config=config,
        logger=logger,
        target_provider=target_provider,
        auditor=auditor,
        exporter=exporter,
        phpipam_registry=phpipam_registry,
        script_generator=script_generator,
    )


if __name__ == "__main__":
    app = build_app()
    try:
        app.logger.info("Application started")
        asyncio.run(app.run())
        app.logger.info("Application finished")
    except Exception as exc:
        app.logger.exception("Application crashed error=%s", exc)
        raise