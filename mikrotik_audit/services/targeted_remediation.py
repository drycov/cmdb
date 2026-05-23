"""Implementation details for services targeted_remediation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mikrotik_audit.commands.mikrotik import MikroTikCommands
from mikrotik_audit.config import AppConfig
from mikrotik_audit.models import Credentials, DeviceInfo
from mikrotik_audit.services.collector import MikroTikCollector
from mikrotik_audit.services.compliance import DevicePolicyInspector
from mikrotik_audit.services.scheduler import SchedulerPolicyInspector
from mikrotik_audit.services.script_repository import ScriptRepository
from mikrotik_audit.services.ssh import SSHService, SSHSession


@dataclass(slots=True)
class RemediationDomainResult:
    """Represent the remediationdomainresult payload."""
    domain: str
    compliant: bool
    commands: list[str] = field(default_factory=list)
    details: str = ""
    applied: int = 0
    failed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TargetedRemediationResult:
    """Represent the targetedremediationresult payload."""
    ip: str
    identity: str = ""
    auth_method: str = ""
    dry_run: bool = True
    script_path: str = ""
    domains: list[RemediationDomainResult] = field(default_factory=list)

    @property
    def command_count(self) -> int:
        return sum(len(item.commands) for item in self.domains)

    @property
    def has_changes(self) -> bool:
        return any(item.commands for item in self.domains)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["command_count"] = self.command_count
        payload["has_changes"] = self.has_changes
        return payload


class TargetedRemediator:
    """Represent targetedremediator."""
    NON_CRITICAL_DOMAINS = ("ntp", "watchdog", "scheduler")

    def __init__(
        self,
        *,
        config: AppConfig,
        ssh: SSHService,
        collector: MikroTikCollector,
        compliance_inspector: DevicePolicyInspector,
        scheduler_inspector: SchedulerPolicyInspector,
        logger,
    ) -> None:
        self.config = config
        self.ssh = ssh
        self.collector = collector
        self.compliance_inspector = compliance_inspector
        self.scheduler_inspector = scheduler_inspector
        self.logger = logger
        self.output_dir = Path(config.remediation.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.script_repository = ScriptRepository(
            storage_root=self.output_dir,
            git_enabled=config.remediation.git_enabled,
            git_repo_dir=Path(config.remediation.git_repo_dir),
            git_subdir="targeted",
            author_name=config.remediation.git_author_name,
            author_email=config.remediation.git_author_email,
            logger=logger,
        )

    def remediate_ip(
        self,
        *,
        ip: str,
        domains: list[str] | None = None,
        apply: bool = False,
    ) -> TargetedRemediationResult:
        if not self.config.remediation.enabled:
            raise RuntimeError("Targeted remediation is disabled in settings.remediation.enabled")

        if apply and not self.config.remediation.allow_apply:
            raise RuntimeError(
                "Live apply is disabled in settings.remediation.allow_apply. "
                "Use dry-run or enable apply explicitly."
            )

        selected_domains = self._normalize_domains(domains)
        credentials = self._open_session(ip)
        if credentials is None:
            raise RuntimeError(f"Could not open SSH session to {ip} with configured credentials")

        session, auth_method = credentials
        with session:
            info = self.collector.collect_router_data(session)
            if info is None:
                raise RuntimeError(f"Could not collect device state from {ip}")

            result = TargetedRemediationResult(
                ip=ip,
                identity=info.identity,
                auth_method=auth_method,
                dry_run=not apply,
            )

            for domain in selected_domains:
                domain_result = self._build_domain_result(
                    session=session,
                    info=info,
                    domain=domain,
                )
                if apply and domain_result.commands:
                    self._apply_commands(session, domain_result)
                result.domains.append(domain_result)

            if result.has_changes:
                result.script_path = str(self._write_script(result))

            return result

    def _normalize_domains(self, domains: list[str] | None) -> list[str]:
        raw_domains = domains or list(self.NON_CRITICAL_DOMAINS)
        normalized = []
        seen = set()

        for domain in raw_domains:
            value = str(domain).strip().lower()
            if not value or value in seen:
                continue
            if value not in self.NON_CRITICAL_DOMAINS:
                raise RuntimeError(f"Unsupported remediation domain: {value}")
            if not self.config.remediation_domain_allowed(value):
                raise RuntimeError(f"Remediation domain is not allowed by policy: {value}")
            normalized.append(value)
            seen.add(value)

        return normalized

    def _open_session(self, ip: str) -> tuple[SSHSession, str] | None:
        for index, cred in enumerate(self.config.mikrotik_credentials):
            session = self.ssh.open_session(
                ip,
                Credentials(cred.username, cred.password),
            )
            if session is None:
                continue

            auth_method = cred.name or ("primary" if index == 0 else f"fallback_{index}")
            return session, auth_method

        return None

    def _build_domain_result(
        self,
        *,
        session: SSHSession,
        info: DeviceInfo,
        domain: str,
    ) -> RemediationDomainResult:
        if domain == "ntp":
            return self._build_ntp_result(info)
        if domain == "watchdog":
            return self._build_watchdog_result(info)
        if domain == "scheduler":
            return self._build_scheduler_result(session=session, info=info)
        raise RuntimeError(f"Unsupported remediation domain: {domain}")

    def _build_ntp_result(self, info: DeviceInfo) -> RemediationDomainResult:
        check = self.compliance_inspector.inspect_ntp(
            info=info,
            config=self.config.ntp,
        )
        if check.status == "OK":
            return RemediationDomainResult(domain="ntp", compliant=True, details=check.expected)

        commands: list[str] = []
        if self.config.ntp.enabled:
            commands.append(MikroTikCommands.ntp_client_set_enabled(self.config.ntp.enabled))
        commands.append(MikroTikCommands.ntp_client_servers_reset())
        commands.extend(
            MikroTikCommands.ntp_client_server_add(address)
            for address in self.config.ntp.servers
        )
        return RemediationDomainResult(
            domain="ntp",
            compliant=False,
            commands=commands,
            details=check.message or check.expected,
        )

    def _build_watchdog_result(self, info: DeviceInfo) -> RemediationDomainResult:
        check = self.compliance_inspector.inspect_watchdog(
            info=info,
            config=self.config.watchdog,
        )
        if check.status == "OK":
            return RemediationDomainResult(
                domain="watchdog",
                compliant=True,
                details=check.expected,
            )

        command = MikroTikCommands.watchdog_set(
            automatic_supout=self.config.watchdog.automatic_supout,
            ping_start_after_boot=self.config.watchdog.ping_start_after_boot,
            ping_timeout=self.config.watchdog.ping_timeout,
            watchdog_timer=self.config.watchdog.watchdog_timer,
        )
        return RemediationDomainResult(
            domain="watchdog",
            compliant=False,
            commands=[command],
            details=check.message or check.expected,
        )

    def _build_scheduler_result(
        self,
        *,
        session: SSHSession,
        info: DeviceInfo,
    ) -> RemediationDomainResult:
        checks = self.scheduler_inspector.inspect_expected(
            session=session,
            expected_rules=self.config.scheduler.expected,
            identity=info.identity,
        )
        commands = self.scheduler_inspector.build_remediation_commands(
            session=session,
            expected_rules=self.config.scheduler.expected,
            identity=info.identity,
        )
        compliant = not commands
        details = "; ".join(
            f"{check.name}:{check.status}:{check.message}".rstrip(":")
            for check in checks
            if check.status != "OK"
        )
        return RemediationDomainResult(
            domain="scheduler",
            compliant=compliant,
            commands=commands,
            details=details,
        )

    def _apply_commands(self, session: SSHSession, result: RemediationDomainResult) -> None:
        for command in result.commands:
            if session.exec_ok(command):
                result.applied += 1
            else:
                result.failed += 1

    def _write_script(self, result: TargetedRemediationResult) -> Path:
        safe_ip = result.ip.replace(".", "_")
        relative_path = f"{safe_ip}__targeted_fix.rsc"
        lines = [
            "# Targeted non-critical remediation script",
            f"# IP: {result.ip}",
            f"# Identity: {result.identity}",
            "",
        ]

        for domain in result.domains:
            if not domain.commands:
                continue
            lines.append(f"# [{domain.domain}]")
            lines.extend(domain.commands)
            lines.append("")

        return self.script_repository.write_text(
            relative_path=relative_path,
            content="\n".join(lines).rstrip() + "\n",
            commit_message=f"targeted remediation update for {result.ip}",
        )
