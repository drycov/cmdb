"""Implementation details for services config_backup."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from mikrotik_audit.config import AppConfig
from mikrotik_audit.models import Credentials
from mikrotik_audit.services.script_repository import ScriptRepository
from mikrotik_audit.services.ssh import SSHService, SSHSession


@dataclass(slots=True)
class ConfigBackupResult:
    """Represent the configbackupresult payload."""
    ip: str
    identity: str
    auth_method: str
    path: str


class ConfigBackupService:
    """Provide the configbackupservice service."""
    def __init__(
        self,
        *,
        config: AppConfig,
        ssh: SSHService,
        logger,
    ) -> None:
        self.config = config
        self.ssh = ssh
        self.logger = logger
        self.output_dir = Path(config.backup.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.repository = ScriptRepository(
            storage_root=self.output_dir,
            git_enabled=config.backup.git_enabled,
            git_repo_dir=Path(config.backup.git_repo_dir),
            git_subdir="configs",
            author_name=config.backup.git_author_name,
            author_email=config.backup.git_author_email,
            logger=logger,
        )

    def backup_ip(self, ip: str) -> ConfigBackupResult:
        if not self.config.backup.enabled:
            raise RuntimeError("Config backup is disabled in settings.backup.enabled")

        session_info = self._open_session(ip)
        if session_info is None:
            raise RuntimeError(f"Could not open SSH session to {ip} with configured credentials")

        session, auth_method = session_info
        with session:
            identity = self._read_identity(session) or ip
            config_text = session.exec(self.config.backup.export_command)
            if config_text is None:
                raise RuntimeError(
                    f"Could not export configuration from {ip} using command {self.config.backup.export_command!r}"
                )

            content = self._build_content(ip=ip, identity=identity, export_text=config_text)
            relative_path = self._build_relative_path(ip=ip, identity=identity)
            path = self.repository.write_text(
                relative_path=relative_path,
                content=content,
                commit_message=f"config backup update for {identity} ({ip})",
                auto_commit=False,
            )
            return ConfigBackupResult(
                ip=ip,
                identity=identity,
                auth_method=auth_method,
                path=str(path),
            )

    def finalize_batch_commit(self, updated_paths: list[str]) -> bool:
        if not self.config.backup.git_enabled:
            return False
        if not updated_paths:
            return False

        unique_paths = len(set(updated_paths))
        message = f"config backup batch update ({unique_paths} files)"
        return self.repository.commit_pending(message)

    def _open_session(self, ip: str) -> tuple[SSHSession, str] | None:
        for index, cred in enumerate(self.config.mikrotik_credentials):
            session = self.ssh.open_session(ip, Credentials(cred.username, cred.password))
            if session is None:
                continue

            auth_method = cred.name or ("primary" if index == 0 else f"fallback_{index}")
            return session, auth_method
        return None

    @staticmethod
    def _read_identity(session: SSHSession) -> str:
        raw = session.exec("/system identity print")
        if not raw:
            return ""

        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if ":" in stripped:
                _, value = stripped.split(":", 1)
                return value.strip()
            return stripped
        return ""

    def _build_relative_path(self, *, ip: str, identity: str) -> str:
        safe_identity = self._slug(identity) or "unknown"
        safe_ip = ip.replace(".", "_")
        mode = self.config.backup.filename_mode

        if mode == "identity":
            filename = f"{safe_identity}.rsc"
        elif mode == "ip":
            filename = f"{safe_ip}.rsc"
        else:
            filename = f"{safe_identity}__{safe_ip}.rsc"
        return filename

    @staticmethod
    def _slug(value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
        return cleaned.strip("._-")

    @staticmethod
    def _build_content(*, ip: str, identity: str, export_text: str) -> str:
        header = "\n".join(
            [
                "# RouterOS configuration backup",
                f"# IP: {ip}",
                f"# Identity: {identity}",
                "",
            ]
        )
        return header + export_text.rstrip() + "\n"
