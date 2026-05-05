from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import Callable, TypeVar

import paramiko
from paramiko import AuthenticationException, SSHException
from pythonping import ping

from commands.mikrotik import MikroTikCommands
from config import AppConfig
from models import Credentials

T = TypeVar("T")


class SSHSession:
    def __init__(
        self,
        ip: str,
        credentials: Credentials,
        client: paramiko.SSHClient,
        logger: logging.Logger,
        command_timeout: int,
    ) -> None:
        self.ip = ip
        self.credentials = credentials
        self.client = client
        self.logger = logger
        self.command_timeout = command_timeout

    @staticmethod
    def _safe_close(obj: object | None) -> None:
        if obj is None:
            return
        try:
            obj.close()
        except Exception:
            pass

    @staticmethod
    def _read_command_output(
        stdout: paramiko.channel.ChannelFile,
        stderr: paramiko.channel.ChannelFile,
    ) -> tuple[str, str, int]:
        output = stdout.read().decode(errors="ignore").strip()
        err = stderr.read().decode(errors="ignore").strip()
        exit_status = stdout.channel.recv_exit_status()
        return output, err, exit_status

    def exec(self, command: str) -> str | None:
        stdin = stdout = stderr = None

        try:
            self.logger.debug(
                "SSH session exec start ip=%s user=%s cmd=%s",
                self.ip,
                self.credentials.username,
                command,
            )

            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=self.command_timeout,
            )
            stdin.close()

            output, err, exit_status = self._read_command_output(stdout, stderr)

            if exit_status != 0:
                self.logger.warning(
                    "SSH session command failed ip=%s user=%s cmd=%s exit_status=%s stderr=%s",
                    self.ip,
                    self.credentials.username,
                    command,
                    exit_status,
                    err,
                )
                return None

            if err:
                self.logger.debug(
                    "SSH session stderr with zero exit ip=%s user=%s cmd=%s stderr=%s",
                    self.ip,
                    self.credentials.username,
                    command,
                    err,
                )

            self.logger.debug(
                "SSH session exec success ip=%s user=%s cmd=%s output_len=%s",
                self.ip,
                self.credentials.username,
                command,
                len(output),
            )
            return output

        except Exception as exc:
            self.logger.debug(
                "SSH session exec exception ip=%s user=%s cmd=%s error=%s",
                self.ip,
                self.credentials.username,
                command,
                exc,
            )
            return None

        finally:
            self._safe_close(stdin)
            self._safe_close(stdout)
            self._safe_close(stderr)

    def exec_ok(self, command: str) -> bool:
        return self.exec(command) is not None

    def upload_file_sftp(
        self,
        local_path: Path,
        remote_name: str | None = None,
    ) -> bool:
        sftp: paramiko.SFTPClient | None = None

        try:
            self.logger.info(
                "SFTP upload start ip=%s user=%s file=%s",
                self.ip,
                self.credentials.username,
                local_path.name,
            )

            sftp = self.client.open_sftp()
            sftp.put(str(local_path), remote_name or local_path.name)

            self.logger.info(
                "SFTP upload success ip=%s user=%s file=%s",
                self.ip,
                self.credentials.username,
                local_path.name,
            )
            return True

        except FileNotFoundError as exc:
            self.logger.error(
                "SFTP local file missing ip=%s user=%s file=%s error=%s",
                self.ip,
                self.credentials.username,
                local_path,
                exc,
            )
            return False

        except Exception as exc:
            self.logger.error(
                "SFTP upload failed ip=%s user=%s file=%s error=%s",
                self.ip,
                self.credentials.username,
                local_path.name,
                exc,
            )
            return False

        finally:
            self._safe_close(sftp)

    def remote_file_exists(self, filename: str) -> bool:
        out = self.exec(MikroTikCommands.file_print(filename))
        if not out:
            return False

        target = filename.strip().lower()

        for line in out.splitlines():
            normalized = line.strip().lower()
            if not normalized:
                continue

            if normalized == target:
                return True

            tokens = normalized.replace('"', " ").split()
            if target in tokens:
                return True

        return False

    def close(self) -> None:
        self._safe_close(self.client)

    def __enter__(self) -> "SSHSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class SSHService:
    def __init__(self, config: AppConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger

    def ping_host(self, ip: str) -> bool:
        try:
            result = ping(ip, count=1, timeout=1)
            return result.success()
        except Exception as exc:
            self.logger.debug("Ping exception ip=%s error=%s", ip, exc)
            return False

    def check_ssh_port(self, ip: str) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((ip, self.config.ssh_port))
                return True
        except Exception as exc:
            self.logger.debug(
                "SSH port check failed ip=%s port=%s error=%s",
                ip,
                self.config.ssh_port,
                exc,
            )
            return False

    def _create_client(self, ip: str, credentials: Credentials) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip,
            port=self.config.ssh_port,
            username=credentials.username,
            password=credentials.password,
            timeout=self.config.timeout,
            banner_timeout=self.config.banner_timeout,
            auth_timeout=self.config.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def open_session(self, ip: str, credentials: Credentials) -> SSHSession | None:
        try:
            self.logger.debug(
                "SSH session open start ip=%s user=%s",
                ip,
                credentials.username,
            )

            client = self._create_client(ip, credentials)

            self.logger.debug(
                "SSH session open success ip=%s user=%s",
                ip,
                credentials.username,
            )

            return SSHSession(
                ip=ip,
                credentials=credentials,
                client=client,
                logger=self.logger,
                command_timeout=self.config.timeout + 5,
            )

        except AuthenticationException as exc:
            self.logger.debug(
                "SSH session auth failed ip=%s user=%s error=%s",
                ip,
                credentials.username,
                exc,
            )
            return None

        except (SSHException, socket.timeout, OSError) as exc:
            self.logger.debug(
                "SSH session transport failed ip=%s user=%s error=%s",
                ip,
                credentials.username,
                exc,
            )
            return None

        except Exception as exc:
            self.logger.debug(
                "SSH session unexpected open error ip=%s user=%s error=%s",
                ip,
                credentials.username,
                exc,
            )
            return None

    def _with_session(
        self,
        ip: str,
        credentials: Credentials,
        action: Callable[[SSHSession], T],
        default: T,
    ) -> T:
        session = self.open_session(ip, credentials)
        if session is None:
            return default

        with session:
            return action(session)

    # backward-compatible wrappers
    def exec(self, ip: str, credentials: Credentials, command: str) -> str | None:
        return self._with_session(
            ip,
            credentials,
            lambda session: session.exec(command),
            None,
        )

    def exec_ok(self, ip: str, credentials: Credentials, command: str) -> bool:
        return self.exec(ip, credentials, command) is not None

    def upload_file_sftp(
        self,
        ip: str,
        credentials: Credentials,
        local_path: Path,
        remote_name: str | None = None,
    ) -> bool:
        return self._with_session(
            ip,
            credentials,
            lambda session: session.upload_file_sftp(local_path, remote_name),
            False,
        )

    def remote_file_exists(self, ip: str, credentials: Credentials, filename: str) -> bool:
        return self._with_session(
            ip,
            credentials,
            lambda session: session.remote_file_exists(filename),
            False,
        )
