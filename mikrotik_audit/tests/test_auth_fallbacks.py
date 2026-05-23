"""Test cases for auth fallbacks behavior."""

from __future__ import annotations

import logging
from types import SimpleNamespace

from mikrotik_audit.app_runtime import DeviceAuditor
from mikrotik_audit.constants.auth_methods import AuthMethod
from mikrotik_audit.models import Credentials


class _FakeSSH:
    """Represent fakessh."""
    @staticmethod
    def ping_host(ip: str) -> bool:
        return True

    @staticmethod
    def check_ssh_port(ip: str) -> bool:
        return True


class _RecordingAuditor(DeviceAuditor):
    """Represent recordingauditor."""
    def __init__(self, *, auth_credentials: list[Credentials]) -> None:
        super().__init__(
            config=SimpleNamespace(
                auto_upload_mmips=False,
                compliance=SimpleNamespace(radius=False, ntp=False, watchdog=False, scheduler=False),
            ),
            ssh=_FakeSSH(),
            collector=object(),
            compliance_inspector=object(),
            firmware_manager=object(),
            radius_remediator=object(),
            logger=logging.getLogger("test.auth_fallbacks"),
            auth_credentials=auth_credentials,
            scheduler_inspector=None,
        )
        self.attempts: list[tuple[str, str, bool]] = []

    def _process_session(
        self,
        *,
        ip: str,
        result,
        credentials: Credentials,
        auth_method: AuthMethod,
        status_builder,
        include_radius: bool,
    ):
        self.attempts.append((credentials.username, auth_method.value, include_radius))
        if credentials.username != "third-user":
            return None

        result.set_auth_method(auth_method)
        result.status = "ssh_ok"
        return result


def test_device_auditor_tries_all_fallback_credentials():
    """Test that test device auditor tries all fallback credentials."""
    auditor = _RecordingAuditor(
        auth_credentials=[
            Credentials("primary-user", "primary-pass"),
            Credentials("first-fallback", "first-pass"),
            Credentials("third-user", "third-pass"),
        ]
    )

    result = auditor.audit_device("10.0.0.1")

    assert [item[0] for item in auditor.attempts] == [
        "primary-user",
        "first-fallback",
        "third-user",
    ]
    assert auditor.attempts[0][1:] == (AuthMethod.PRIMARY.value, False)
    assert auditor.attempts[1][1:] == (AuthMethod.FALLBACK.value, True)
    assert auditor.attempts[2][1:] == (AuthMethod.FALLBACK.value, True)
    assert result.auth_method == AuthMethod.FALLBACK.value
    assert result.status == "ssh_ok"
