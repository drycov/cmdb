"""Implementation details for services script_repository."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path


class ScriptRepository:
    """Persist data through the scriptrepository repository."""
    def __init__(
        self,
        *,
        storage_root: Path,
        git_enabled: bool,
        git_repo_dir: Path,
        git_subdir: str,
        author_name: str,
        author_email: str,
        logger: logging.Logger | None = None,
    ) -> None:
        self.storage_root = storage_root
        self.git_enabled = git_enabled
        self.git_repo_dir = git_repo_dir
        self.git_subdir = git_subdir.strip().strip("/\\")
        self.author_name = author_name
        self.author_email = author_email
        self.logger = logger or logging.getLogger(__name__)
        self._repo_ready = False
        self._pending_repo_relatives: set[Path] = set()

        if self.git_enabled:
            self.base_dir = self.git_repo_dir / self.git_subdir if self.git_subdir else self.git_repo_dir
        else:
            self.base_dir = self.storage_root

        self.base_dir.mkdir(parents=True, exist_ok=True)

    def write_text(
        self,
        *,
        relative_path: str,
        content: str,
        commit_message: str,
        auto_commit: bool = True,
    ) -> Path:
        target_path = self.base_dir / relative_path
        target_path.parent.mkdir(parents=True, exist_ok=True)

        previous = None
        if target_path.exists():
            previous = target_path.read_text(encoding="utf-8")

        if previous == content:
            self.logger.info("Script unchanged path=%s", target_path)
            return target_path

        target_path.write_text(content, encoding="utf-8", newline="\n")

        if self.git_enabled:
            self._ensure_repo()
            repo_relative = target_path.relative_to(self.git_repo_dir)
            self._git_add(repo_relative)
            if auto_commit:
                self._git_commit_if_needed(repo_relative, commit_message)
            else:
                self._pending_repo_relatives.add(repo_relative)

        return target_path

    def commit_pending(self, message: str) -> bool:
        if not self.git_enabled:
            return False

        self._ensure_repo()
        status = self._git("status", "--porcelain", capture_output=True)
        if not status.stdout.strip():
            self.logger.info("Git script repo has no pending changes for batch commit")
            self._pending_repo_relatives.clear()
            return False

        self._git("commit", "-m", message)
        self._pending_repo_relatives.clear()
        return True

    def _ensure_repo(self) -> None:
        if self._repo_ready:
            return

        self.git_repo_dir.mkdir(parents=True, exist_ok=True)
        git_dir = self.git_repo_dir / ".git"
        if not git_dir.exists():
            self._git("init")

        self._git("config", "user.name", self.author_name)
        self._git("config", "user.email", self.author_email)
        self._git("config", "core.autocrlf", "false")
        self._git("config", "core.eol", "lf")
        self._repo_ready = True

    def _git_add(self, repo_relative: Path) -> None:
        self._git("add", "--", str(repo_relative))

    def _git_commit_if_needed(self, repo_relative: Path, message: str) -> None:
        status = self._git("status", "--porcelain", "--", str(repo_relative), capture_output=True)
        if not status.stdout.strip():
            self.logger.info("Git script repo has no pending changes path=%s", repo_relative)
            return

        self._git("commit", "-m", message, "--", str(repo_relative))

    def _git(self, *args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
        command = ["git", *args]
        result = subprocess.run(
            command,
            cwd=str(self.git_repo_dir),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr or stdout or f"exit code {result.returncode}"
            raise RuntimeError(f"Git command failed ({' '.join(command)}): {details}")
        return result
