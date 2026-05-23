"""Compatibility runner exports for the packaged audit application."""

from __future__ import annotations

from mikrotik_audit.runtime.bootstrap import AuditApplication as AuditRunner

__all__ = ["AuditRunner"]
