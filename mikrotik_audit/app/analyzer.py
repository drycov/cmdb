"""Implementation details for app analyzer."""

from __future__ import annotations

from typing import List

from .analysis_support import (
    detect_transit,
    ensure_ethernet_ports,
    finalize_decision,
    resolve_identity,
    resolve_management_ip,
    resolve_model,
)
from .models import AnalysisResult, DeviceModel
from .parser import parse_rsc
from .classifier import classify_ports


def analyze_path(path: str) -> AnalysisResult:
    """Handle analyze path."""
    data = parse_rsc(path)
    device = DeviceModel(raw_sections=data)
    device.identity = resolve_identity(device)
    device.mgmt_ip = resolve_management_ip(device)
    device.model = resolve_model(device)
    ensure_ethernet_ports(device)

    classify_ports(device)

    result = AnalysisResult(device=device)
    detect_transit(result)
    finalize_decision(result)

    return result


def analyze_paths(paths: List[str]) -> List[AnalysisResult]:
    """Handle analyze paths."""
    return [analyze_path(path) for path in paths]
