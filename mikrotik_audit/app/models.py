from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PortModel:
    name: str
    comment: Optional[str] = None
    pvid: Optional[int] = None
    tagged_vlans: List[int] = field(default_factory=list)
    untagged_vlans: List[int] = field(default_factory=list)
    role: str = "unknown"
    confidence: float = 0.0


@dataclass
class DeviceModel:
    identity: str = ""
    model: str = ""
    mgmt_ip: Optional[str] = None
    ports: Dict[str, PortModel] = field(default_factory=dict)
    bridge_vlans: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    eos: Dict[str, Any] = field(default_factory=dict)
    raw_sections: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    device: DeviceModel
    transit_detected: bool = False
    radio_detected: bool = False
    decision: str = "NEED_MANUAL_REVIEW"
    risks: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
