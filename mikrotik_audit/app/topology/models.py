"""Implementation details for app topology models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from mikrotik_audit.models.device_info import DeviceInfo


@dataclass
class TopologyDevice:
    """Represent topologydevice."""
    ip: str
    status: str = ""
    identity: str = ""
    primary_mac: str = ""
    uplink_interface: str = ""
    uplink_mac: str = ""
    neighbor_identity: str = ""
    neighbor_address: str = ""
    neighbor_interface: str = ""
    neighbor_mac: str = ""
    vlan_count: str = ""
    vlan_names: str = ""
    ospf_neighbor_count: str = ""
    ospf_instances: str = ""
    bridge_warning: str = ""
    error: str = ""
    device_info: DeviceInfo | None = None


@dataclass
class TopologyLink:
    """Represent topologylink."""
    source_ip: str
    source_identity: str
    source_interface: str
    source_mac: str
    target_ip: str
    target_identity: str
    target_interface: str
    target_mac: str
    relation: str = ""
    confidence: float = 0.0


@dataclass
class TopologyAnalysisResult:
    """Represent the topologyanalysisresult payload."""
    device: TopologyDevice
    status: str = ""
    error: str = ""
    edges: List[TopologyLink] = field(default_factory=list)
