from __future__ import annotations

from typing import List

from .models import AnalysisResult, DeviceModel
from .parser import parse_rsc
from .classifier import classify_ports


def analyze_paths(paths: List[str]) -> AnalysisResult:
    # For now, analyze the first path as single device
    data = parse_rsc(paths[0])
    device = DeviceModel()
    device.raw_sections = data

    # system identity
    for s in data.get("/system identity", []):
        device.identity = s.get("name") or s.get("raw") or device.identity

    # ip address
    mgmt_ip = None
    for a in data.get("/ip address", []):
        ip = a.get("address") or a.get("address=")
        if not ip:
            continue
        address = ip.split("/")[0]
        if mgmt_ip is None:
            mgmt_ip = address
        comment = (a.get("comment") or "").lower()
        interface = (a.get("interface") or "").lower()
        if "mgmt" in comment or "mgmt" in interface or interface.startswith("vlan"):
            mgmt_ip = address
            break
    device.mgmt_ip = mgmt_ip

    # model from /system resource or comments (best-effort)
    for s in data.get("/system resource", []):
        device.model = s.get("model") or device.model

    # initialize ports from ethernet
    for e in data.get("/interface ethernet", []):
        from .models import PortModel

        name = (
            e.get("name")
            or e.get("interface")
            or e.get("default-name")
            or e.get("default_name")
        )
        if name:
            device.ports[name] = PortModel(name=name, comment=e.get("comment"))

    classify_ports(device)

    result = AnalysisResult(device=device)

    # basic transit/radio heuristics
    # transit if eoip present or multiple tagged downstreams
    if data.get("/interface eoip"):
        result.transit_detected = True
        result.risks.append("EoIP present")

    # simple decision heuristics
    mgmt_vlan_present = any(
        850 in (int(x) if isinstance(x, str) and x.isdigit() else 0 for x in [])
        for _ in ((),)
    )
    # fallback decision: require manual review unless safe conditions met
    result.decision = "NEED_MANUAL_REVIEW"
    result.recommendations.append("Run full manual review; offline analyzer is conservative")

    return result
