from __future__ import annotations

import json
from typing import Dict

from .models import AnalysisResult


def to_json(result: AnalysisResult) -> str:
    def _port_to_dict(p):
        return {
            "role": p.role,
            "tagged_vlans": p.tagged_vlans,
            "untagged_vlans": p.untagged_vlans,
            "pvid": p.pvid,
            "comment": p.comment,
            "confidence": p.confidence,
        }

    dev = result.device
    out: Dict = {
        "identity": dev.identity,
        "mgmt_ip": dev.mgmt_ip,
        "model": dev.model,
        "uplink_ports": [n for n, p in dev.ports.items() if p.role == "trunk"],
        "ports": {n: _port_to_dict(p) for n, p in dev.ports.items()},
        "transit_detected": result.transit_detected,
        "radio_detected": result.radio_detected,
        "decision": result.decision,
        "risks": result.risks,
        "recommendations": result.recommendations,
    }
    return json.dumps(out, ensure_ascii=False, indent=2)


def to_markdown(result: AnalysisResult) -> str:
    dev = result.device
    lines = []
    lines.append(f"# Analysis {dev.identity} ({dev.model})")
    lines.append("")
    lines.append(f"- Management IP: {dev.mgmt_ip}")
    lines.append(f"- Decision: **{result.decision}**")
    lines.append("")
    lines.append("## Ports")
    lines.append("| Port | Role | Tagged | Untagged | PVID | Confidence |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for n, p in dev.ports.items():
        lines.append(
            f"| {n} | {p.role} | {p.tagged_vlans} | {p.untagged_vlans} | {p.pvid} | {p.confidence:.2f} |")

    if result.risks:
        lines.append("")
        lines.append("## Risks")
        for r in result.risks:
            lines.append(f"- {r}")

    if result.recommendations:
        lines.append("")
        lines.append("## Recommendations")
        for r in result.recommendations:
            lines.append(f"- {r}")

    return "\n".join(lines)


def build_sections_from_analysis(result: AnalysisResult) -> dict:
    dev = result.device
    summary_headers = [
        "identity",
        "mgmt_ip",
        "model",
        "transit_detected",
        "radio_detected",
        "decision",
        "risks",
        "recommendations",
    ]
    summary_row = {
        "identity": dev.identity,
        "mgmt_ip": dev.mgmt_ip,
        "model": dev.model,
        "transit_detected": result.transit_detected,
        "radio_detected": result.radio_detected,
        "decision": result.decision,
        "risks": ", ".join(result.risks),
        "recommendations": ", ".join(result.recommendations),
    }

    ports_headers = ["port", "role", "tagged_vlans", "untagged_vlans", "pvid", "comment", "confidence"]
    ports_rows = []
    for n, p in dev.ports.items():
        ports_rows.append(
            {
                "port": n,
                "role": p.role,
                "tagged_vlans": ",".join(str(x) for x in p.tagged_vlans),
                "untagged_vlans": ",".join(str(x) for x in p.untagged_vlans),
                "pvid": p.pvid,
                "comment": p.comment,
                "confidence": p.confidence,
            }
        )

    sections = {
        "analyzer_summary": (summary_headers, [summary_row]),
        "analyzer_ports": (ports_headers, ports_rows),
    }
    return sections


def build_sections_from_analyses(results: list[AnalysisResult]) -> dict:
    summary_headers = [
        "identity",
        "mgmt_ip",
        "model",
        "transit_detected",
        "radio_detected",
        "decision",
        "risks",
        "recommendations",
    ]
    summary_rows: list[dict[str, object]] = []
    ports_headers = [
        "identity",
        "port",
        "role",
        "tagged_vlans",
        "untagged_vlans",
        "pvid",
        "comment",
        "confidence",
    ]
    ports_rows: list[dict[str, object]] = []

    for result in results:
        dev = result.device
        summary_rows.append(
            {
                "identity": dev.identity,
                "mgmt_ip": dev.mgmt_ip,
                "model": dev.model,
                "transit_detected": result.transit_detected,
                "radio_detected": result.radio_detected,
                "decision": result.decision,
                "risks": ", ".join(result.risks),
                "recommendations": ", ".join(result.recommendations),
            }
        )
        for n, p in dev.ports.items():
            ports_rows.append(
                {
                    "identity": dev.identity,
                    "port": n,
                    "role": p.role,
                    "tagged_vlans": ",".join(str(x) for x in p.tagged_vlans),
                    "untagged_vlans": ",".join(str(x) for x in p.untagged_vlans),
                    "pvid": p.pvid,
                    "comment": p.comment,
                    "confidence": p.confidence,
                }
            )

    return {
        "analyzer_summary": (summary_headers, summary_rows),
        "analyzer_ports": (ports_headers, ports_rows),
    }
