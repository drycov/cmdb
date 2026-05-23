"""Implementation details for app report."""

from __future__ import annotations

import json
import re
from typing import Dict, Iterable

from .analysis_support import (
    PORT_HEADERS,
    PORT_HEADERS_WITH_IDENTITY,
    SUMMARY_HEADERS,
    build_all_port_rows,
    build_port_rows,
    build_summary_row,
    build_summary_rows,
)
from .models import AnalysisResult


TERMINATION_HEADERS = ["object", "node", "ip", "vlan"]
_OBJECT_TOKEN_RE = re.compile(r"^(?:ovn\d+(?:-\d+)?|lu\d+(?:-\d+)?|p\d+(?:-\d+)?|\d{3,5})$", re.IGNORECASE)


def _extract_comment_objects(comment: str | None) -> list[str]:
    """Internal helper for extract comment objects."""
    if not comment:
        return []

    raw_tokens = re.split(r"[+_/\s,;]+", comment)
    objects: list[str] = []
    seen: set[str] = set()

    for raw_token in raw_tokens:
        token = raw_token.strip().strip("\"'()[]{}").lower()
        if not token or not _OBJECT_TOKEN_RE.match(token):
            continue
        if token in seen:
            continue
        seen.add(token)
        objects.append(token)

    return objects


def _port_vlans(port) -> list[int]:
    """Internal helper for port vlans."""
    vlans = set(port.tagged_vlans or [])
    vlans.update(port.untagged_vlans or [])
    if port.pvid is not None:
        vlans.add(port.pvid)
    return sorted(vlans)


def _build_termination_rows(result: AnalysisResult) -> list[dict[str, object]]:
    """Internal helper for build termination rows."""
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str]] = set()
    device = result.device

    for port in device.ports.values():
        objects = _extract_comment_objects(port.comment)
        if not objects:
            continue

        vlan_values = _port_vlans(port)
        vlan_text = ",".join(str(vlan) for vlan in vlan_values)

        for object_name in objects:
            key = (object_name, device.identity, device.mgmt_ip or "", vlan_text)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "object": object_name,
                    "node": device.identity,
                    "ip": device.mgmt_ip or "",
                    "vlan": vlan_text,
                }
            )

    rows.sort(key=lambda row: (str(row["object"]), str(row["node"]), str(row["ip"]), str(row["vlan"])))
    return rows


def to_json(result: AnalysisResult) -> str:
    """Handle to json."""
    def _port_to_dict(port):
        return {
            "role": port.role,
            "tagged_vlans": port.tagged_vlans,
            "untagged_vlans": port.untagged_vlans,
            "pvid": port.pvid,
            "comment": port.comment,
            "confidence": port.confidence,
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
    """Handle to markdown."""
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
    """Build sections from analysis."""
    sections = {
        "analyzer_summary": (SUMMARY_HEADERS, [build_summary_row(result)]),
        "analyzer_ports": (PORT_HEADERS, build_port_rows(result)),
        "terminations": (TERMINATION_HEADERS, _build_termination_rows(result)),
    }
    return sections


def build_sections_from_analyses(results: list[AnalysisResult]) -> dict:
    """Build sections from analyses."""
    termination_rows = _build_termination_rows_for_all(results)

    return {
        "analyzer_summary": (SUMMARY_HEADERS, build_summary_rows(results)),
        "analyzer_ports": (PORT_HEADERS_WITH_IDENTITY, build_all_port_rows(results)),
        "terminations": (TERMINATION_HEADERS, termination_rows),
    }


def _build_termination_rows_for_all(results: Iterable[AnalysisResult]) -> list[dict[str, object]]:
    """Internal helper for build termination rows for all."""
    rows: list[dict[str, object]] = []
    for result in results:
        rows.extend(_build_termination_rows(result))
    return rows
