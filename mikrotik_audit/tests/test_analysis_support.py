"""Test cases for analysis support behavior."""

from __future__ import annotations

from mikrotik_audit.app.analysis_support import (
    build_port_rows,
    build_summary_row,
    finalize_decision,
)
from mikrotik_audit.app.models import AnalysisResult, DeviceModel, PortModel


def test_finalize_decision_marks_safe_when_mgmt_and_trunk_present() -> None:
    """Test that test finalize decision marks safe when mgmt and trunk present."""
    result = AnalysisResult(
        device=DeviceModel(
            identity="r1",
            mgmt_ip="10.0.0.1",
            ports={
                "ether1": PortModel(name="ether1", role="trunk", tagged_vlans=[850, 851]),
            },
        )
    )

    finalize_decision(result)

    assert result.decision == "SAFE_TO_REVIEW"
    assert result.recommendations


def test_build_summary_row_flattens_lists_for_export() -> None:
    """Test that test build summary row flattens lists for export."""
    result = AnalysisResult(
        device=DeviceModel(identity="r1", mgmt_ip="10.0.0.1", model="RB5009"),
        risks=["risk-a", "risk-b"],
        recommendations=["rec-a", "rec-b"],
    )

    row = build_summary_row(result)

    assert row["risks"] == "risk-a, risk-b"
    assert row["recommendations"] == "rec-a, rec-b"


def test_build_port_rows_can_include_identity() -> None:
    """Test that test build port rows can include identity."""
    result = AnalysisResult(
        device=DeviceModel(
            identity="r1",
            ports={
                "ether1": PortModel(
                    name="ether1",
                    role="access",
                    tagged_vlans=[],
                    untagged_vlans=[100],
                    pvid=100,
                    comment="user-port",
                    confidence=0.9,
                )
            },
        )
    )

    rows = build_port_rows(result, include_identity=True)

    assert rows == [
        {
            "identity": "r1",
            "port": "ether1",
            "role": "access",
            "tagged_vlans": "",
            "untagged_vlans": "100",
            "pvid": 100,
            "comment": "user-port",
            "confidence": 0.9,
        }
    ]
