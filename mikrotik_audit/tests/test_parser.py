"""Test cases for parser behavior."""

from __future__ import annotations

from mikrotik_audit.app.analyzer import analyze_path, analyze_paths
from mikrotik_audit.app.parser import parse_rsc
from mikrotik_audit.app.report import build_sections_from_analysis


def test_simple_parse(tmp_path):
    """Test that test simple parse."""
    content = '''/system identity set name=ovn916_ukg
/interface ethernet
add name=ether1 comment="uplink_from_US2"
/interface bridge port
add bridge=br1 interface=ether1 pvid=850 edge=yes
/interface bridge vlan
add bridge=br1 tagged=ether1 vlan-ids=850
'''
    p = tmp_path / "sample.rsc"
    p.write_text(content)
    data = parse_rsc(str(p))
    assert "/system identity" in data
    assert any("name" in e for e in data.get("/system identity", [])) or data.get("/system identity")


def test_build_terminations_section_from_comments_and_vlans(tmp_path):
    """Test that test build terminations section from comments and vlans."""
    content = '''/system identity set name=US5_EDGE_SW1
/ip address add address=10.164.200.12/24 comment=uplink_from_US1_mgmt interface=vlan101
/interface ethernet set [ find default-name=sfp2 ] comment=lu4_ovn124
/interface ethernet set [ find default-name=sfp7 ] comment=lu3_ovn123_ovn54
/interface bridge port add bridge=bridge_vlan interface=sfp2
/interface bridge port add bridge=bridge_vlan interface=sfp7
/interface bridge vlan add bridge=bridge_vlan tagged=sfp-sfpplus1,sfp2 vlan-ids=1204
/interface bridge vlan add bridge=bridge_vlan tagged=sfp-sfpplus1,sfp2 vlan-ids=1124
/interface bridge vlan add bridge=bridge_vlan tagged=sfp-sfpplus1,sfp7 vlan-ids=1203
/interface bridge vlan add bridge=bridge_vlan tagged=sfp-sfpplus1,sfp7 vlan-ids=1054
'''
    p = tmp_path / "sample_terminations.rsc"
    p.write_text(content, encoding="utf-8")

    result = analyze_path(str(p))
    sections = build_sections_from_analysis(result)
    headers, rows = sections["terminations"]

    assert headers == ["object", "node", "ip", "vlan"]
    assert rows == [
        {"object": "lu3", "node": "US5_EDGE_SW1", "ip": "10.164.200.12", "vlan": "1054,1203"},
        {"object": "lu4", "node": "US5_EDGE_SW1", "ip": "10.164.200.12", "vlan": "1124,1204"},
        {"object": "ovn123", "node": "US5_EDGE_SW1", "ip": "10.164.200.12", "vlan": "1054,1203"},
        {"object": "ovn124", "node": "US5_EDGE_SW1", "ip": "10.164.200.12", "vlan": "1124,1204"},
        {"object": "ovn54", "node": "US5_EDGE_SW1", "ip": "10.164.200.12", "vlan": "1054,1203"},
    ]


def test_analyze_paths_returns_result_for_each_file(tmp_path):
    """Test that test analyze paths returns result for each file."""
    first = tmp_path / "first.rsc"
    second = tmp_path / "second.rsc"
    first.write_text("/system identity set name=first\n", encoding="utf-8")
    second.write_text("/system identity set name=second\n", encoding="utf-8")

    results = analyze_paths([str(first), str(second)])

    assert [result.device.identity for result in results] == ["first", "second"]
