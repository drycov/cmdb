from __future__ import annotations

from mikrotik_audit.app.parser import parse_rsc


def test_simple_parse(tmp_path):
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
