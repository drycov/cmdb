from __future__ import annotations

from typing import Dict, List

from .models import DeviceModel, PortModel


def _to_ints(vals: str | None) -> List[int]:
    if not vals:
        return []
    parts = [p.strip() for p in vals.replace(";", ",").split(",") if p.strip()]
    out: List[int] = []
    for p in parts:
        try:
            out.append(int(p))
        except Exception:
            # attempt to extract numbers
            import re

            m = re.search(r"(\d+)", p)
            if m:
                out.append(int(m.group(1)))
    return out


def classify_ports(device: DeviceModel) -> None:
    # populate PortModel entries from bridge ports, ethernet and bridge vlans
    bridge_ports = device.raw_sections.get("/interface bridge port", [])
    ether_if = {
        e.get("name")
        or e.get("interface")
        or e.get("default-name")
        or e.get("default_name"): e
        for e in device.raw_sections.get("/interface ethernet", [])
    }
    # initialize ports
    for name in ether_if.keys():
        if not name:
            continue
        if name not in device.ports:
            device.ports[name] = PortModel(name=name, comment=ether_if[name].get("comment"))

    for bp in bridge_ports:
        name = bp.get("interface") or bp.get("name") or bp.get("iface")
        if not name:
            continue
        p = device.ports.setdefault(name, PortModel(name=name))
        if "pvid" in bp:
            try:
                p.pvid = int(bp["pvid"])
            except Exception:
                pass
        # edge/restricted flag may be present
        if bp.get("edge") == "yes" or bp.get("restricted-role") == "yes":
            p.confidence = max(p.confidence, 0.6)

    # bridge vlan entries
    for bv in device.raw_sections.get("/interface bridge vlan", []):
        tagged = bv.get("tagged")
        untagged = bv.get("untagged")
        vlan_ids = bv.get("vlan-ids") or bv.get("vlan-id") or bv.get("vlan-ids")
        ids = _to_ints(vlan_ids)
        for vid in ids:
            device.bridge_vlans.setdefault(vid, {"tagged": [], "untagged": []})
            if tagged:
                for ifname in [x.strip() for x in tagged.split(",") if x.strip()]:
                    device.bridge_vlans[vid]["tagged"].append(ifname)
                    p = device.ports.setdefault(ifname, PortModel(name=ifname))
                    if vid not in p.tagged_vlans:
                        p.tagged_vlans.append(vid)
            if untagged:
                for ifname in [x.strip() for x in untagged.split(",") if x.strip()]:
                    device.bridge_vlans[vid]["untagged"].append(ifname)
                    p = device.ports.setdefault(ifname, PortModel(name=ifname))
                    if vid not in p.untagged_vlans:
                        p.untagged_vlans.append(vid)

    # finalize role decisions
    for name, p in device.ports.items():
        # routed: has ip assigned to interface
        if any(a.get("interface") == name for a in device.raw_sections.get("/ip address", [])):
            p.role = "routed"
            p.confidence = max(p.confidence, 0.9)
            continue

        if p.tagged_vlans and not p.untagged_vlans:
            p.role = "trunk"
            p.confidence = max(p.confidence, 0.9 if len(p.tagged_vlans) >= 2 else 0.75)
            continue

        if p.untagged_vlans and not p.tagged_vlans and p.pvid is not None:
            p.role = "access"
            p.confidence = max(p.confidence, 0.9)
            continue

        if p.tagged_vlans and p.untagged_vlans:
            p.role = "hybrid"
            p.confidence = max(p.confidence, 0.7)
            continue

        # fallback: unused vs unknown
        if not p.tagged_vlans and not p.untagged_vlans and p.pvid is None:
            p.role = "unused"
            p.confidence = max(p.confidence, 0.6)
        else:
            p.role = "unknown"
            p.confidence = max(p.confidence, 0.5)
