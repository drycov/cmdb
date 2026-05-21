from __future__ import annotations

import re
from typing import Dict, List


def _parse_kv_pairs(text: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    # simple key=value parsing, handles quoted values
    for m in re.finditer(r"(\S+?)=(\".*?\"|\S+)", text):
        k = m.group(1)
        v = m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        pairs[k] = v
    return pairs


def parse_rsc(path: str) -> Dict[str, List[Dict[str, str]]]:
    sections: Dict[str, List[Dict[str, str]]] = {}
    current_section = None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("/"):
                # section command
                parts = line.split()
                # e.g. /interface bridge add name=br1 vlan-filtering=yes
                actions = {"add", "set", "remove", "print", "enable", "disable", "comment", "find", "edit"}
                if len(parts) > 3 and parts[2] not in actions and parts[3] in actions:
                    section = " ".join(parts[:3])
                    cmd = parts[3]
                    rest = " ".join(parts[4:])
                else:
                    section = " ".join(parts[:2]) if len(parts) > 1 else parts[0]
                    cmd = parts[2] if len(parts) > 2 else ""
                    rest = " ".join(parts[3:]) if len(parts) > 3 else ""
                current_section = section
                sections.setdefault(current_section, []).append({
                    "cmd": cmd,
                    "raw": rest,
                    **_parse_kv_pairs(rest),
                })
            else:
                # continuation or command without leading slash
                if current_section is None:
                    continue
                sections.setdefault(current_section, []).append({"cmd": "line", "raw": line})

    return sections
