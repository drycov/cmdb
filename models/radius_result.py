from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict

@dataclass(slots=True)
class RadiusResult:
    radius_added: bool = False
    radius_recreated: bool = False
    radius_present_after: bool = False
    aaa_enabled: bool = False
    aaa_present_after: bool = False