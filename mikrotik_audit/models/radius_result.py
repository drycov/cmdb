"""Implementation details for models radius_result."""

from __future__ import annotations

from dataclasses import dataclass

@dataclass(slots=True)
class RadiusResult:
    """Represent the radiusresult payload."""
    radius_added: bool = False
    radius_recreated: bool = False
    radius_present_after: bool = False
    aaa_enabled: bool = False
    aaa_present_after: bool = False
