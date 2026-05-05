from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PHPIPAMAddress:
    id: str = ""
    ip: str = ""
    hostname: str = ""
    description: str = ""
    custom_version: str = ""
    custom_board_name: str = ""
    custom_platform: str = ""
    custom_architecture: str = ""
    custom_status: str = ""