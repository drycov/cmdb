from __future__ import annotations

import json
from typing import Any


class JsonWriter:
    def __init__(self, path: str) -> None:
        self.path = path
        self.f = None

    def open(self) -> None:
        self.f = open(self.path, "a", encoding="utf-8")

    def begin_section(self, name: str, headers: list[str]) -> None:
        self.current_section = name

    def write_row(self, section: str, row: dict[str, Any]) -> None:
        payload = {"section": section, **row}
        self.f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def close_section(self, name: str) -> None:
        pass

    def close(self) -> None:
        self.f.close()
