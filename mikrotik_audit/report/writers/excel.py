from __future__ import annotations
from typing import Any
from openpyxl import Workbook


class ExcelWriter:
    def __init__(self, path: str) -> None:
        self.path = path
        self.wb = None
        self.sheets = {}
        self.headers = {}

    def open(self) -> None:
        self.wb = Workbook(write_only=True)

    def begin_section(self, name: str, headers: list[str]) -> None:
        ws = self.wb.create_sheet(title=name)
        self.sheets[name] = ws
        self.headers[name] = headers

        ws.append(headers)

    def write_row(self, section: str, row: dict[str, Any]) -> None:
        ws = self.sheets[section]
        headers = self.headers[section]

        ws.append([row.get(h, "") for h in headers])

    def close_section(self, name: str) -> None:
        pass

    def close(self) -> None:
        self.wb.save(self.path)