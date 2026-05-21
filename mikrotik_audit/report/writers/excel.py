from __future__ import annotations

from pathlib import Path
from typing import Any

from openpyxl import Workbook, load_workbook


class ExcelWriter:
    def __init__(self, path: str) -> None:
        self.path = path
        self.wb = None
        self.sheets = {}
        self.headers = {}
        self._created_new = False

    def open(self) -> None:
        workbook_path = Path(self.path)
        if workbook_path.exists():
            self.wb = load_workbook(workbook_path)
            self._created_new = False
            return

        self.wb = Workbook()
        self._created_new = True

    def begin_section(self, name: str, headers: list[str]) -> None:
        self._remove_default_sheet()

        if name in self.wb.sheetnames:
            ws = self.wb[name]
            merged_headers = self._ensure_headers(ws, headers)
        else:
            ws = self.wb.create_sheet(title=name)
            ws.append(headers)
            merged_headers = headers

        self.sheets[name] = ws
        self.headers[name] = merged_headers

    def write_row(self, section: str, row: dict[str, Any]) -> None:
        ws = self.sheets[section]
        headers = self.headers[section]

        ws.append([row.get(h, "") for h in headers])

    def close_section(self, name: str) -> None:
        pass

    def close(self) -> None:
        self.wb.save(self.path)

    def _remove_default_sheet(self) -> None:
        if not self._created_new:
            return

        if self.wb.sheetnames != ["Sheet"]:
            return

        sheet = self.wb["Sheet"]
        if sheet.max_row == 1 and sheet.max_column == 1 and sheet["A1"].value is None:
            self.wb.remove(sheet)

    def _ensure_headers(self, ws, headers: list[str]) -> list[str]:
        existing_headers = self._read_headers(ws)
        if not existing_headers:
            ws.append(headers)
            return headers

        merged_headers = existing_headers[:]
        for header in headers:
            if header not in merged_headers:
                merged_headers.append(header)
                ws.cell(row=1, column=len(merged_headers), value=header)
        return merged_headers

    @staticmethod
    def _read_headers(ws) -> list[str]:
        if ws.max_row < 1:
            return []

        values = [cell.value for cell in ws[1]]
        if not any(value is not None and value != "" for value in values):
            return []
        return ["" if value is None else str(value) for value in values]
