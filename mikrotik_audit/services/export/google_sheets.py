"""Implementation details for services export google_sheets."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Iterable

import gspread
from google.oauth2.service_account import Credentials

from mikrotik_audit.models import AuditResult

from .common import (
    INVENTORY_HEADERS,
    PHPIPAM_MISMATCH_HEADERS,
    TOPOLOGY_HEADERS,
    VLAN_HEADERS,
    build_phpipam_mismatch_rows,
    build_summary_rows,
    build_topology_rows,
    build_vlan_rows,
    rows_by_headers,
)


class GoogleSheetsExporter:
    """Represent googlesheetsexporter."""
    INVENTORY_SHEET = "mikrotik_inventory"
    SUMMARY_SHEET = "summary"
    TOPOLOGY_SHEET = "topology"
    MISMATCH_SHEET = "phpipam_mismatches"
    RAW_SHEET = "raw_inventory"
    VLAN_SHEET = "vlans"

    BATCH_SIZE = 500  # 🔥 ключ для streaming

    def __init__(
        self,
        credentials_path: str,
        spreadsheet_name: str,
        worksheet_name: str,
        logger: logging.Logger,
    ) -> None:
        self.logger = logger
        self.worksheet_name = worksheet_name or self.INVENTORY_SHEET

        creds = Credentials.from_service_account_file(
            credentials_path,
            scopes=[
                "https://www.googleapis.com/auth/spreadsheets",
                "https://www.googleapis.com/auth/drive",
            ],
        )

        self.client = gspread.authorize(creds)
        self.spreadsheet = self.client.open(spreadsheet_name)

    # ---------------------------------------------------
    # ENTRYPOINT
    # ---------------------------------------------------

    def export(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            self.logger.warning("Google Sheets export: no rows")
            return

        results = (AuditResult(**row) for row in rows)  # 🔥 generator

        self._export_inventory(results)
        self._export_summary(rows)  # summary проще через rows
        self._export_mismatches(rows)
        self._export_topology(rows)
        self._export_vlans(rows)
        self._export_raw_inventory(rows)

    # ---------------------------------------------------
    # CORE STREAMING EXPORT
    # ---------------------------------------------------

    def _stream_to_sheet(
        self,
        *,
        title: str,
        headers: list[str],
        rows: Iterable[dict[str, Any]],
    ) -> None:
        ws = self._get_or_create_worksheet(title)

        self._retry(lambda: ws.clear())
        self._retry(lambda: ws.update([headers]))

        batch: list[list[Any]] = []

        for row in rows:
            batch.append([row.get(h, "") for h in headers])

            if len(batch) >= self.BATCH_SIZE:
                self._append_batch(ws, batch)
                batch.clear()

        if batch:
            self._append_batch(ws, batch)

    def _append_batch(self, ws, batch):
        self._retry(lambda: ws.append_rows(batch, value_input_option="RAW"))

    # ---------------------------------------------------
    # SECTIONS
    # ---------------------------------------------------

    def _export_inventory(self, results: Iterable[AuditResult]) -> None:
        self._stream_to_sheet(
            title=self.INVENTORY_SHEET,
            headers=INVENTORY_HEADERS,
            rows=rows_by_headers(results, INVENTORY_HEADERS),
        )

    def _export_summary(self, rows: list[dict[str, Any]]) -> None:
        ws = self._get_or_create_worksheet(self.SUMMARY_SHEET)

        values = [["metric", "value"], *build_summary_rows([AuditResult(**r) for r in rows])]

        self._retry(lambda: ws.clear())
        self._retry(lambda: ws.update(values))

    def _export_mismatches(self, rows: list[dict[str, Any]]) -> None:
        results = [AuditResult(**r) for r in rows]

        self._stream_to_sheet(
            title=self.MISMATCH_SHEET,
            headers=PHPIPAM_MISMATCH_HEADERS,
            rows=build_phpipam_mismatch_rows(results),
        )

    def _export_topology(self, rows: list[dict[str, Any]]) -> None:
        results = [AuditResult(**r) for r in rows]

        self._stream_to_sheet(
            title=self.TOPOLOGY_SHEET,
            headers=TOPOLOGY_HEADERS,
            rows=build_topology_rows(results),
        )

    def _export_vlans(self, rows: list[dict[str, Any]]) -> None:
        results = [AuditResult(**r) for r in rows]

        self._stream_to_sheet(
            title=self.VLAN_SHEET,
            headers=VLAN_HEADERS,
            rows=build_vlan_rows(results),
        )

    def _export_raw_inventory(self, rows: list[dict[str, Any]]) -> None:
        self._stream_to_sheet(
            title=self.RAW_SHEET,
            headers=AuditResult.EXPORT_HEADERS,
            rows=rows,
        )

    # ---------------------------------------------------
    # UTILS
    # ---------------------------------------------------

    def _get_or_create_worksheet(self, title: str):
        try:
            return self.spreadsheet.worksheet(title)
        except gspread.WorksheetNotFound:
            return self.spreadsheet.add_worksheet(title=title, rows=1000, cols=50)

    def _retry(self, fn: Callable[[], Any]) -> Any:
        last_exc = None

        for attempt in range(1, 4):
            try:
                return fn()
            except Exception as exc:
                last_exc = exc
                self.logger.warning(
                    "Sheets error attempt=%s err=%s",
                    attempt,
                    exc,
                )
                time.sleep(attempt * 2)

        raise RuntimeError("Sheets failed") from last_exc
