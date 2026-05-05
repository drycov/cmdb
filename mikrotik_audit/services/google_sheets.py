from __future__ import annotations

import logging
import time
from collections import Counter
from typing import Any

import gspread
from google.oauth2.service_account import Credentials

from models import AuditResult


class GoogleSheetsExporter:
    INVENTORY_SHEET = "mikrotik_inventory"
    SUMMARY_SHEET = "summary"
    TOPOLOGY_SHEET = "topology"
    MISMATCH_SHEET = "phpipam_mismatches"
    RAW_SHEET = "raw_inventory"
    INVENTORY_HEADERS = [
        "ip",
        "identity",
        "status",
        "inventory_status",
        "inventory_severity",
        "phpipam_match_type",
        "phpipam_hostname",
        "phpipam_ip",
        "version",
        "board_name",
        "platform",
        "architecture",
        "ospf_instance_count",
        "ospf_neighbor_count",
        "bridge_count",
        "bridge_port_count",
        "scheduler_count",
        "dhcp_server_count",
        "dhcp_client_count",
        "ssh_port_value",
        "winbox_port_value",
        "firewall_filter_count",
        "firewall_nat_count",
        "route_count",
        "default_route_count",
        "vlan_count",
        "radius_count",
        "watchdog_enabled",
        "ping",
        "ssh_port",
        "auth_method",
        "firmware_target_version",
        "firmware_error",
        "phpipam_note",
    ]
    TOPOLOGY_HEADERS = [
        "ip",
        "identity",
        "board_name",
        "mac_address",
        "uplink_interface",
        "uplink_mac",
        "neighbor_identity",
        "neighbor_address",
        "neighbor_interface",
        "neighbor_mac",
    ]
    PHPIPAM_MISMATCH_HEADERS = [
        "ip",
        "identity",
        "inventory_status",
        "inventory_severity",
        "phpipam_match_type",
        "phpipam_hostname",
        "phpipam_ip",
        "phpipam_address_id",
        "phpipam_description",
        "phpipam_note",
        "status",
        "version",
        "board_name",
    ]

    SEVERITY_COLORS = {
        "INFO": {"red": 0.85, "green": 1.0, "blue": 0.85},
        "WARNING": {"red": 1.0, "green": 0.95, "blue": 0.70},
        "ERROR": {"red": 1.0, "green": 0.80, "blue": 0.80},
    }

    HEADER_COLOR = {"red": 0.20, "green": 0.20, "blue": 0.20}

    def __init__(
        self,
        credentials_path: str,
        spreadsheet_name: str,
        worksheet_name: str,
        logger: logging.Logger,
    ) -> None:
        self.logger = logger
        self.worksheet_name = worksheet_name or self.INVENTORY_SHEET

        scopes = [
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ]

        creds = Credentials.from_service_account_file(
            credentials_path,
            scopes=scopes,
        )

        self.client = gspread.authorize(creds)
        self.spreadsheet = self.client.open(spreadsheet_name)

    def export(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            self.logger.warning("Google Sheets export: no rows")
            return

        normalized_rows = [
            {header: row.get(header, "") for header in AuditResult.EXPORT_HEADERS}
            for row in rows
        ]

        inventory_ws = self._get_or_create_worksheet(
            self.worksheet_name,
            rows=max(len(normalized_rows) + 10, 1000),
            cols=max(len(self.INVENTORY_HEADERS) + 5, 50),
        )

        self._export_inventory(inventory_ws, self.INVENTORY_HEADERS, normalized_rows)
        self._export_summary(normalized_rows)
        self._export_mismatches(normalized_rows)
        self._export_topology(normalized_rows)
        self._export_raw_inventory(normalized_rows)

        self.logger.info(
            "Google Sheets export completed rows=%s columns=%s",
            len(normalized_rows),
            len(self.INVENTORY_HEADERS),
        )
        
    def _clear_filter(self, worksheet):
        body = {
            "requests": [
                {
                    "clearBasicFilter": {
                        "sheetId": worksheet.id
                    }
                }
            ]
        }

        try:
            self.spreadsheet.batch_update(body)
        except Exception:
            pass  # фильтра может не быть — это нормально

    def _apply_filter(self, worksheet, headers_count: int, rows_count: int):
        end_col = headers_count - 1
        end_row = rows_count

        body = {
            "requests": [
                {
                    "setBasicFilter": {
                        "filter": {
                            "range": {
                                "sheetId": worksheet.id,
                                "startRowIndex": 0,
                                "endRowIndex": end_row + 1,
                                "startColumnIndex": 0,
                                "endColumnIndex": end_col + 1,
                            }
                        }
                    }
                }
            ]
        }

        self._retry(lambda: self.spreadsheet.batch_update(body))

    def _export_inventory(
        self,
        worksheet: gspread.Worksheet,
        headers: list[str],
        rows: list[dict[str, Any]],
    ) -> None:
        values = [headers]
        values.extend([[row.get(header, "") for header in headers] for row in rows])

        self._retry(lambda: worksheet.clear())
        self._retry(lambda: worksheet.update(values, value_input_option="RAW"))

        worksheet.freeze(rows=1)
        self._clear_filter(worksheet)

        self._apply_filter(worksheet, len(headers), len(rows))
        self._format_header(worksheet, len(headers))
        self._format_inventory_rows(worksheet, rows)

    def _export_mismatches(self, rows: list[dict[str, Any]]) -> None:
        mismatch_rows = [
            row for row in rows if str(row.get("inventory_status", "OK")) != "OK"
        ]
        worksheet = self._get_or_create_worksheet(
            self.MISMATCH_SHEET,
            rows=max(len(mismatch_rows) + 10, 100),
            cols=max(len(self.PHPIPAM_MISMATCH_HEADERS) + 5, 20),
        )
        self._export_inventory(
            worksheet,
            self.PHPIPAM_MISMATCH_HEADERS,
            mismatch_rows,
        )

    def _export_topology(self, rows: list[dict[str, Any]]) -> None:
        topology_rows = [
            row
            for row in rows
            if any(
                [
                    row.get("uplink_interface"),
                    row.get("uplink_mac"),
                    row.get("neighbor_identity"),
                    row.get("neighbor_address"),
                    row.get("neighbor_interface"),
                    row.get("neighbor_mac"),
                ]
            )
        ]
        worksheet = self._get_or_create_worksheet(
            self.TOPOLOGY_SHEET,
            rows=max(len(topology_rows) + 10, 100),
            cols=max(len(self.TOPOLOGY_HEADERS) + 5, 20),
        )
        self._export_inventory(
            worksheet,
            self.TOPOLOGY_HEADERS,
            topology_rows,
        )

    def _export_raw_inventory(self, rows: list[dict[str, Any]]) -> None:
        worksheet = self._get_or_create_worksheet(
            self.RAW_SHEET,
            rows=max(len(rows) + 10, 1000),
            cols=max(len(AuditResult.EXPORT_HEADERS) + 5, 50),
        )
        self._export_inventory(
            worksheet,
            AuditResult.EXPORT_HEADERS,
            rows,
        )

    def _export_summary(self, rows: list[dict[str, Any]]) -> None:
        worksheet = self._get_or_create_worksheet(
            self.SUMMARY_SHEET,
            rows=100,
            cols=20,
        )

        status_counter = Counter(row.get("inventory_status", "UNKNOWN") for row in rows)
        severity_counter = Counter(row.get("inventory_severity", "UNKNOWN") for row in rows)
        match_counter = Counter(row.get("phpipam_match_type", "UNKNOWN") for row in rows)

        total = len(rows)
        ok = status_counter.get("OK", 0)
        compliance = round((ok / total) * 100, 2) if total else 0

        values = [
            ["metric", "value"],
            ["total_devices", total],
            ["compliance_percent", compliance],
            ["ok", status_counter.get("OK", 0)],
            ["hostname_mismatch", status_counter.get("HOSTNAME_MISMATCH", 0)],
            ["hostname_partial_match", status_counter.get("HOSTNAME_PARTIAL_MATCH", 0)],
            ["hostname_incomplete", status_counter.get("HOSTNAME_INCOMPLETE", 0)],
            ["not_found", status_counter.get("NOT_FOUND", 0)],
            ["duplicate", status_counter.get("DUPLICATE", 0)],
            ["severity_info", severity_counter.get("INFO", 0)],
            ["severity_warning", severity_counter.get("WARNING", 0)],
            ["severity_error", severity_counter.get("ERROR", 0)],
            ["match_ip", match_counter.get("ip", 0)],
            ["match_hostname", match_counter.get("hostname", 0)],
            ["match_partial_hostname", match_counter.get("partial_hostname", 0)],
            ["match_not_found", match_counter.get("not_found", 0)],
        ]

        self._retry(lambda: worksheet.clear())
        self._retry(lambda: worksheet.update(values, value_input_option="RAW"))

        worksheet.freeze(rows=1)
        self._format_header(worksheet, 2)

    def _format_header(self, worksheet: gspread.Worksheet, columns_count: int) -> None:
        requests = [
            {
                "repeatCell": {
                    "range": {
                        "sheetId": worksheet.id,
                        "startRowIndex": 0,
                        "endRowIndex": 1,
                        "startColumnIndex": 0,
                        "endColumnIndex": columns_count,
                    },
                    "cell": {
                        "userEnteredFormat": {
                            "backgroundColor": self.HEADER_COLOR,
                            "textFormat": {
                                "bold": True,
                                "foregroundColor": {
                                    "red": 1,
                                    "green": 1,
                                    "blue": 1,
                                },
                            },
                        }
                    },
                    "fields": "userEnteredFormat(backgroundColor,textFormat)",
                }
            }
        ]

        self._retry(lambda: self.spreadsheet.batch_update({"requests": requests}))

    def _format_inventory_rows(
        self,
        worksheet: gspread.Worksheet,
        rows: list[dict[str, Any]],
    ) -> None:
        requests = []

        for idx, row in enumerate(rows, start=1):
            severity = str(row.get("inventory_severity", "")).upper()
            color = self.SEVERITY_COLORS.get(severity)

            if not color:
                continue

            requests.append(
                {
                    "repeatCell": {
                        "range": {
                            "sheetId": worksheet.id,
                            "startRowIndex": idx,
                            "endRowIndex": idx + 1,
                        },
                        "cell": {
                            "userEnteredFormat": {
                                "backgroundColor": color,
                            }
                        },
                        "fields": "userEnteredFormat.backgroundColor",
                    }
                }
            )

        for chunk in self._chunks(requests, 500):
            self._retry(lambda chunk=chunk: self.spreadsheet.batch_update({"requests": chunk}))

    def _get_or_create_worksheet(
        self,
        title: str,
        rows: int,
        cols: int,
    ) -> gspread.Worksheet:
        try:
            return self.spreadsheet.worksheet(title)
        except gspread.WorksheetNotFound:
            return self.spreadsheet.add_worksheet(
                title=title,
                rows=rows,
                cols=cols,
            )

    def _retry(self, fn):
        last_exc: Exception | None = None

        for attempt in range(1, 4):
            try:
                return fn()
            except Exception as exc:
                last_exc = exc
                self.logger.warning(
                    "Google Sheets operation failed attempt=%s error=%s",
                    attempt,
                    exc,
                )
                time.sleep(attempt * 2)

        raise RuntimeError("Google Sheets operation failed after retries") from last_exc

    @staticmethod
    def _chunks(items: list[dict[str, Any]], size: int):
        for i in range(0, len(items), size):
            yield items[i : i + size]
