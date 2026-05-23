"""Implementation details for report writers gsheet."""

import logging
import time
from typing import Any

from gspread.exceptions import APIError

from mikrotik_audit.report.writers.tabular import merge_headers, project_row


class GSheetWriter:
    """Write gsheetwriter output."""
    def __init__(
        self,
        spreadsheet,
        batch_size: int = 500,
        max_batch_cells: int = 10000,
        suppress_cell_limit_errors: bool = True,
        auto_rollover_on_cell_limit: bool = True,
    ) -> None:
        self.spreadsheet = spreadsheet
        self.batch_size = batch_size
        self.max_batch_cells = max(1, max_batch_cells)
        self.suppress_cell_limit_errors = suppress_cell_limit_errors
        self.auto_rollover_on_cell_limit = auto_rollover_on_cell_limit
        self.buffers = {}
        self.headers = {}
        self.sheets = {}
        self.base_spreadsheet_title = getattr(spreadsheet, "title", "MikroTik Audit")
        self.rollover_count = 0

        self.last_call = 0
        self.min_interval = 1.2  # ~50 req/min
        self.disabled = False
        self.disable_reason = ""
        self.logger = logging.getLogger(__name__)

    def open(self) -> None:
        pass

    def begin_section(self, name: str, headers: list[str]) -> None:
        if self.disabled:
            return

        self.buffers.setdefault(name, [])
        self.headers.setdefault(name, headers[:])

        try:
            ws = self._get_or_create(name)
            merged_headers = self._ensure_headers(ws, headers)
        except APIError as error:
            if self._should_rollover(error) and self._try_rollover(error):
                ws = self._get_or_create(name)
                merged_headers = self._ensure_headers(ws, headers)
            elif self._should_suppress_cell_limit_error(error):
                self._disable(self._build_cell_limit_message(error))
                return
            else:
                raise

        self.sheets[name] = ws
        self.headers[name] = merged_headers

    def write_row(self, section: str, row: dict[str, Any]) -> None:
        if self.disabled:
            return

        headers = self.headers[section]
        buffer = self.buffers[section]

        buffer.append(project_row(headers, row))

        if len(buffer) >= self._section_batch_size(section):
            self._flush(section)

    def close_section(self, name: str) -> None:
        if self.disabled:
            return
        self._flush(name)

    def close(self) -> None:
        if self.disabled:
            return
        for name in self.buffers:
            self._flush(name)

    # ----------------------------
    # INTERNAL
    # ----------------------------

    def _flush(self, section: str) -> None:
        if self.disabled:
            return

        buffer = self.buffers[section]
        if not buffer:
            return

        ws = self.sheets[section]
        chunk_size = self._section_batch_size(section)

        self._rate_limit()

        while buffer:
            chunk = buffer[:chunk_size]

            for attempt in range(5):
                try:
                    ws.append_rows(chunk, value_input_option="RAW")
                    del buffer[: len(chunk)]
                    break

                except APIError as e:
                    if "429" in str(e):
                        sleep = 2 ** attempt
                        time.sleep(sleep)
                    elif self._should_suppress_cell_limit_error(e):
                        if self._should_rollover(e) and self._try_rollover(e):
                            ws = self.sheets[section]
                            break
                        self._disable(self._build_cell_limit_message(e))
                        buffer.clear()
                        return
                    else:
                        raise
            else:
                raise RuntimeError("Google Sheets write failed after retries")

    def _rate_limit(self):
        now = time.time()
        delta = now - self.last_call

        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)

        self.last_call = time.time()

    def _get_or_create(self, title: str):
        try:
            return self.spreadsheet.worksheet(title)
        except Exception:
            return self.spreadsheet.add_worksheet(title=title, rows=1000, cols=50)

    def _ensure_headers(self, ws, headers: list[str]) -> list[str]:
        existing_headers = ws.row_values(1)
        if not existing_headers:
            ws.append_row(headers)
            return headers

        merged_headers = merge_headers(existing_headers, headers)

        if len(merged_headers) > len(existing_headers):
            missing_columns = len(merged_headers) - len(existing_headers)
            ws.add_cols(missing_columns)
            ws.update("1:1", [merged_headers], value_input_option="RAW")

        return merged_headers

    def _section_batch_size(self, section: str) -> int:
        header_count = max(1, len(self.headers.get(section, [])))
        max_rows_by_cells = max(1, self.max_batch_cells // header_count)
        return max(1, min(self.batch_size, max_rows_by_cells))

    def _should_suppress_cell_limit_error(self, error: APIError) -> bool:
        return self.suppress_cell_limit_errors and self._is_cell_limit_error(error)

    def _should_rollover(self, error: APIError) -> bool:
        return self._should_suppress_cell_limit_error(error) and self._is_workbook_cell_limit_error(error)

    @staticmethod
    def _is_cell_limit_error(error: APIError) -> bool:
        message = str(error).lower()
        return any(
            marker in message
            for marker in (
                "above the limit of 10000000 cells",
                "limit of 10000000 cells",
                "limit of 10000 cells",
                "exceeds the limit of 10000 cells",
                "too many cells",
            )
        )

    @staticmethod
    def _build_cell_limit_message(error: APIError) -> str:
        message = str(error).lower()
        if "10000000" in message:
            return (
                "Google Sheets workbook reached the 10,000,000 cell limit; "
                "disabling further sheet writes."
            )
        return (
            "Google Sheets export hit the per-request cell limit; "
            "disabling further sheet writes."
        )

    @staticmethod
    def _is_workbook_cell_limit_error(error: APIError) -> bool:
        return "10000000" in str(error)

    def _disable(self, reason: str) -> None:
        if self.disabled:
            return

        self.disabled = True
        self.disable_reason = reason
        for buffered_rows in self.buffers.values():
            buffered_rows.clear()
        self.logger.warning(reason)

    def _try_rollover(self, error: APIError) -> bool:
        if not self.auto_rollover_on_cell_limit:
            return False

        old_title = getattr(self.spreadsheet, "title", self.base_spreadsheet_title)

        try:
            new_spreadsheet = self.spreadsheet.client.create(self._rollover_title())
            self.spreadsheet = new_spreadsheet
            self.sheets = {}
            self.rollover_count += 1

            for section, headers in list(self.headers.items()):
                ws = self._get_or_create(section)
                merged_headers = self._ensure_headers(ws, headers)
                self.sheets[section] = ws
                self.headers[section] = merged_headers
                self.buffers.setdefault(section, [])

            self.logger.warning(
                "Google Sheets workbook '%s' reached the 10,000,000 cell limit; "
                "continuing in rollover workbook '%s'.",
                old_title,
                getattr(new_spreadsheet, "title", self._rollover_title()),
            )
            return True
        except Exception:
            self.logger.exception(
                "Failed to create a rollover Google Sheets workbook after hitting the cell limit: %s",
                error,
            )
            return False

    def _rollover_title(self) -> str:
        suffix = time.strftime("%Y%m%d-%H%M%S")
        next_index = self.rollover_count + 1
        return f"{self.base_spreadsheet_title} [rollover {next_index} {suffix}]"
