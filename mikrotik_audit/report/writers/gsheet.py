import time
from gspread.exceptions import APIError


class GSheetWriter:
    def __init__(self, spreadsheet, batch_size: int = 500) -> None:
        self.spreadsheet = spreadsheet
        self.batch_size = batch_size
        self.buffers = {}
        self.headers = {}
        self.sheets = {}

        self.last_call = 0
        self.min_interval = 1.2  # ~50 req/min

    def open(self) -> None:
        pass

    def begin_section(self, name: str, headers: list[str]) -> None:
        ws = self._get_or_create(name)
        merged_headers = self._ensure_headers(ws, headers)

        self.sheets[name] = ws
        self.headers[name] = merged_headers
        self.buffers[name] = []

    def write_row(self, section: str, row: dict) -> None:
        headers = self.headers[section]
        buffer = self.buffers[section]

        buffer.append([row.get(h, "") for h in headers])

        if len(buffer) >= self.batch_size:
            self._flush(section)

    def close_section(self, name: str) -> None:
        self._flush(name)

    def close(self) -> None:
        for name in self.buffers:
            self._flush(name)

    # ----------------------------
    # INTERNAL
    # ----------------------------

    def _flush(self, section: str) -> None:
        buffer = self.buffers[section]
        if not buffer:
            return

        ws = self.sheets[section]

        self._rate_limit()

        for attempt in range(5):
            try:
                ws.append_rows(buffer, value_input_option="RAW")
                buffer.clear()
                return

            except APIError as e:
                if "429" in str(e):
                    sleep = 2 ** attempt
                    time.sleep(sleep)
                else:
                    raise

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
        except:
            return self.spreadsheet.add_worksheet(title=title, rows=1000, cols=50)

    def _ensure_headers(self, ws, headers: list[str]) -> list[str]:
        existing_headers = ws.row_values(1)
        if not existing_headers:
            ws.append_row(headers)
            return headers

        merged_headers = existing_headers[:]
        for header in headers:
            if header not in merged_headers:
                merged_headers.append(header)

        if len(merged_headers) > len(existing_headers):
            missing_columns = len(merged_headers) - len(existing_headers)
            ws.add_cols(missing_columns)
            ws.update("1:1", [merged_headers], value_input_option="RAW")

        return merged_headers
