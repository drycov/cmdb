"""Test cases for gsheet writer behavior."""

from __future__ import annotations

from gspread.exceptions import APIError

from mikrotik_audit.report.writers.gsheet import GSheetWriter


class FakeResponse:
    """Define the fakeresponse schema."""
    status_code = 400
    text = "Request exceeds the limit of 10000000 cells"

    def json(self) -> dict[str, object]:
        return {
            "error": {
                "code": 400,
                "message": self.text,
                "status": "INVALID_ARGUMENT",
            }
        }


def make_cell_limit_error() -> APIError:
    """Handle make cell limit error."""
    return APIError(FakeResponse())


class FakeWorksheet:
    """Represent fakeworksheet."""
    def __init__(self, spreadsheet, title: str) -> None:
        self.spreadsheet = spreadsheet
        self.title = title
        self.header: list[str] = []
        self.rows: list[list[object]] = []

    def row_values(self, index: int) -> list[str]:
        return self.header[:] if index == 1 else []

    def append_row(self, values: list[str]) -> None:
        self.header = values[:]

    def add_cols(self, count: int) -> None:
        return None

    def update(self, cell_range: str, values: list[list[str]], value_input_option: str = "RAW") -> None:
        self.header = values[0][:]

    def append_rows(self, rows: list[list[object]], value_input_option: str = "RAW") -> None:
        if self.spreadsheet.fail_next_append:
            self.spreadsheet.fail_next_append = False
            raise make_cell_limit_error()
        self.rows.extend([row[:] for row in rows])


class FakeClient:
    """Communicate through the fakeclient client."""
    def __init__(self) -> None:
        self.created: list[FakeSpreadsheet] = []

    def create(self, title: str):
        spreadsheet = FakeSpreadsheet(title=title, client=self)
        self.created.append(spreadsheet)
        return spreadsheet


class FakeSpreadsheet:
    """Represent fakespreadsheet."""
    def __init__(self, title: str, client: FakeClient, fail_next_append: bool = False) -> None:
        self.title = title
        self.client = client
        self.fail_next_append = fail_next_append
        self._worksheets: dict[str, FakeWorksheet] = {}

    def worksheet(self, title: str) -> FakeWorksheet:
        if title not in self._worksheets:
            raise KeyError(title)
        return self._worksheets[title]

    def add_worksheet(self, title: str, rows: int, cols: int) -> FakeWorksheet:
        worksheet = FakeWorksheet(self, title)
        self._worksheets[title] = worksheet
        return worksheet


def test_gsheet_writer_rolls_over_to_new_workbook_on_cell_limit(monkeypatch) -> None:
    """Test that test gsheet writer rolls over to new workbook on cell limit."""
    client = FakeClient()
    spreadsheet = FakeSpreadsheet("Audit Workbook", client=client, fail_next_append=True)
    writer = GSheetWriter(spreadsheet=spreadsheet, batch_size=1)

    writer.begin_section("analyzer_summary", ["identity", "decision"])
    writer.write_row("analyzer_summary", {"identity": "r1", "decision": "keep"})
    writer.close_section("analyzer_summary")

    assert writer.disabled is False
    assert len(client.created) == 1
    rollover_book = client.created[0]
    assert rollover_book.title.startswith("Audit Workbook [rollover 1 ")
    assert spreadsheet._worksheets["analyzer_summary"].rows == []
    assert rollover_book._worksheets["analyzer_summary"].rows == [["r1", "keep"]]
