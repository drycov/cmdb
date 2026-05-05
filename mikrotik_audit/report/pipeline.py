from __future__ import annotations

from collections.abc import AsyncIterable

from services.export.common import (
    INVENTORY_HEADERS,
    ISSUE_HEADERS,
    PHPIPAM_MISMATCH_HEADERS,
    TOPOLOGY_HEADERS,
    VLAN_HEADERS,
)
from models import AuditResult

from .adapters import (
    inventory_row,
    issue_rows,
    mismatch_rows,
    raw_row,
    topology_rows,
    vlan_rows,
)
from .summary import SummaryAccumulator
from .writers.base import ReportWriter


class ReportPipeline:
    def __init__(self, writers: list[ReportWriter]) -> None:
        self.writers = writers
        self.summary = SummaryAccumulator()

    async def run(self, results: AsyncIterable[AuditResult]) -> None:
        try:
            self._open()
            self._begin_sections()

            async for result in results:
                self.summary.add(result)

                self._write("mikrotik_inventory", inventory_row(result))
                self._write("raw_inventory", raw_row(result))

                for row in topology_rows(result):
                    self._write("topology", row)

                for row in mismatch_rows(result):
                    self._write("phpipam_mismatches", row)

                for row in issue_rows(result):
                    self._write("issues", row)

                for row in vlan_rows(result):
                    self._write("vlans", row)

            self._begin_summary()

            for row in self.summary.rows():
                self._write("summary", row)

        finally:
            self._close_sections()
            self._close()

    def _open(self) -> None:
        for writer in self.writers:
            writer.open()

    def _begin_sections(self) -> None:
        sections = {
            "mikrotik_inventory": INVENTORY_HEADERS,
            "topology": TOPOLOGY_HEADERS,
            "phpipam_mismatches": PHPIPAM_MISMATCH_HEADERS,
            "issues": ISSUE_HEADERS,
            "vlans": VLAN_HEADERS,
            "raw_inventory": AuditResult.EXPORT_HEADERS,
        }

        for name, headers in sections.items():
            for writer in self.writers:
                writer.begin_section(name, headers)

    def _begin_summary(self) -> None:
        for writer in self.writers:
            writer.begin_section("summary", ["metric", "value"])

    def _write(self, section: str, row: dict) -> None:
        for writer in self.writers:
            writer.write_row(section, row)

    def _close_sections(self) -> None:
        for name in [
            "mikrotik_inventory",
            "topology",
            "phpipam_mismatches",
            "issues",
            "vlans",
            "raw_inventory",
            "summary",
        ]:
            for writer in self.writers:
                try:
                    writer.close_section(name)
                except Exception:
                    pass

    def _close(self) -> None:
        for writer in self.writers:
            writer.close()