"""HTMLGenerator - Generate standalone HTML reports from scan results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from openpyxl import load_workbook


class HTMLGenerator:
    """Generate self-contained HTML reports with inline CSS/JS."""

    def __init__(self, workdir: Path, task_id: str):
        self.workdir = workdir
        self.task_id = task_id

    def generate_from_excel(self, xlsx_path: Path) -> Path:
        """Generate HTML report from an Excel file.

        Args:
            xlsx_path: Path to the Excel report.

        Returns:
            Path to generated HTML file.
        """
        wb = load_workbook(xlsx_path, read_only=True, data_only=True)
        sheets_data: dict[str, list[list[Any]]] = {}

        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            rows: list[list[Any]] = []
            for row in ws.iter_rows(values_only=True):
                rows.append(list(row))
            sheets_data[sheet_name] = rows

        wb.close()
        return self._write_html(sheets_data)

    def generate_from_records(
        self, all_records: dict[str, list[dict[str, Any]]]
    ) -> Path:
        """Generate HTML report from deduped records.

        Args:
            all_records: Mapping of record_type -> records.

        Returns:
            Path to generated HTML file.
        """
        sheets_data: dict[str, list[list[Any]]] = {}
        for rtype, records in all_records.items():
            if not records:
                sheets_data[rtype] = []
                continue
            headers = list(records[0].keys())
            rows = [headers]
            for rec in records:
                rows.append([rec.get(h, "") for h in headers])
            sheets_data[rtype] = rows

        return self._write_html(sheets_data)

    def _write_html(self, sheets_data: dict[str, list[list[Any]]]) -> Path:
        """Write the HTML report file."""
        output_path = self.workdir / f"report_{self.task_id}.html"

        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='zh-CN'>",
            "<head>",
            "<meta charset='UTF-8'>",
            f"<title>ArguScanner 报告 - {self.task_id}</title>",
            "<style>",
            _CSS,
            "</style>",
            "</head>",
            "<body>",
            f"<h1>ArguScanner 报告：{self.task_id}</h1>",
        ]

        for sheet_name, rows in sheets_data.items():
            if not rows:
                continue
            html_parts.append(f"<h2>{sheet_name} ({len(rows) - 1} 条记录)</h2>")
            html_parts.append("<table>")
            headers = rows[0]
            status_col = None
            for idx, h in enumerate(headers):
                if str(h).lower() == "status":
                    status_col = idx
                    break
            for i, row in enumerate(rows):
                tag = "th" if i == 0 else "td"
                html_parts.append("<tr>")
                for c_idx, cell in enumerate(row):
                    attrs = ""
                    if status_col is not None and i > 0:
                        try:
                            status_val = int(row[status_col])
                            if status_val >= 400:
                                attrs = " class='dead'"
                            elif status_val >= 200:
                                attrs = " class='alive'"
                        except (ValueError, TypeError):
                            pass
                    html_parts.append(f"<{tag}{attrs}>{cell}</{tag}>")
                html_parts.append("</tr>")
            html_parts.append("</table>")

        html_parts.extend([
            "</body>",
            "</html>",
        ])

        output_path.write_text("\n".join(html_parts), encoding="utf-8")
        return output_path


_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 24px; background: #f5f5f5; }
h1 { color: #1a1a2e; }
h2 { color: #2F5496; margin-top: 24px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background: #2F5496; color: white; }
tr:nth-child(even) { background: #f9f9f9; }
.alive { color: #27ae60; font-weight: bold; }
.dead { color: #c0392b; font-weight: bold; }
"""
