"""ReportGenerator - Excel report generation with all pipeline sheets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from arguscaner.core.dedup import DeduplicationEngine


# --- Sheet column definitions (per README spec) ---

SHEET_COLUMNS: dict[str, list[str]] = {
    "概览": [
        "任务ID", "目标", "目标类型", "开始时间", "结束时间",
        "总耗时(秒)", "资产总数", "子域名数",
        "存活URL数", "开放端口数", "指纹数",
        "漏洞数", "中断数", "WAF触发数",
        "失败阶段", "IP数", "API端点数", "递归轮数",
    ],
    "子域名": ["域名", "IP", "来源", "时间戳"],
    "存活URL": ["URL", "状态", "状态分类", "标题", "长度", "IP", "来源"],
    "开放端口": ["IP", "端口", "协议", "服务", "Banner", "状态"],
    "指纹": ["IP", "端口", "服务", "产品", "版本", "CPE"],
    "漏洞": [
        "IP", "端口", "CVE编号", "严重程度",
        "模板ID", "匹配器", "提取结果", "复现命令", "描述",
    ],
    "中断": [
        "阶段", "目标", "错误原因", "被阻代理",
        "重试次数", "状态", "重试时间",
    ],
    "JS URLs": ["URL", "来源", "时间戳"],
    "JS Subdomains": ["子域名", "来源", "时间戳"],
    "IP映射": ["主机", "IP", "来源", "时间戳"],
    "API端点": [
        "URL", "状态", "API类型", "内容类型", "标题",
        "证据", "来源", "时间戳",
    ],
}

# Chinese column name -> English record key
SHEET_COLUMN_KEYS: dict[str, dict[str, str]] = {
    "子域名": {"域名": "domain", "IP": "ip", "来源": "source", "时间戳": "timestamp"},
    "存活URL": {"URL": "url", "状态": "status", "标题": "title", "长度": "length", "IP": "ip", "来源": "source"},
    "开放端口": {"IP": "ip", "端口": "port", "协议": "protocol", "服务": "service", "Banner": "banner", "状态": "state"},
    "指纹": {"IP": "ip", "端口": "port", "服务": "service", "产品": "product", "版本": "version", "CPE": "cpe"},
    "漏洞": {
        "IP": "ip", "端口": "port", "CVE编号": "cve_id",
        "严重程度": "severity", "模板ID": "template_id",
        "匹配器": "matcher", "提取结果": "extracted_results",
        "复现命令": "curl_command", "描述": "description",
    },
    "JS URLs": {"URL": "data", "来源": "source", "时间戳": "timestamp"},
    "JS Subdomains": {"子域名": "data", "来源": "source", "时间戳": "timestamp"},
    "IP映射": {"主机": "host", "IP": "ip", "来源": "source", "时间戳": "timestamp"},
    "API端点": {
        "URL": "url", "状态": "status", "API类型": "api_type",
        "内容类型": "content_type", "标题": "title", "证据": "evidence",
        "来源": "source", "时间戳": "timestamp",
    },
}

HEADER_FONT = Font(bold=True, color="FFFFFF", size=11)
HEADER_FILL = PatternFill(start_color="2F5496", end_color="2F5496", fill_type="solid")
HEADER_ALIGN = Alignment(horizontal="center", vertical="center")
THIN_BORDER = Border(
    left=Side(style="thin"),
    right=Side(style="thin"),
    top=Side(style="thin"),
    bottom=Side(style="thin"),
)


class ReportGenerator:
    """Generate Excel reports with every sheet defined in SHEET_COLUMNS."""

    def __init__(self, workdir: Path, task_id: str, settings: dict[str, Any]):
        self.workdir = workdir
        self.task_id = task_id
        self.settings = settings
        self.output_config = settings.get("output", {}).get("excel", {})

    def generate(
        self,
        scan_result: Any,
        all_records: dict[str, list[dict[str, Any]]] | None = None,
    ) -> Path:
        """Generate the full Excel report.

        Args:
            scan_result: ScanResult object from scheduler.
            all_records: Pre-deduped records by type. If None, runs dedup.

        Returns:
            Path to generated .xlsx file.
        """
        if all_records is None:
            dedup = DeduplicationEngine(self.workdir)
            all_records = dedup.deduplicate_all(self.workdir)

        filename = self.output_config.get(
            "file_name", "report_{task_id}.xlsx"
        ).format(task_id=self.task_id)
        output_path = self.workdir / filename

        wb = Workbook()

        self._create_summary_sheet(wb, scan_result, all_records)
        self._create_data_sheet(wb, "子域名", all_records.get("subdomains", []))
        self._create_data_sheet(wb, "存活URL", all_records.get("live_urls", []))
        self._create_data_sheet(wb, "开放端口", all_records.get("open_ports", []))
        self._create_data_sheet(wb, "指纹", all_records.get("fingerprints", []))
        self._create_data_sheet(wb, "漏洞", all_records.get("vulnerabilities", []))
        self._create_data_sheet(wb, "JS URLs", all_records.get("js_urls", []))
        self._create_data_sheet(wb, "JS Subdomains", all_records.get("js_subdomains", []))
        self._create_data_sheet(wb, "IP映射", all_records.get("ip_map", []))
        self._create_data_sheet(wb, "API端点", all_records.get("api_endpoints", []))
        self._create_interrupted_sheet(wb, scan_result)

        wb.save(output_path)
        return output_path

    def _create_summary_sheet(
        self,
        wb: Workbook,
        scan_result: Any,
        all_records: dict[str, list[dict[str, Any]]],
    ) -> None:
        """Create the Summary sheet."""
        ws = wb.active
        ws.title = "概览"

        columns = SHEET_COLUMNS["概览"]
        self._write_headers(ws, columns)

        import datetime
        started = getattr(scan_result, "started_at", 0)
        finished = getattr(scan_result, "finished_at", 0)
        started_str = datetime.datetime.fromtimestamp(started).isoformat() if started else ""
        finished_str = datetime.datetime.fromtimestamp(finished).isoformat() if finished else ""

        failed_stages = getattr(scan_result, "failed_stages", [])
        waf_count = sum(
            1 for s in getattr(scan_result, "stages", {}).values()
            if hasattr(s, "error") and s.error and "waf" in str(s.error).lower()
        )

        values = [
            getattr(scan_result, "task_id", self.task_id),
            getattr(scan_result, "target", ""),
            getattr(scan_result, "target_type", ""),
            started_str,
            finished_str,
            round(getattr(scan_result, "total_duration", 0), 2),
            sum(len(v) for v in all_records.values()),
            len(all_records.get("subdomains", [])),
            len(all_records.get("live_urls", [])),
            len(all_records.get("open_ports", [])),
            len(all_records.get("fingerprints", [])),
            len(all_records.get("vulnerabilities", [])),
            getattr(scan_result, "interrupted_count", 0),
            waf_count,
            ", ".join(failed_stages) if failed_stages else "",
            len(all_records.get("ip_map", [])),
            len(all_records.get("api_endpoints", [])),
            len(getattr(scan_result, "recursive_rounds", []) or []),
        ]

        for col_idx, value in enumerate(values, 1):
            ws.cell(row=2, column=col_idx, value=value)

        self._set_column_widths(ws, columns)

    def _create_data_sheet(
        self,
        wb: Workbook,
        sheet_name: str,
        records: list[dict[str, Any]],
    ) -> None:
        """Create a data sheet with headers and records."""
        ws = wb.create_sheet(sheet_name)
        columns = SHEET_COLUMNS.get(sheet_name, [])
        if not columns:
            return

        self._write_headers(ws, columns)

        for row_idx, record in enumerate(records, 2):
            for col_idx, col_name in enumerate(columns, 1):
                if col_name == "状态分类" and "status" in record:
                    status = record.get("status", 0)
                    try:
                        status_int = int(status)
                        value = "存活" if 200 <= status_int < 400 else "非存活"
                    except (ValueError, TypeError):
                        value = "未知"
                else:
                    key_map = SHEET_COLUMN_KEYS.get(sheet_name, {})
                    record_key = key_map.get(col_name, col_name.lower().replace(" ", "_"))
                    value = record.get(record_key, "")
                    if isinstance(value, (list, dict, tuple)):
                        value = json.dumps(value, ensure_ascii=False)
                ws.cell(row=row_idx, column=col_idx, value=value)

        self._set_column_widths(ws, columns)
        if records:
            ws.freeze_panes = "A2"

    def _create_interrupted_sheet(self, wb: Workbook, scan_result: Any) -> None:
        """Create the Interrupted sheet from failed stages."""
        ws = wb.create_sheet("中断")
        columns = SHEET_COLUMNS["中断"]
        self._write_headers(ws, columns)

        failed_stages = getattr(scan_result, "failed_stages", [])
        target = getattr(scan_result, "target", "")
        stages = getattr(scan_result, "stages", {})

        row_idx = 2
        for stage_name in failed_stages:
            sr = stages.get(stage_name)
            error = getattr(sr, "error", "") if sr else ""
            ws.cell(row=row_idx, column=1, value=stage_name)
            ws.cell(row=row_idx, column=2, value=target)
            ws.cell(row=row_idx, column=3, value=str(error))
            ws.cell(row=row_idx, column=4, value="")
            ws.cell(row=row_idx, column=5, value=0)
            ws.cell(row=row_idx, column=6, value="failed")
            ws.cell(row=row_idx, column=7, value="")
            row_idx += 1

        self._set_column_widths(ws, columns)

    def _write_headers(self, ws: Any, columns: list[str]) -> None:
        """Write styled header row."""
        for col_idx, header in enumerate(columns, 1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = HEADER_FONT
            cell.fill = HEADER_FILL
            cell.alignment = HEADER_ALIGN
            cell.border = THIN_BORDER

    def _set_column_widths(self, ws: Any, columns: list[str]) -> None:
        """Auto-size column widths based on header length."""
        for col_idx, header in enumerate(columns, 1):
            width = max(len(header) + 4, 12)
            ws.column_dimensions[get_column_letter(col_idx)].width = width
