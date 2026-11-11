"""Tests for the report generator."""

from __future__ import annotations

from pathlib import Path

import pytest
from openpyxl import load_workbook

from arguscaner.core.report_generator import ReportGenerator


class MockScanResult:
    def __init__(self):
        self.task_id = "hv-test-001"
        self.target = "example.com"
        self.started_at = 1693000000.0
        self.finished_at = 1693000010.0
        self.total_duration = 10.0
        self.interrupted_count = 0
        self.failed_stages = []
        self.stages = {}


class TestReportGenerator:

    def test_generates_xlsx(self, tmp_workdir, sample_settings):
        result = MockScanResult()
        gen = ReportGenerator(tmp_workdir, "hv-test-001", sample_settings)
        path = gen.generate(result)
        assert path.exists()
        assert path.suffix == ".xlsx"

    def test_workbook_has_all_sheets(self, tmp_workdir, sample_settings):
        result = MockScanResult()
        gen = ReportGenerator(tmp_workdir, "hv-test-001", sample_settings)
        path = gen.generate(result)
        wb = load_workbook(path)
        expected = ["概览", "子域名", "存活URL", "开放端口",
                     "指纹", "漏洞", "中断"]
        for sheet in expected:
            assert sheet in wb.sheetnames
        wb.close()

    def test_summary_has_data(self, tmp_workdir, sample_settings):
        result = MockScanResult()
        gen = ReportGenerator(tmp_workdir, "hv-test-001", sample_settings)
        path = gen.generate(result)
        wb = load_workbook(path)
        ws = wb["概览"]
        assert ws.cell(row=1, column=1).value == "任务ID"
        assert ws.cell(row=2, column=1).value == "hv-test-001"
        wb.close()

    def test_live_urls_has_status_category_column(self, tmp_workdir, sample_settings):
        result = MockScanResult()
        gen = ReportGenerator(tmp_workdir, "hv-test-001", sample_settings)
        path = gen.generate(result)
        wb = load_workbook(path)
        ws = wb["存活URL"]
        headers = [ws.cell(row=1, column=c).value for c in range(1, ws.max_column + 1)]
        assert "状态分类" in headers
        wb.close()

    def test_status_category_values(self, tmp_workdir, sample_settings):
        from arguscaner.core.report_generator import SHEET_COLUMNS
        gen = ReportGenerator(tmp_workdir, "hv-test-001", sample_settings)
        columns = SHEET_COLUMNS["存活URL"]
        assert columns == ["URL", "状态", "状态分类", "标题", "长度", "IP", "来源"]

    def test_ip_and_api_sheets_present_even_when_empty(
        self, tmp_workdir, sample_settings
    ):
        result = MockScanResult()
        gen = ReportGenerator(tmp_workdir, "hv-test-001", sample_settings)
        path = gen.generate(result)
        wb = load_workbook(path)
        assert "IP映射" in wb.sheetnames
        assert "API端点" in wb.sheetnames
        assert wb["IP映射"].cell(row=1, column=1).value == "主机"
        assert wb["API端点"].cell(row=1, column=1).value == "URL"
        wb.close()

    def test_ip_and_api_records_rendered(self, tmp_workdir, sample_settings):
        result = MockScanResult()
        result.recursive_rounds = [{"round": 1}]
        records = {
            "ip_map": [{"host": "a.example.com", "ip": "1.1.1.1", "source": "dns"}],
            "api_endpoints": [{
                "url": "https://a.example.com/swagger.json",
                "status": 200,
                "api_type": "swagger/openapi",
                "content_type": "application/json",
                "title": "Swagger",
                "evidence": "status=200",
                "source": "api_probe",
            }],
        }
        gen = ReportGenerator(tmp_workdir, "hv-test-001", sample_settings)
        path = gen.generate(result, records)
        wb = load_workbook(path)
        assert wb["IP映射"].cell(row=2, column=1).value == "a.example.com"
        assert wb["IP映射"].cell(row=2, column=2).value == "1.1.1.1"
        assert wb["API端点"].cell(row=2, column=1).value.endswith("/swagger.json")
        assert wb["API端点"].cell(row=2, column=3).value == "swagger/openapi"
        wb.close()
