"""Tests for Web UI routes and management API."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import yaml

import pytest

from arguscaner.web.app import create_app
from arguscaner.entrypoint import SETTINGS_YAML


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _load_settings() -> dict:
    with open(SETTINGS_YAML, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _save_settings(settings: dict) -> None:
    with open(SETTINGS_YAML, "w", encoding="utf-8") as f:
        yaml.safe_dump(settings, f, allow_unicode=True, sort_keys=False)


class TestApiAuth:

    def test_mutation_requires_token_when_set(self, client, monkeypatch):
        monkeypatch.setenv("ARGUS_API_TOKEN", "secret-token")
        r = client.post("/api/scan", json={})
        assert r.status_code == 401

    def test_mutation_allowed_with_token(self, client, monkeypatch):
        monkeypatch.setenv("ARGUS_API_TOKEN", "secret-token")
        r = client.post(
            "/api/scan",
            json={},
            headers={"X-API-Token": "secret-token"},
        )
        # Auth passed; empty target is rejected by the handler.
        assert r.status_code == 400

    def test_get_not_blocked_by_token(self, client, monkeypatch):
        monkeypatch.setenv("ARGUS_API_TOKEN", "secret-token")
        r = client.get("/api/plugins")
        assert r.status_code == 200


class TestPages:
    def test_index(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"\xe6\x96\xb0\xe5\xbb\xba\xe6\x89\xab\xe6\x8f\x8f" in r.data
        assert b"target-file" in r.data
        assert b"\xe5\xaf\xbc\xe5\x85\xa5\xe6\x96\x87\xe4\xbb\xb6" in r.data

    def test_plugins_page(self, client):
        r = client.get("/plugins")
        assert r.status_code == 200
        assert b"\xe6\x8f\x92\xe4\xbb\xb6" in r.data
        assert b"oneforall" in r.data
        assert b"\xe6\xb7\xbb\xe5\x8a\xa0\xe8\x87\xaa\xe5\xae\x9a\xe4\xb9\x89\xe6\x8f\x92\xe4\xbb\xb6" in r.data
        assert "工具".encode() in r.data
        assert "配置路径".encode() in r.data

    def test_pipeline_page(self, client):
        r = client.get("/pipeline")
        assert r.status_code == 200
        assert b"\xe6\xb5\x81\xe7\xa8\x8b\xe5\xae\x9a\xe4\xb9\x89" in r.data
        assert b"oneforall" in r.data

    def test_settings_page(self, client):
        r = client.get("/settings")
        assert r.status_code == 200
        assert b"\xe8\xae\xbe\xe7\xbd\xae" in r.data
        # Translated field labels and grouped plugin section are embedded.
        assert "全局并发数".encode() in r.data
        assert "插件配置".encode() in r.data
        assert "OneForAll 子域名枚举".encode() in r.data

    def test_proxy_page(self, client):
        r = client.get("/proxy")
        assert r.status_code == 200
        assert b"\xe4\xbb\xa3\xe7\x90\x86\xe6\xb1\xa0" in r.data

    def test_nav_links(self, client):
        r = client.get("/")
        assert "插件".encode() in r.data
        assert "流程".encode() in r.data
        assert "设置".encode() in r.data
        assert "代理".encode() in r.data


class TestPluginAPI:

    def test_list(self, client):
        r = client.get("/api/plugins")
        assert r.status_code == 200
        data = r.get_json()
        names = [p["name"] for p in data["plugins"]]
        assert "oneforall" in names

    def test_add_and_remove(self, client):
        payload = {
            "name": "web_test_plugin",
            "description": "Test plugin for web API",
            "command_template": "echo {{target}} > {{output}}",
            "supported_target_types": ["domain"],
            "output_schema": {"result": "str"},
        }
        r = client.post(
            "/api/plugins",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["plugin"]["name"] == "web_test_plugin"

        # Remove
        r = client.delete("/api/plugins/web_test_plugin")
        assert r.status_code == 200

        # Verify removed
        r = client.get("/api/plugins")
        names = [p["name"] for p in r.get_json()["plugins"]]
        assert "web_test_plugin" not in names

    def test_add_missing_name(self, client):
        r = client.post(
            "/api/plugins",
            data=json.dumps({"command_template": "echo {{target}}"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_add_missing_command(self, client):
        r = client.post(
            "/api/plugins",
            data=json.dumps({"name": "no_cmd"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_remove_builtin_fails(self, client):
        r = client.delete("/api/plugins/oneforall")
        assert r.status_code == 400
        assert "不是自定义插件" in r.get_json()["error"]

    def test_enable_disable(self, client):
        r = client.put(
            "/api/plugins/nmap_scan/status",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        assert r.status_code == 200
        assert r.get_json()["enabled"] is False
        settings = _load_settings()
        assert settings["plugins"]["nmap_scan"]["enabled"] is False
        # Restore
        client.put(
            "/api/plugins/nmap_scan/status",
            data=json.dumps({"enabled": True}),
            content_type="application/json",
        )


class TestSettingsAPI:

    def test_get(self, client):
        r = client.get("/api/settings")
        assert r.status_code == 200
        data = r.get_json()
        assert "defaults" in data

    def test_put(self, client):
        r = client.put(
            "/api/settings",
            data=json.dumps({"defaults.timeout": 999}),
            content_type="application/json",
        )
        assert r.status_code == 200
        settings = _load_settings()
        assert settings["defaults"]["timeout"] == 999
        # Restore
        _save_settings(settings)


class TestProxyAPI:

    def test_get(self, client):
        r = client.get("/api/proxy")
        assert r.status_code == 200
        assert "sources" in r.get_json()

    def test_add_remove(self, client):
        r = client.post(
            "/api/proxy",
            data=json.dumps({"url": "http://test-web:9999"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert "http://test-web:9999" in data["sources"]

        r = client.delete(
            "/api/proxy",
            data=json.dumps({"url": "http://test-web:9999"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        assert "http://test-web:9999" not in r.get_json()["sources"]


class TestPipelineAPI:

    def test_get(self, client):
        r = client.get("/api/pipeline")
        assert r.status_code == 200
        data = r.get_json()
        assert "stages" in data
        names = [s["name"] for s in data["stages"]]
        assert "subdomain_enum" in names
        assert "port_scan" in names

    def test_get_includes_definition_graph_and_levels(self, client):
        data = client.get("/api/pipeline").get_json()
        assert data["name"] == "default"
        assert data["definition"]["stages"]
        assert data["levels"]
        assert data["graph"]["nodes"]
        assert data["pipelines"]

    def test_graph_endpoint(self, client):
        r = client.get("/api/pipeline/graph")
        assert r.status_code == 200
        graph = r.get_json()
        assert graph["nodes"]
        data_edges = [edge for edge in graph["edges"] if edge["kind"] == "data"]
        assert data_edges
        assert all(edge["label"] for edge in data_edges)
        assert any(edge["kind"] == "order" for edge in graph["edges"])

    def test_validate_ok(self, client):
        definition = client.get("/api/pipeline").get_json()["definition"]
        r = client.post("/api/pipeline/validate", json={"definition": definition})
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

    def test_validate_reports_errors(self, client):
        definition = {
            "pipeline": {"name": "bad"},
            "stages": [
                {"id": "dup", "plugin": "oneforall", "level": 1},
                {"id": "dup", "plugin": "oneforall", "level": 2},
            ],
        }
        r = client.post("/api/pipeline/validate", json={"definition": definition})
        assert r.status_code == 400
        payload = r.get_json()
        assert payload["ok"] is False
        assert payload["errors"]

    def test_save_and_restore_default(self, client, tmp_path, monkeypatch):
        import shutil

        from arguscaner.scheduler import pipeline_io

        target = tmp_path / "pipeline.yaml"
        shutil.copy(pipeline_io.DEFAULT_PIPELINE, target)
        monkeypatch.setattr(pipeline_io, "DEFAULT_PIPELINE", target)

        definition = client.get("/api/pipeline").get_json()["definition"]
        definition["pipeline"]["description"] = "edited by test"
        r = client.put("/api/pipelines/default", json={"definition": definition})
        assert r.status_code == 200, r.get_json()
        assert "edited by test" in target.read_text(encoding="utf-8")
        assert (tmp_path / ".history").exists()

        r = client.post("/api/pipelines/default/restore")
        assert r.status_code == 200
        assert "edited by test" not in target.read_text(encoding="utf-8")

    def test_restore_without_backup(self, client, tmp_path, monkeypatch):
        from arguscaner.scheduler import pipeline_io

        target = tmp_path / "pipeline.yaml"
        target.write_text(
            "pipeline: {name: empty}\nstages: []\n", encoding="utf-8"
        )
        monkeypatch.setattr(pipeline_io, "DEFAULT_PIPELINE", target)
        r = client.post("/api/pipelines/default/restore")
        assert r.status_code == 404

    def test_create_update_delete_custom_pipeline(self, client, tmp_path, monkeypatch):
        from arguscaner.scheduler import pipeline_io
        from arguscaner.web import routes

        custom_dir = tmp_path / "pipelines"
        monkeypatch.setattr(routes, "CUSTOM_PIPELINES_DIR", custom_dir)
        monkeypatch.setattr(pipeline_io, "CUSTOM_PIPELINES_DIR", custom_dir)

        definition = {
            "pipeline": {"name": "web_custom", "description": "测试流程", "version": 2},
            "stages": [{"id": "enum", "plugin": "oneforall", "level": 1}],
        }
        r = client.post(
            "/api/pipelines",
            json={"name": "web_custom", "definition": definition},
        )
        assert r.status_code == 201, r.get_json()
        assert (custom_dir / "web_custom.yaml").exists()

        listing = client.get("/api/pipelines").get_json()["pipelines"]
        assert "web_custom" in [item["name"] for item in listing]

        updated = {
            "pipeline": {"name": "web_custom", "version": 2},
            "stages": [
                {"id": "enum", "plugin": "oneforall", "level": 1},
                {"id": "probe", "plugin": "httpx_probe", "level": 2,
                 "inputs": [{"from": "enum", "data": "subdomain"}]},
            ],
        }
        r = client.put("/api/pipelines/web_custom", json={"definition": updated})
        assert r.status_code == 200, r.get_json()
        assert len(r.get_json()["definition"]["stages"]) == 2

        r = client.delete("/api/pipelines/web_custom")
        assert r.status_code == 200
        assert not (custom_dir / "web_custom.yaml").exists()

    def test_delete_default_rejected(self, client):
        r = client.delete("/api/pipelines/default")
        assert r.status_code == 400


class TestStatusPipelineMetadata:

    def test_history_uses_task_pipeline_stages(self, client, tmp_path, monkeypatch):
        from arguscaner.web import routes

        monkeypatch.setattr(routes, "WORKSPACE", tmp_path)
        task = tmp_path / "task-pipeline-meta"
        task.mkdir()
        meta = {
            "task_id": task.name,
            "target": "example.com",
            "target_type": "domain",
            "pipeline": "custom_flow",
            "pipeline_file": "configs/pipelines/custom_flow.yaml",
            "pipeline_stages": [
                {"id": "alpha", "label": "第一阶段", "plugin": "oneforall", "level": 1},
                {"id": "beta", "label": "第二阶段", "plugin": "httpx_probe", "level": 2},
            ],
        }
        (task / "task.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )
        (task / ".alpha.done").write_text(
            json.dumps({"state": "done"}), encoding="utf-8"
        )

        entry = client.get("/api/history").get_json()[0]
        assert entry["pipeline"] == "custom_flow"
        assert entry["status"] == "running"
        assert [s["id"] for s in entry["pipeline_stages"]] == ["alpha", "beta"]

        (task / ".beta.done").write_text(
            json.dumps({"state": "done"}), encoding="utf-8"
        )
        entry = client.get("/api/history").get_json()[0]
        assert entry["status"] == "done"

    def test_status_failed_stage_wins(self, client, tmp_path, monkeypatch):
        from arguscaner.web import routes

        monkeypatch.setattr(routes, "WORKSPACE", tmp_path)
        task = tmp_path / "task-failed"
        task.mkdir()
        meta = {
            "task_id": task.name,
            "target": "example.com",
            "pipeline_stages": [
                {"id": "alpha", "label": "A", "plugin": "oneforall", "level": 1},
            ],
        }
        (task / "task.json").write_text(json.dumps(meta), encoding="utf-8")
        (task / ".alpha.done").write_text(
            json.dumps({"state": "failed"}), encoding="utf-8"
        )
        data = client.get(f"/api/status/{task.name}").get_json()
        assert data["status"] == "failed"
        assert data["failed_stages"] == ["alpha"]
        assert data["pipeline_stages"] == meta["pipeline_stages"]


class TestToolsAPI:

    def test_list_tools(self, client):
        r = client.get("/api/tools")
        assert r.status_code == 200
        tools = r.get_json()["tools"]
        keys = {tool["key"] for tool in tools}
        assert {"httpx", "nmap", "urlfinder", "oneforall", "jsfinder"} <= keys
        for tool in tools:
            assert "path" in tool
            assert "source" in tool
            assert "exists" in tool

    def test_bundled_httpx_is_available(self, client):
        tools = {tool["key"]: tool for tool in client.get("/api/tools").get_json()["tools"]}
        # settings.yaml no longer pins the external URLFinder/httpx path.
        assert tools["httpx"]["source"] in ("bundled", "path", "env")
        assert tools["httpx"]["exists"] is True

    def test_check_existing_path(self, client, tmp_path):
        exe = tmp_path / "fake-tool.exe"
        exe.write_bytes(b"")
        r = client.post("/api/tools/check", json={"path": str(exe)})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["exists"] is True

    def test_check_missing_path(self, client, tmp_path):
        r = client.post(
            "/api/tools/check",
            json={"path": str(tmp_path / "missing.exe")},
        )
        assert r.status_code == 200
        assert r.get_json()["ok"] is False

    def test_check_requires_path(self, client):
        r = client.post("/api/tools/check", json={})
        assert r.status_code == 400


class TestBatchAPI:

    def test_batch_page(self, client):
        r = client.get("/batch")
        assert r.status_code == 200
        assert "批量扫描".encode() in r.data

    @patch("arguscaner.web.routes._redis_available", return_value=True)
    @patch("arguscaner.web.tasks.run_batch_scan")
    def test_batch_scan(self, mock_task, mock_redis, client):
        mock_result = MagicMock()
        mock_result.id = "test-batch-001"
        mock_task.delay.return_value = mock_result

        payload = {"targets": "example.com,192.168.1.1"}
        r = client.post(
            "/api/scan/batch",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert "celery_task_id" in data
        assert data["status"] == "batch_started"
        assert data["target_count"] == 2

    @patch("arguscaner.web.routes._redis_available", return_value=True)
    @patch("arguscaner.web.tasks.run_batch_scan")
    def test_batch_scan_with_url(self, mock_task, mock_redis, client):
        mock_result = MagicMock()
        mock_result.id = "test-batch-002"
        mock_task.delay.return_value = mock_result

        payload = {"targets": "http://127.0.0.1,https://example.com"}
        r = client.post(
            "/api/scan/batch",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["target_count"] == 2

    def test_batch_empty(self, client):
        r = client.post(
            "/api/scan/batch",
            data=json.dumps({"targets": ""}),
            content_type="application/json",
        )
        assert r.status_code == 400

    @patch("arguscaner.web.routes._redis_available", return_value=True)
    @patch("arguscaner.web.tasks.run_batch_scan")
    def test_batch_invalid_target(self, mock_task, mock_redis, client):
        mock_result = MagicMock()
        mock_result.id = "test-batch-003"
        mock_task.delay.return_value = mock_result

        payload = {"targets": "example.com,not_a_valid_target"}
        r = client.post(
            "/api/scan/batch",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert "celery_task_id" in data
