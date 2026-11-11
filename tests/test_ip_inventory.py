"""Tests for the persistent IP scan inventory."""

from __future__ import annotations

import json

from arguscaner.core.ip_inventory import (
    IpInventory,
    find_task_root,
    normalize_ip,
)


class TestNormalizeIp:

    def test_plain_ipv4(self):
        assert normalize_ip("1.2.3.4") == "1.2.3.4"

    def test_ipv4_with_port(self):
        assert normalize_ip("1.2.3.4:443") == "1.2.3.4"

    def test_ipv6_with_brackets_and_port(self):
        assert normalize_ip("[2001:db8::1]:443") == "2001:db8::1"

    def test_ipv6_zone_stripped(self):
        assert normalize_ip("fe80::1%eth0") == "fe80::1"

    def test_hostname_is_not_an_ip(self):
        assert normalize_ip("example.com") is None

    def test_empty(self):
        assert normalize_ip("") is None
        assert normalize_ip(None) is None


class TestFindTaskRoot:

    def test_finds_nearest_task_json(self, tmp_workdir):
        (tmp_workdir / "task.json").write_text("{}", encoding="utf-8")
        round_dir = tmp_workdir / "rounds" / "r001"
        round_dir.mkdir(parents=True)
        assert find_task_root(round_dir) == tmp_workdir.resolve()

    def test_falls_back_to_workdir(self, tmp_workdir):
        nested = tmp_workdir / "no-meta" / "r001"
        nested.mkdir(parents=True)
        assert find_task_root(nested) == nested.resolve()


class TestIpInventory:

    def test_task_scope_path(self, tmp_workdir):
        (tmp_workdir / "task.json").write_text("{}", encoding="utf-8")
        round_dir = tmp_workdir / "rounds" / "r001"
        round_dir.mkdir(parents=True)
        inv = IpInventory.for_workdir(round_dir, {"recursive": {"ip_cache_scope": "task"}})
        assert inv.path == tmp_workdir.resolve() / ".state" / "scanned_ips.json"

    def test_workspace_scope_path(self, tmp_workdir, sample_settings):
        workspace = tmp_workdir / "workspace"
        task = workspace / "task-1"
        (task / "rounds" / "r001").mkdir(parents=True)
        (task / "task.json").write_text("{}", encoding="utf-8")
        inv = IpInventory.for_workdir(
            task / "rounds" / "r001",
            {"recursive": {"ip_cache_scope": "workspace"}},
        )
        assert inv.path == workspace / ".state" / "scanned_ips.json"

    def test_mark_and_filter(self, tmp_workdir):
        inv = IpInventory(tmp_workdir / ".state" / "scanned_ips.json")
        assert inv.filter_unscanned(["1.1.1.1", "2.2.2.2"]) == (
            ["1.1.1.1", "2.2.2.2"], []
        )
        inv.mark_scanned("1.1.1.1", ports=[80, 443], task_id="t1")
        unscanned, skipped = inv.filter_unscanned(
            ["1.1.1.1", "1.1.1.1:22", "2.2.2.2"]
        )
        assert unscanned == ["2.2.2.2"]
        assert skipped == ["1.1.1.1"]

    def test_mark_many_merges_ports(self, tmp_workdir):
        inv = IpInventory(tmp_workdir / ".state" / "scanned_ips.json")
        assert inv.mark_many(["1.1.1.1"], ports_by_ip={"1.1.1.1": [80]}) == 1
        inv.mark_many(["1.1.1.1"], ports_by_ip={"1.1.1.1": [443]})
        data = json.loads(
            (tmp_workdir / ".state" / "scanned_ips.json").read_text(encoding="utf-8")
        )
        assert data["ips"]["1.1.1.1"]["ports"] == [80, 443]

    def test_corrupt_file_is_treated_as_empty(self, tmp_workdir):
        path = tmp_workdir / ".state" / "scanned_ips.json"
        path.parent.mkdir(parents=True)
        path.write_text("not json", encoding="utf-8")
        inv = IpInventory(path)
        assert inv.is_scanned("1.1.1.1") is False
