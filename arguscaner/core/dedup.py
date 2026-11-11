"""DeduplicationEngine - Three-tier dedup for scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class DeduplicationEngine:
    """Three-tier deduplication engine.

    L1: Intra-phase dedup (within a single plugin's output)
    L2: Global merge dedup (across all stage outputs)
    L3: Output normalization (standardize formats before writing)
    """

    def __init__(self, workdir: Path):
        self.workdir = workdir

    # --- Unique key definitions per record type ---

    UNIQUE_KEYS: dict[str, list[str]] = {
        "subdomains": ["domain"],
        "live_urls": ["url"],
        "open_ports": ["ip", "port"],
        "fingerprints": ["ip", "port", "service"],
        "vulnerabilities": ["ip", "port", "cve_id"],
        "js_data": ["type", "data"],
        "js_urls": ["data"],
        "js_subdomains": ["data"],
        "ip_map": ["host", "ip"],
        "api_endpoints": ["url"],
    }

    #: Stage name -> record type. Matching is on the exact file stem so raw
    #: plugin files (``*_output.jsonl`` / ``*_raw.jsonl``) are never treated as
    #: stage output.
    RECORD_TYPE_BY_STAGE: dict[str, str] = {
        "subdomain_enum": "subdomains",
        "http_probe": "live_urls",
        "port_scan": "open_ports",
        "js_url_extract": "js_data",
        "urlfinder_extract": "js_data",
        "ip_discovery": "ip_map",
        "api_probe": "api_endpoints",
    }

    #: Non-stage JSONL files that must never be aggregated.
    IGNORED_STEMS = frozenset({"run", "round_targets"})

    def get_record_type(self, filename: str) -> str:
        """Determine record type from a JSONL filename."""
        stem = Path(filename).stem
        if stem in self.IGNORED_STEMS:
            return "unknown"
        if stem.endswith("_output") or stem.endswith("_raw"):
            return "unknown"
        return self.RECORD_TYPE_BY_STAGE.get(stem, "unknown")

    def get_unique_key(self, record: dict[str, Any], record_type: str) -> str:
        """Generate a unique key for a record based on its type."""
        key_fields = self.UNIQUE_KEYS.get(record_type, [])
        if not key_fields:
            return json.dumps(record, sort_keys=True, ensure_ascii=False)
        parts = [str(record.get(f, "")) for f in key_fields]
        return "|".join(parts)

    # --- L1: Intra-phase dedup ---

    def l1_intra_phase(self, records: list[dict[str, Any]], record_type: str) -> list[dict[str, Any]]:
        """L1 - Deduplicate within a single plugin's output.

        Removes duplicate records based on unique key within the same phase.
        """
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []

        for record in records:
            key = self.get_unique_key(record, record_type)
            if key not in seen:
                seen.add(key)
                deduped.append(record)

        return deduped

    # --- L2: Global merge dedup ---

    def l2_global_merge(self, all_records: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
        """L2 - Merge and deduplicate across all stage outputs.

        Args:
            all_records: Mapping of record_type -> list of records.

        Returns:
            Deduplicated mapping of record_type -> list of records.
        """
        merged: dict[str, dict[str, dict[str, Any]]] = {}

        for record_type, records in all_records.items():
            if record_type not in merged:
                merged[record_type] = {}

            for record in records:
                key = self.get_unique_key(record, record_type)
                if key not in merged[record_type]:
                    merged[record_type][key] = record

        return {rtype: list(recs.values()) for rtype, recs in merged.items()}

    # --- L3: Output normalization ---

    def l3_normalize(self, records: list[dict[str, Any]], record_type: str) -> list[dict[str, Any]]:
        """L3 - Normalize record formats before final output.

        - Domains: lowercase
        - URLs: standardized
        - IP:Port: combined format
        """
        normalized: list[dict[str, Any]] = []

        for record in records:
            rec = dict(record)

            if record_type == "subdomains" and "domain" in rec:
                rec["domain"] = rec["domain"].strip().lower().strip(".")

            elif record_type == "live_urls" and "url" in rec:
                rec["url"] = self._normalize_url(rec["url"])

            elif record_type == "open_ports":
                if "ip" in rec:
                    rec["ip"] = rec["ip"].strip()

            elif record_type == "fingerprints":
                if "ip" in rec:
                    rec["ip"] = rec["ip"].strip()

            elif record_type == "ip_map":
                if "host" in rec:
                    rec["host"] = str(rec["host"]).strip().lower().rstrip(".")
                if "ip" in rec:
                    rec["ip"] = str(rec["ip"]).strip()

            elif record_type == "api_endpoints":
                if "url" in rec:
                    rec["url"] = self._normalize_url(rec["url"])

            normalized.append(rec)

        return normalized

    def _normalize_url(self, url: str) -> str:
        """Standardize URL format."""
        url = url.strip()
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "http://" + url
        return url.rstrip("/")

    # --- Full pipeline ---

    def deduplicate_all(self, workdir: Path) -> dict[str, list[dict[str, Any]]]:
        """Run full deduplication pipeline on all plugin outputs.

        1. Read all JSONL files
        2. L1: Dedup within each file
        3. L2: Merge across files
        4. L3: Normalize output

        Returns:
            Mapping of record_type -> deduplicated records.
        """
        all_records: dict[str, list[dict[str, Any]]] = {}

        # Recursive rounds live under <task>/rounds/rNNN; include them so the
        # report contains assets discovered in every round.
        for jsonl_file in workdir.rglob("*.jsonl"):
            if jsonl_file.name.startswith("run."):
                continue
            record_type = self.get_record_type(jsonl_file.name)
            if record_type == "unknown":
                continue

            records = self._read_jsonl(jsonl_file)
            records = self.l1_intra_phase(records, record_type)

            if record_type not in all_records:
                all_records[record_type] = []
            all_records[record_type].extend(records)

        all_records = self.l2_global_merge(all_records)

        # Split js_data into js_urls and js_subdomains by type field
        if "js_data" in all_records:
            js_records = all_records.pop("js_data")
            urls = [r for r in js_records if r.get("type") == "url"]
            subs = [r for r in js_records if r.get("type") == "subdomain"]
            all_records["js_urls"] = urls
            all_records["js_subdomains"] = subs

        for rtype in all_records:
            all_records[rtype] = self.l3_normalize(all_records[rtype], rtype)

        return all_records

    def _read_jsonl(self, filepath: Path) -> list[dict[str, Any]]:
        """Read a JSONL file."""
        records = []
        if not filepath.exists():
            return records
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records
