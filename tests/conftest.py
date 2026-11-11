"""Shared test fixtures."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_workdir():
    """Create a temporary working directory."""
    with tempfile.TemporaryDirectory(prefix="arguscanner_test_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_settings():
    """Sample settings dictionary."""
    return {
        "defaults": {
            "concurrency": 10,
            "timeout": 30,
        },
        "rate_limiter": {"rps_limit": 10, "burst_limit": 5},
        "retry": {"max_attempts": 3, "backoff_seconds": 5},
        "waf_aware": {
            "enabled": True,
            "trigger_status_codes": [403, 429, 503],
            "trigger_response_keywords": ["blocked", "captcha"],
        },
        "output": {
            "excel": {
                "enabled": True,
                "file_name": "report_{task_id}.xlsx",
                "sheets": ["Summary", "Subdomains", "Live URLs", "Open Ports"],
            }
        },
    }


@pytest.fixture
def sample_target():
    return "example.com"
