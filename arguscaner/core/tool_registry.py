"""Registry metadata for external tools used by built-in plugins.

The registry describes *where* a tool may live and which settings keys can
override it.  Actual path resolution lives in
:mod:`arguscaner.utils.tool_paths`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

#: ``arguscaner/`` package directory.
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
#: Repository / project root (directory containing ``arguscaner/``).
PROJECT_ROOT = PACKAGE_ROOT.parent
#: Directory containing tools bundled with the application.
TOOLS_DIR = PACKAGE_ROOT / "tools"

#: Definition for every external tool.
#:
#: ``setting_keys`` is ordered by priority: the first non-empty value wins and
#: later keys act as shared fallbacks (``api_probe`` reuses the httpx path from
#: ``httpx_probe`` when it has no override).
TOOL_SPECS: dict[str, dict[str, Any]] = {
    "httpx": {
        "label": "httpx",
        "description": "HTTP 存活探测与 API 路径探测",
        "executables": ["httpx.exe", "httpx"],
        "bundled": ["httpx/httpx.exe", "httpx/httpx"],
        "setting_keys": [
            "plugins.httpx_probe.httpx_path",
            "plugins.api_probe.httpx_path",
        ],
        "env": ["HTTPX_PATH"],
        "version_args": ["-version"],
        "plugins": ["httpx_probe", "api_probe"],
        "python": False,
    },
    "nmap": {
        "label": "Nmap",
        "description": "端口与服务扫描",
        "executables": ["nmap.exe", "nmap"],
        "bundled": ["nmap/nmap.exe", "nmap/nmap"],
        "setting_keys": ["plugins.nmap_scan.nmap_path"],
        "env": ["NMAP_PATH"],
        "version_args": ["--version"],
        "plugins": ["nmap_scan"],
        "python": False,
    },
    "urlfinder": {
        "label": "URLFinder",
        "description": "页面 URL / JS 深度提取",
        "executables": ["URLFinder.exe", "URLFinder"],
        "bundled": ["urlfinder/URLFinder.exe", "urlfinder/URLFinder"],
        "setting_keys": ["plugins.urlfinder.urlfinder_path"],
        "env": ["URLFINDER_PATH"],
        "version_args": ["-h"],
        "plugins": ["urlfinder"],
        "python": False,
    },
    "oneforall": {
        "label": "OneForAll",
        "description": "子域名枚举（Python 脚本）",
        "executables": ["oneforall.py"],
        "bundled": ["oneforall/oneforall.py"],
        "setting_keys": ["plugins.oneforall.oneforall_path"],
        "env": ["ONEFORALL_PATH"],
        "version_args": [],
        "plugins": ["oneforall"],
        "python": True,
    },
    "jsfinder": {
        "label": "JSFinder",
        "description": "JavaScript URL / 子域名提取（Python 脚本）",
        "executables": ["JSFinder.py", "jsfinder.py"],
        "bundled": ["jsfinder/JSFinder.py"],
        "setting_keys": ["plugins.jsfinder.jsfinder_path"],
        "env": ["JSFINDER_PATH"],
        "version_args": [],
        "plugins": ["jsfinder"],
        "python": True,
    },
}


def get_spec(key: str) -> dict[str, Any]:
    """Return the spec for ``key`` or raise ``KeyError``."""
    return TOOL_SPECS[key]


def tools_for_plugin(plugin_name: str) -> list[str]:
    """Return the tool keys used by a plugin."""
    return [
        key for key, spec in TOOL_SPECS.items() if plugin_name in spec["plugins"]
    ]