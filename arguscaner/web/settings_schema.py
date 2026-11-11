"""Chinese labels and editor metadata for the settings page.

The settings file is intentionally flat and English-keyed.  This module keeps
the UI translation separate from storage so existing ``settings.yaml`` files
keep working unchanged.
"""

from __future__ import annotations

from typing import Any

SECTION_META: dict[str, dict[str, str]] = {
    "defaults": {
        "label": "默认参数",
        "description": "全局并发与单阶段超时，作用于所有扫描阶段。",
        "icon": "i-gear",
    },
    "plugins": {
        "label": "插件配置",
        "description": "内置扫描器的开关、工具路径与执行参数。",
        "icon": "i-plug",
    },
    "recursive": {
        "label": "递归扫描",
        "description": "多轮资产扩展、轮次上限与 IP 去重策略。",
        "icon": "i-refresh",
    },
    "rate_limiter": {
        "label": "全局限速",
        "description": "令牌桶限速，保护目标并降低触发 WAF 的概率。",
        "icon": "i-radar",
    },
    "retry": {
        "label": "失败重试",
        "description": "阶段失败后的重试次数、退避时间与可重试退出码。",
        "icon": "i-history",
    },
    "waf_aware": {
        "label": "WAF 规避",
        "description": "WAF 触发判定、自动恢复与代理轮转。",
        "icon": "i-globe",
    },
    "test": {
        "label": "测试参数",
        "description": "CLI 自测与测试输出相关配置。",
        "icon": "i-terminal",
    },
    "output": {
        "label": "报告输出",
        "description": "Excel / HTML / JSON 报告生成选项。",
        "icon": "i-inbox",
    },
}

PLUGIN_META: dict[str, dict[str, Any]] = {
    "oneforall": {
        "label": "OneForAll 子域名枚举",
        "description": "从域名收集子域名，输出标准化 JSONL。",
        "tool": "oneforall",
    },
    "httpx_probe": {
        "label": "httpx HTTP 存活探测",
        "description": "探测存活 URL、状态码与页面标题。",
        "tool": "httpx",
    },
    "nmap_scan": {
        "label": "Nmap 端口扫描",
        "description": "端口与服务识别，已扫描 IP 自动跳过。",
        "tool": "nmap",
    },
    "jsfinder": {
        "label": "JSFinder JS 链接提取",
        "description": "从页面与 JavaScript 中提取 URL 和子域名。",
        "tool": "jsfinder",
    },
    "urlfinder": {
        "label": "URLFinder 深度提取",
        "description": "抓取页面与 JS 中的 URL、接口线索。",
        "tool": "urlfinder",
    },
    "ip_discovery": {
        "label": "IP 解析与资产发现",
        "description": "将本轮主机解析为 IP，支持可选 CIDR 展开。",
        "tool": "",
    },
    "api_probe": {
        "label": "API 端点探测",
        "description": "使用 httpx 探测 Swagger / GraphQL / Actuator 等接口。",
        "tool": "httpx",
    },
}

#: Editor metadata. ``type`` is one of text/int/float/bool/array/enum/path.
FIELD_META: dict[str, dict[str, Any]] = {
    # defaults
    "defaults.concurrency": {
        "label": "全局并发数",
        "hint": "同时执行的阶段/任务上限，建议 20–200。",
        "type": "int", "min": 1, "max": 2000,
    },
    "defaults.timeout": {
        "label": "单阶段超时（秒）",
        "hint": "单个插件动作的最长运行时间。",
        "type": "int", "min": 5, "max": 86400,
    },
    # recursive
    "recursive.enabled": {
        "label": "启用多轮递归",
        "hint": "发现新资产后自动进入下一轮。",
        "type": "bool",
    },
    "recursive.max_rounds": {
        "label": "最大轮次",
        "hint": "达到轮次上限后停止扩展。",
        "type": "int", "min": 1, "max": 50,
    },
    "recursive.max_assets_per_round": {
        "label": "每轮最大资产数",
        "hint": "单轮最多处理的主机/URL 数量。",
        "type": "int", "min": 1,
    },
    "recursive.max_ips_per_round": {
        "label": "每轮最大 IP 数",
        "hint": "单轮最多端口扫描的 IP 数量。",
        "type": "int", "min": 1,
    },
    "recursive.ip_cache_scope": {
        "label": "IP 去重范围",
        "hint": "task 仅当前任务去重；workspace 在整个工作区共享。",
        "type": "enum", "options": ["task", "workspace"],
    },
    "recursive.skip_scanned_ips": {
        "label": "跳过已扫描 IP",
        "hint": "开启后不会重复端口扫描同一 IP。",
        "type": "bool",
    },
    "recursive.rescan_ips": {
        "label": "强制重新扫描 IP",
        "hint": "优先级高于“跳过已扫描 IP”。",
        "type": "bool",
    },
    # rate limiter
    "rate_limiter.rps_limit": {
        "label": "每秒请求数上限",
        "hint": "令牌桶补充速率，单位 req/s。",
        "type": "int", "min": 1, "max": 100000,
    },
    "rate_limiter.burst_limit": {
        "label": "突发请求上限",
        "hint": "令牌桶容量，允许短时突发。",
        "type": "int", "min": 1, "max": 100000,
    },
    # retry
    "retry.max_attempts": {
        "label": "最大尝试次数",
        "hint": "包含首次执行，例如 3 表示最多重试 2 次。",
        "type": "int", "min": 1, "max": 10,
    },
    "retry.backoff_seconds": {
        "label": "重试退避（秒）",
        "hint": "每次重试前的等待时间。",
        "type": "int", "min": 0, "max": 3600,
    },
    "retry.retryable_exit_codes": {
        "label": "可重试退出码",
        "hint": "每行一个整数，命中时允许重试。",
        "type": "array", "item_type": "int",
    },
    "retry.non_retryable_exit_codes": {
        "label": "不可重试退出码",
        "hint": "每行一个整数，命中时立即失败。",
        "type": "array", "item_type": "int",
    },
    # waf aware
    "waf_aware.enabled": {
        "label": "启用 WAF 感知",
        "hint": "根据状态码与关键字识别拦截。",
        "type": "bool",
    },
    "waf_aware.auto_recover": {
        "label": "自动恢复",
        "hint": "触发 WAF 后自动等待或轮转代理。",
        "type": "bool",
    },
    "waf_aware.trigger_status_codes": {
        "label": "触发状态码",
        "hint": "每行一个状态码，例如 403。",
        "type": "array", "item_type": "int",
    },
    "waf_aware.trigger_response_keywords": {
        "label": "触发响应关键字",
        "hint": "每行一个关键字，响应命中即视为拦截。",
        "type": "array", "item_type": "text",
    },
    "waf_aware.post_scan_retry.mode": {
        "label": "任务后补扫模式",
        "hint": "auto 自动补扫；manual 人工确认；save_only 仅保存清单。",
        "type": "enum", "options": ["auto", "manual", "save_only"],
    },
    "waf_aware.post_scan_retry.max_retry_attempts": {
        "label": "补扫最大尝试次数",
        "type": "int", "min": 0, "max": 10,
    },
    "waf_aware.post_scan_retry.retry_interval_seconds": {
        "label": "补扫间隔（秒）",
        "type": "int", "min": 0, "max": 86400,
    },
    "waf_aware.recovery.initial_wait_seconds": {
        "label": "初始等待（秒）",
        "type": "int", "min": 0, "max": 86400,
    },
    "waf_aware.recovery.max_wait_seconds": {
        "label": "最大等待（秒）",
        "type": "int", "min": 0, "max": 86400,
    },
    "waf_aware.recovery.backoff_multiplier": {
        "label": "退避倍数",
        "hint": "每次等待时间乘以该倍数。",
        "type": "float", "min": 1, "max": 10, "step": 0.5,
    },
    "waf_aware.recovery.proxy_pool.enabled": {
        "label": "启用代理池",
        "type": "bool",
    },
    "waf_aware.recovery.proxy_pool.sources": {
        "label": "代理源列表",
        "hint": "每行一个代理 URL，例如 http://127.0.0.1:8080。",
        "type": "array", "item_type": "text",
    },
    "waf_aware.recovery.proxy_pool.rotate_on_trigger": {
        "label": "触发时轮转代理",
        "type": "bool",
    },
    "waf_aware.recovery.proxy_pool.max_rotate_attempts": {
        "label": "最大轮转次数",
        "type": "int", "min": 0, "max": 50,
    },
    "waf_aware.recovery.proxy_pool.fallback_on_exhaustion": {
        "label": "代理耗尽后的行为",
        "hint": "enter_wait 表示进入等待恢复。",
        "type": "text",
    },
    # test
    "test.default_target": {
        "label": "默认测试目标",
        "type": "text",
    },
    "test.verbose_by_default": {
        "label": "默认输出详细日志",
        "type": "bool",
    },
    "test.mock_waf_enabled": {
        "label": "启用 WAF 模拟",
        "type": "bool",
    },
    "test.output_dir": {
        "label": "测试输出目录",
        "hint": "相对路径基于项目根目录。",
        "type": "path",
    },
    "test.warn_on_output_exceed": {
        "label": "输出超量告警",
        "type": "bool",
    },
    "test.exceed_ratio_threshold": {
        "label": "超量告警阈值",
        "hint": "实际输出量 / 预期输出量的比值。",
        "type": "float", "min": 1, "max": 100, "step": 0.1,
    },
    # output
    "output.excel.enabled": {
        "label": "生成 Excel 报告",
        "type": "bool",
    },
    "output.excel.file_name": {
        "label": "Excel 文件名模板",
        "hint": "支持 {task_id} 占位符。",
        "type": "text",
    },
    "output.excel.dedup_strategy": {
        "label": "去重策略",
        "type": "text",
    },
    "output.excel.sheets": {
        "label": "工作表列表",
        "hint": "每行一个工作表名称。",
        "type": "array", "item_type": "text",
    },
    "output.excel.chunk_size": {
        "label": "分批写入行数",
        "type": "int", "min": 1,
    },
    "output.excel.max_rows_per_sheet": {
        "label": "单表最大行数",
        "type": "int", "min": 1,
    },
    "output.html.enabled": {
        "label": "生成 HTML 报告",
        "type": "bool",
    },
    "output.json.enabled": {
        "label": "生成 JSON 报告",
        "type": "bool",
    },
    # plugins
    "plugins.oneforall.enabled": {
        "label": "启用插件",
        "type": "bool",
    },
    "plugins.oneforall.oneforall_path": {
        "label": "OneForAll 入口路径",
        "hint": "留空时依次使用环境变量、内置目录与 PATH；可填项目目录或 oneforall.py。",
        "type": "path", "tool": "oneforall",
    },
    "plugins.httpx_probe.enabled": {
        "label": "启用插件",
        "type": "bool",
    },
    "plugins.httpx_probe.httpx_path": {
        "label": "httpx 可执行文件",
        "hint": "留空时优先使用内置 httpx；API 探测默认复用此路径。",
        "type": "path", "tool": "httpx",
    },
    "plugins.httpx_probe.max_hosts": {
        "label": "最大探测主机数",
        "type": "int", "min": 1,
    },
    "plugins.httpx_probe.threads": {
        "label": "并发线程数",
        "hint": "0 表示使用 httpx 默认值。",
        "type": "int", "min": 0, "max": 1000,
    },
    "plugins.httpx_probe.rate_limit": {
        "label": "每秒请求上限",
        "hint": "0 表示不限制。",
        "type": "int", "min": 0, "max": 100000,
    },
    "plugins.httpx_probe.extra_args": {
        "label": "附加命令行参数",
        "hint": "每行一个参数，例如 -timeout。",
        "type": "array", "item_type": "text",
    },
    "plugins.nmap_scan.enabled": {
        "label": "启用插件",
        "type": "bool",
    },
    "plugins.nmap_scan.nmap_path": {
        "label": "Nmap 可执行文件",
        "hint": "可填 nmap.exe 或 Nmap 安装目录；留空时使用 PATH。",
        "type": "path", "tool": "nmap",
    },
    "plugins.nmap_scan.ports": {
        "label": "端口范围",
        "hint": "例如 80,443 或 1-65535 或 -（全端口）。",
        "type": "text",
    },
    "plugins.nmap_scan.timing": {
        "label": "时序模板",
        "hint": "例如 -T4；留空表示不指定。",
        "type": "text",
    },
    "plugins.nmap_scan.min_rate": {
        "label": "最小发包速率",
        "hint": "每秒最少发送的探测包数量。",
        "type": "int", "min": 1,
    },
    "plugins.nmap_scan.extra_args": {
        "label": "附加命令行参数",
        "hint": "每行一个参数。",
        "type": "array", "item_type": "text",
    },
    "plugins.jsfinder.enabled": {
        "label": "启用插件",
        "type": "bool",
    },
    "plugins.jsfinder.jsfinder_path": {
        "label": "JSFinder 入口路径",
        "hint": "留空时依次使用环境变量、内置目录与 PATH。",
        "type": "path", "tool": "jsfinder",
    },
    "plugins.jsfinder.timeout": {
        "label": "单目标超时（秒）",
        "type": "int", "min": 1,
    },
    "plugins.jsfinder.retry": {
        "label": "重试次数",
        "type": "int", "min": 0, "max": 10,
    },
    "plugins.jsfinder.retry_delay": {
        "label": "重试间隔（秒）",
        "type": "int", "min": 0, "max": 3600,
    },
    "plugins.jsfinder.max_targets": {
        "label": "每轮最大目标数",
        "type": "int", "min": 1,
    },
    "plugins.urlfinder.enabled": {
        "label": "启用插件",
        "type": "bool",
    },
    "plugins.urlfinder.urlfinder_path": {
        "label": "URLFinder 可执行文件",
        "hint": "留空时优先使用内置 URLFinder.exe。",
        "type": "path", "tool": "urlfinder",
    },
    "plugins.urlfinder.timeout": {
        "label": "单目标超时（秒）",
        "type": "int", "min": 1,
    },
    "plugins.urlfinder.retry": {
        "label": "重试次数",
        "type": "int", "min": 0, "max": 10,
    },
    "plugins.urlfinder.retry_delay": {
        "label": "重试间隔（秒）",
        "type": "int", "min": 0, "max": 3600,
    },
    "plugins.urlfinder.max_targets": {
        "label": "每轮最大目标数",
        "type": "int", "min": 1,
    },
    "plugins.ip_discovery.enabled": {
        "label": "启用插件",
        "type": "bool",
    },
    "plugins.ip_discovery.dns_workers": {
        "label": "DNS 并发数",
        "type": "int", "min": 1,
    },
    "plugins.ip_discovery.dns_timeout": {
        "label": "DNS 超时（秒）",
        "type": "float", "min": 0.5, "max": 60, "step": 0.5,
    },
    "plugins.ip_discovery.expand_cidr": {
        "label": "展开 CIDR",
        "hint": "将 CIDR 目标展开为主机列表。",
        "type": "bool",
    },
    "plugins.ip_discovery.max_cidr_hosts": {
        "label": "CIDR 最大主机数",
        "type": "int", "min": 1,
    },
    "plugins.ip_discovery.max_hosts": {
        "label": "每轮最大主机数",
        "type": "int", "min": 1,
    },
    "plugins.api_probe.enabled": {
        "label": "启用插件",
        "type": "bool",
    },
    "plugins.api_probe.httpx_path": {
        "label": "httpx 可执行文件",
        "hint": "留空时复用 httpx 存活探测插件的路径或内置 httpx。",
        "type": "path", "tool": "httpx",
    },
    "plugins.api_probe.threads": {
        "label": "并发线程数",
        "type": "int", "min": 1, "max": 1000,
    },
    "plugins.api_probe.timeout": {
        "label": "请求超时（秒）",
        "type": "int", "min": 1, "max": 300,
    },
    "plugins.api_probe.rate_limit": {
        "label": "每秒请求上限",
        "type": "int", "min": 0, "max": 100000,
    },
    "plugins.api_probe.max_origins": {
        "label": "每轮最大 Origin 数",
        "type": "int", "min": 1,
    },
    "plugins.api_probe.max_paths": {
        "label": "每个 Origin 最大路径数",
        "type": "int", "min": 1,
    },
    "plugins.api_probe.include_scheme_fallback": {
        "label": "回退尝试 HTTP/HTTPS",
        "hint": "HTTPS 失败时尝试另一协议。",
        "type": "bool",
    },
    "plugins.api_probe.wordlist": {
        "label": "API 路径字典",
        "hint": "相对路径基于 configs/，例如 wordlists/api_paths.txt。",
        "type": "path",
    },
}


def field_meta(key: str) -> dict[str, Any]:
    """Return metadata for ``key`` with a sensible fallback."""
    meta = FIELD_META.get(key)
    if meta:
        return dict(meta)
    section = key.split(".", 1)[0]
    if section == "plugins" and key.count(".") >= 2:
        plugin = key.split(".")[1]
        label = PLUGIN_META.get(plugin, {}).get("label", plugin)
        return {"label": key.rsplit(".", 1)[-1], "hint": label, "type": "text"}
    return {"label": key.rsplit(".", 1)[-1], "type": "text"}


def schema_payload() -> dict[str, Any]:
    """Serializable schema used by the settings and plugin pages."""
    return {
        "sections": SECTION_META,
        "plugins": PLUGIN_META,
        "fields": FIELD_META,
    }