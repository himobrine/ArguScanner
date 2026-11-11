# ArguScanner – 一键护网信息收集工具

## 项目概览

**ArguScanner** 是一套面向红蓝对抗（护网）场景的"一键信息收集"系统。以 **Python 3.10+** 为核心，兼容 **Windows** 与 **Linux**，通过 **插件抽象层** 把常见渗透工具（OneForAll、httpx、Nmap 等）统一为可调度的插件，实现 **高并发、全链路去重、断点续跑、WAF‑aware 自动恢复** 的生产级流水线。

系统同时提供 **CLI 命令行** 与 **Web UI** 两种操作方式，支持远程发起扫描、实时查看进度与结果。

---

## 目录结构

```
arguscaner/
├── arguscaner/
│   ├── __init__.py
│   ├── entrypoint.py              # CLI 入口 (typer)
│   ├── web/
│   │   ├── __init__.py
│   │   ├── app.py                 # Flask 应用初始化
│   │   ├── routes.py              # 路由: /, /scan, /status, /results
│   │   ├── templates/
│   │   │   ├── base.html          # 基础布局模板
│   │   │   ├── index.html         # 首页: 发起扫描
│   │   │   ├── status.html        # 任务状态页
│   │   │   └── results.html       # 结果查看页
│   │   └── static/
│   │       └── style.css          # 样式文件
│   ├── configs/
│   │   ├── settings.yaml          # 全局配置
│   │   └── pipeline.yaml          # DAG 任务定义
│   ├── core/
│   │   ├── __init__.py
│   │   ├── plugins/
│   │   │   ├── __init__.py
│   │   │   ├── base_plugin.py     # 插件抽象基类
│   │   │   ├── oneforall.py       # OneForAll 子域名枚举
│   │   │   ├── httpx_probe.py     # httpx HTTP 探测
│   │   │   └── nmap_scan.py       # Nmap 端口扫描
│   │   ├── report_generator.py    # Excel 报告生成
│   │   └── dedup.py               # 三层去重
│   ├── scheduler/
│   │   ├── __init__.py
│   │   ├── scheduler_core.py      # DAG 调度核心
│   │   ├── html_generator.py      # HTML 报告生成
│   │   └── logger.py              # JSON-Lines 日志
│   └── utils/
│       ├── __init__.py
│       ├── rate_limiter.py        # 令牌桶限速
│       ├── proxy_manager.py       # 代理池管理
│       └── waf_detector.py        # WAF 触发检测
├── tests/
│   ├── __init__.py
│   ├── test_report_generator.py   # 报告生成测试
│   └── test_tester.py             # 插件测试子命令测试
├── logs/                          # 运行日志
├── workspace/                     # 工作目录（扫描产物）
├── requirements.txt
├── setup.cfg
└── pyproject.toml
```

---

## 六层架构

| 层级 | 职责 | 关键实现 |
|------|------|----------|
| **输入层** | 支持单域名、IP 段、批量清单等多种录入方式 | `configs/settings.yaml`、CLI `auto-recon scan -t <target>`、Web UI 表单 |
| **调度编排层** | 解析任务 DAG、维护状态机、按依赖顺序调度插件 | `scheduler/scheduler_core.py`（networkx.DiGraph） |
| **工具抽象层** | 将 CLI 工具封装为标准插件，解耦、易增删 | `core/plugins/*.py`（BasePlugin 抽象） |
| **数据处理层** | 原始结果清洗、去重、关联聚合 | `core/dedup.py`（三层去重 L1/L2/L3） |
| **输出可视化层** | 生成 HTML、Excel 报告 | `core/report_generator.py`（Excel）`scheduler/html_generator.py`（HTML） |
| **监控与日志层** | 统一记录阶段耗时、错误堆栈、WAF 触发次数 | `scheduler/logger.py`（JSON-Lines）`logs/run.jsonl` |

---

## 三大运行原则

1. **阶段内异步，阶段间同步** – 同一阶段的插件使用高并发并行执行；相邻阶段之间必须等前置阶段全部成功后再开始，保证数据完整性。
2. **数据标准化契约** – 所有插件输出遵循 `output_schema`（JSONL），写入工作目录实现文件交互，不靠内存传递。
3. **断点续跑与容错** – 成功阶段生成 `.done` 标记；插件异常仅影响本阶段，后续阶段继续执行。支持自动恢复或手动补扫。

---

## 调度引擎

### 基本工作流

```
输入层 → 任务 DAG → 调度编排层 → 插件抽象层 → 数据处理层 → 输出可视化层 → 监控与日志层
```

- 任务 DAG 由 `pipeline.yaml` 定义，`networkx.DiGraph` 检测循环依赖
- 全局限速通过令牌桶（`AdaptiveRateLimiter`）实现
- 代理池（`ProxyManager`）支持 `{{proxy}}` 渲染
- WAF 感知：触发后执行代理轮转 → 指数退避 → 标记 fallback_failed

### 流程定义（可编辑）

`configs/pipeline.yaml` 使用 v2 格式，可在 Web「流程」页面直接编辑并以时间戳备份保存：

```yaml
pipeline:
  name: default_recon
  version: 2
stages:
  - id: subdomain_enum
    plugin: oneforall
    label: 子域名枚举
    level: 1                     # 执行层级：同层并发，数值小者先执行
    inputs: []                   # 数据来源；from 指向上游阶段或 target
    outputs: {data: subdomain}   # 连线/数据类型标签
  - id: http_probe
    plugin: httpx_probe
    level: 2
    after: [subdomain_enum]      # 仅排序，前置失败不阻塞
    inputs:
      - {from: subdomain_enum, data: subdomain}
    params:                      # 本阶段插件参数，覆盖 settings.yaml
      timeout: 300
```

- **数据连接是真实绑定**：阶段启动器会把 `inputs` 解析为上游的 `<stage_id>.jsonl` 并注入插件；插件优先读取声明来源，未声明时回退到历史文件名。
- **同一插件可多次使用**：每个阶段拥有独立插件实例与 `params`；插件私有文件中会追加 `__<stage_id>` 后缀避免互相覆盖。
- **递归流程**：`configs/pipeline_recursive.yaml` 为轮次内部流程；`configs/pipelines/<name>.yaml` 保存用户自建流程。

### post_scan_retry 策略

| mode | 行为 |
|------|------|
| `auto` | 任务结束后自动进入补扫 |
| `manual` | 完成后打印中断清单，等待用户 y/N 确认 |
| `save_only` | 仅保存中断状态文件，不启动补扫 |

### 多轮递归扫描

第一轮结束后，调度器会把已发现的子域名、存活 URL、JS 中提取的 URL、API 端点与 IP 汇总为资产目录，并自动开启第二轮。每一轮的流程固定为：

```
ip_discovery → (http_probe ∥ port_scan) → (jsfinder ∥ urlfinder ∥ api_probe)
```

- **不是固定两轮**：每轮结束后把新出现的资产加入队列，继续下一轮，直到无新增资产或达到 `recursive.max_rounds`。
- **IP 跳转**：`ip_discovery` 会解析本轮主机（含域名多 A 记录、IPv6、可选 CIDR 展开）；新 IP 进入下一轮，产生 IP → HTTP → API 的多次跳转。
- **API 发现**：`api_probe` 复用 httpx，对本轮新 origin 探测 Swagger/OpenAPI/GraphQL/Actuator 等路径，新命中端点所属主机继续进入下一轮。
- **IP 去重**：已端口扫描过的 IP 写入 `<task>/.state/scanned_ips.json`，后续轮次（或恢复任务时）自动跳过。`recursive.ip_cache_scope: workspace` 可改为工作区级共享去重。
- **`after` 仅排序**：HTTP 探测等待子域名枚举完成，但枚举失败不会阻塞探测。

相关配置（`settings.yaml`）：

```yaml
recursive:
  enabled: true
  max_rounds: 5              # 总轮次（含第一轮）
  max_assets_per_round: 1000
  max_ips_per_round: 1024
  ip_cache_scope: task       # task | workspace
  skip_scanned_ips: true
  rescan_ips: false
```

轮次产物位于 `workspace/<task_id>/rounds/rNNN/`，报告会汇总所有轮次的结果。

---

## Excel 报告

单个工作簿（`.xlsx`）包含 **11 张 Sheet**：

| Sheet | 列 | 说明 |
|-------|----|------|
| **Summary** | task_id, target, started_at, finished_at, total_duration_seconds, total_assets, subdomain_count, live_url_count, open_port_count, fingerprint_count, vulnerability_count, interrupted_count, waf_trigger_count, failed_stages | 任务概览 |
| **Subdomains** | Domain, IP, Source, Timestamp | OneForAll 等输出 |
| **Live URLs** | URL, Status, Title, Length, IP, Source | httpx 检测结果 |
| **Open Ports** | IP, Port, Protocol, Service, Banner, State | Nmap 扫描 |
| **Fingerprints** | IP, Port, Service, Product, Version, CPE | 指纹识别 |
| **Vulnerabilities** | IP, Port, CVE ID, Severity, Description | 漏洞/风险标记 |
| **Interrupted** | Stage, Target, Error Reason, Blocked Proxy, Retry Count, Status, Retry Timestamp | 中断任务状态 |
| **JS URLs** | URL, Source, Timestamp | JSFinder/URLFinder 提取的 URL |
| **JS Subdomains** | Subdomain, Source, Timestamp | JS 中提取的子域名 |
| **IP映射** | Host, IP, Source, Timestamp | 主机 → IP 解析结果 |
| **API端点** | URL, Status, API Type, Content Type, Title, Evidence, Source, Timestamp | API 端点探测结果 |

### 去重层级

1. **L1 – 阶段内去重**：插件完成后立即对其产出文件执行基于唯一键的去重
2. **L2 – 全局合并去重**：生成报告前加载所有阶段文件，统一合并
3. **L3 – 输出前清洗**：统一字段格式（域名小写、URL 标准化、IP:Port 串化）

---

## 一键搭建

要求 **Python 3.10 或更高版本**（推荐 3.10–3.12）。脚本会自动创建
`.venv`、安装依赖、初始化目录并检测外部工具。

### Windows

```bat
setup.bat
```

或使用 PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

### Linux / macOS

```bash
bash setup.sh
```

### 启动 Web UI

```bat
:: Windows
start.bat
```

```bash
# Linux / macOS
./start.sh
```

### 常用参数

```bash
# 只检查环境，不安装
setup.bat --check              # Windows
bash setup.sh --check          # Linux

# 安装开发依赖并运行测试
setup.bat --dev --test

# 安装可选工具 OneForAll / JSFinder（Nmap 不会自动安装）
setup.bat --install-optional-tools

# 工具路径为空或失效时，自动写回检测到的路径
setup.bat --fix-tool-paths

# 单独选择安装 Redis（默认仅警告，Web UI 可退回线程模式）
setup.bat --install-redis

# 安装完成后直接启动 Web UI
setup.bat --run --host 127.0.0.1 --port 5000
```

- **Nmap** 不自动安装，请在系统中安装后加入 `PATH`，或在 Web 设置页填写
  `Nmap 可执行文件`。
- **Redis** 默认只是警告；未安装时 Celery 不可用，Web UI 自动使用线程模式。
- Windows 缺少 Python 时，安装 3.10+ 任一版本即可（推荐 3.12），无需限定 3.10。

---

## CLI 命令

```bash
# 手动安装（不使用一键脚本时）
pip install -r requirements.txt

# 单目标完整扫描
auto-recon scan example.com --concurrency 150

# 多轮递归扫描（默认启用；--no-recursive 关闭）
auto-recon scan example.com --recursive

# 忽略已扫描 IP 清单，强制重新端口扫描
auto-recon scan example.com --rescan-ips

# 批量目标扫描
auto-recon batch targets.txt --workspace /data/scan

# 查看任务状态
auto-recon status hv-2026-0903-001

# 手动恢复
auto-recon resume hv-2026-0903-001 --force

# 插件调试
auto-recon test-plugin -t example.com -p http_probe --limit 5 --verbose

# 代理池连通性测试
auto-recon test-plugin --test-proxy-pool -t example.com

# 启动 Web UI（默认仅监听本机）
auto-recon web --host 127.0.0.1 --port 5000
# 如需从其他机器访问，请先设置 API 令牌并显式绑定：
#   set ARGUS_API_TOKEN=<随机长字符串>   （Linux: export ARGUS_API_TOKEN=...）
#   auto-recon web --host 0.0.0.0 --port 5000
# 所有写操作（POST/PUT/DELETE）需携带请求头 X-API-Token
```

### 外部工具安装

ArguScanner 依赖以下外部工具。**httpx 与 URLFinder 已内置**在
`arguscaner/tools/`，无需单独安装；其余工具需安装后可在 Web「设置 →
插件配置」中指定路径。

工具路径解析优先级（从高到低）：

1. 流水线阶段 `params` 中的路径
2. `settings.yaml` 的 `plugins.<插件>.<工具>_path`
3. 环境变量（`HTTPX_PATH` / `NMAP_PATH` / `URLFINDER_PATH` /
   `ONEFORALL_PATH` / `JSFINDER_PATH`）
4. 内置目录 `arguscaner/tools/`
5. 系统 `PATH`
6. 裸命令名

#### OneForAll（子域名枚举）

```bash
# 下载 OneForAll（Windows 路径示例，Linux 请替换为对应目录）
git clone https://github.com/shmilylty/OneForAll.git D:\tools\OneForAll

# 安装依赖
cd D:\tools\OneForAll
pip install -r requirements.txt

# 更新配置（settings.yaml）—— 路径需按你的实际安装位置调整
plugins:
  oneforall:
    enabled: true
    oneforall_path: D:\tools\OneForAll\oneforall.py   # Linux: /opt/OneForAll/oneforall.py
```

> 路径优先级：`settings.yaml` 的 `oneforall_path` → 环境变量
> `ONEFORALL_PATH` → 内置目录（如存在）→ PATH 中的 `oneforall.py`。
> 跨平台部署时请显式配置，避免 `FileNotFoundError`。

#### JSFinder（JS URL 提取）

```bash
# 下载 JSFinder（Windows 路径示例，Linux 请替换为对应目录）
git clone https://github.com/Threezh1/JSFinder.git D:\tools\JSFinder

# 安装依赖
cd D:\tools\JSFinder
pip install -r requirements.txt

# 更新配置（settings.yaml）—— 路径需按你的实际安装位置调整
plugins:
  jsfinder:
    enabled: true
    jsfinder_path: D:\tools\JSFinder\JSFinder.py   # Linux: /opt/JSFinder/JSFinder.py
```

#### URLFinder（页面 URL / JS 提取）

URLFinder 已内置：`arguscaner/tools/urlfinder/URLFinder.exe`（MIT），
无需安装。如需使用其他版本，在设置页或 `settings.yaml` 中覆盖：

```yaml
plugins:
  urlfinder:
    enabled: true
    urlfinder_path: D:\tools\URLFinder\URLFinder.exe   # 留空则使用内置
```

> 路径优先级：`settings.yaml` → 环境变量 `URLFINDER_PATH` → 内置 → PATH。

#### Nmap（端口扫描）

Nmap 需要单独安装：https://nmap.org/download.html

安装后确保 `nmap` 在系统 PATH 中；也可在设置页指定 `nmap.exe` 或安装目录：

```yaml
plugins:
  nmap_scan:
    nmap_path: D:\tools\nmap\nmap.exe   # 或 D:\tools\nmap
```

#### httpx（HTTP 存活检测）

httpx 已内置：`arguscaner/tools/httpx/httpx.exe`（MIT），无需安装。
如需使用其他版本：

```yaml
plugins:
  httpx_probe:
    httpx_path: C:\Tools\httpx.exe   # 留空则使用内置；api_probe 默认复用此路径
```

---

## Web UI

### 启动

```bash
auto-recon web --host 127.0.0.1 --port 5000
# 浏览器访问 http://localhost:5000
# 远程访问需显式绑定 0.0.0.0 并设置 ARGUS_API_TOKEN（见上文）
```

### 页面

| 路由 | 功能 |
|------|------|
| `GET /` | 首页，填写扫描目标、选择插件、设置并发参数 |
| `POST /api/scan` | 创建扫描任务，返回 task_id |
| `GET /status/<task_id>` | 任务状态页，实时展示阶段进度、WAF 触发数 |
| `GET /results/<task_id>` | 结果查看页，表格展示各 Sheet 数据 |
| `GET /api/status/<task_id>` | JSON API: 阶段进度、错误信息 |
| `GET /api/logs/<task_id>` | JSON API: 最近日志条目 |

### 交互流程

```
用户浏览器 → GET / → 填写目标、选择插件
         → POST /api/scan → 返回 task_id，重定向到 /status/<task_id>
         → /status 页面: 每 3s AJAX GET /api/status/<task_id> 轮询进度
         → 扫描完成: 跳转 /results/<task_id> 查看报告
```

前端使用 **Jinja2 + HTMX**，AJAX 定时轮询实现进度更新，无需 WebSocket。

---

## 插件系统

### BasePlugin 抽象基类

所有插件继承 `BasePlugin`，需实现：
- `name`: 插件名称
- `command_template`: CLI 命令模板（支持 `{{target}}`、`{{output}}`、`{{proxy}}` 等变量）
  > 安全说明：所有插件均以 **argv 列表 + `shell=False`** 执行。模板会被
  > `shlex` 拆分为参数，**不会经过 shell**。因此模板中不要使用管道 `|`、
  > 重定向 `>`、`&&`、`$VAR` 等 shell 特性——它们会被当作普通参数。
  > 内置插件直接构造 argv，`command_template` 仅用于展示。
- `output_schema`: 输出字段定义
- `execute(target, workdir, proxy=None)`: 执行命令
- `parse_output(output_file)`: 解析输出为结构化字典列表

### 内置插件

| 插件 | 工具 | 用途 |
|------|------|------|
| `oneforall` | OneForAll | 子域名枚举 |
| `httpx_probe` | httpx | HTTP 存活探测 |
| `nmap_scan` | Nmap | 端口扫描 |

---

## WAF 感知

| 触发条件 | 恢复策略 |
|----------|----------|
| HTTP 状态码命中 `trigger_status_codes` | 1. 代理轮转（若还有可用代理） |
| 响应关键词命中 `trigger_response_keywords` | 2. 指数退避（initial_wait → max_wait） |
| | 3. 最终兜底：标记 fallback_failed，继续调度其它资产 |

全局暂停/恢复：`pause(reason, resume_at)` 将 RPS 降至 `initial_rps_ratio`，恢复后逐步 ramp-up。

---

## 全局配置 `configs/settings.yaml`

```yaml
defaults:
  concurrency: 100
  timeout: 300

rate_limiter:
  rps_limit: 100
  burst_limit: 20

retry:
  max_attempts: 3
  backoff_seconds: 30
  retryable_exit_codes: [1, 2, 137]
  non_retryable_exit_codes: [0, 127]

waf_aware:
  enabled: true
  auto_recover: true
  post_scan_retry:
    mode: auto
    max_retry_attempts: 2
    retry_interval_seconds: 60
  recovery:
    initial_wait_seconds: 60
    max_wait_seconds: 3600
    backoff_multiplier: 2
    proxy_pool:
      enabled: true
      sources: ["http://proxy1:8080", "socks5://proxy2:1080"]
      rotate_on_trigger: true
      max_rotate_attempts: 5
      fallback_on_exhaustion: "enter_wait"

test:
  default_target: "example.com"
  verbose_by_default: false
  mock_waf_enabled: false
  output_dir: "workspace/test_outputs"
  warn_on_output_exceed: true
  exceed_ratio_threshold: 1.5

output:
  excel:
    enabled: true
    file_name: "report_{task_id}.xlsx"
    dedup_strategy: "global"
    sheets: ["Summary", "Subdomains", "Live URLs", "Open Ports", "Fingerprints", "Vulnerabilities", "Interrupted"]
    chunk_size: 50000
    max_rows_per_sheet: 1048000
  html:
    enabled: true
  json:
    enabled: false
```

---

## 实现阶段

| 阶段 | 内容 | 优先级 |
|------|------|--------|
| Phase 1 | 项目脚手架：目录结构、requirements.txt、pyproject.toml、配置文件 | 高 |
| Phase 2 | 插件系统：BasePlugin 抽象基类 + OneForAll/httpx/Nmap 三个插件 | 高 |
| Phase 3 | 调度核心：DAG 解析、任务状态机、异步执行、断点续跑 | 高 |
| Phase 4 | 数据处理：三层去重（L1/L2/L3）、唯一键合并 | 高 |
| Phase 5 | Excel 报告生成：openpyxl、7 张 Sheet、分块写入、CSV 回退 | 高 |
| Phase 6 | CLI 界面：typer 实现 scan/batch/status/resume/test-plugin/web | 高 |
| Phase 7 | Web UI：Flask + Jinja2/HTMX、AJAX 轮询进度 | 中 |
| Phase 8 | WAF 感知：简化版检测、令牌桶限速、代理池桩 | 中 |
| Phase 9 | 日志：JSON-Lines、.done 标记、断点续跑 | 中 |
| Phase 10 | 单元测试：报告生成、插件测试子命令 | 中 |
| Phase 11 | 集成验证：端到端 CLI/Web 扫描 | 低 |

---

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Python 3.10+ |
| CLI | Typer |
| Web 后端 | Flask |
| 前端 | Jinja2 + HTMX |
| 实时更新 | AJAX 定时轮询（3s 间隔） |
| 任务依赖 | networkx (DiGraph DAG) |
| Excel 报告 | openpyxl |
| 数据校验 | Pydantic |
| 配置管理 | PyYAML |
| 测试 | pytest |

---

## 依赖安装

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
openpyxl>=3.1.0
typer>=0.9.0
pydantic>=2.0
networkx>=2.8
PyYAML>=6.0
flask>=3.0
```

---

## 许可证

本项目采用 **GNU Affero General Public License v3.0 or later（AGPL-3.0-or-later）** 发布，完整条款见 [LICENSE](LICENSE)。

内置的第三方工具 `httpx` 与 `URLFinder` 仍分别遵循其自带的 MIT 许可证，许可证文件位于 `arguscaner/tools/` 对应目录。

---

*本 README 记录了截至 2026‑09‑04 的完整架构与实现计划，后续功能迭代请同步更新对应章节。*
