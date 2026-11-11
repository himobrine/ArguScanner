#!/usr/bin/env python3
"""One-click setup for ArguScanner (Windows / Linux / macOS).

The platform wrappers (``setup.bat`` / ``setup.ps1`` / ``setup.sh``) only
locate a suitable Python interpreter; all real work happens here.  The script
uses the standard library only so it can run before dependencies are installed.
"""

from __future__ import annotations

import argparse
import copy
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENV_DIR = PROJECT_ROOT / ".venv"
CONFIGS_DIR = PROJECT_ROOT / "arguscaner" / "configs"
SETTINGS_PATH = CONFIGS_DIR / "settings.yaml"
LOGS_DIR = PROJECT_ROOT / "logs"
LOG_PATH = LOGS_DIR / "setup.log"

MIN_PYTHON = (3, 10)
TESTED_MAX = (3, 12)

OPTIONAL_TOOLS = [
    {
        "name": "OneForAll",
        "owner": "shmilylty",
        "repo": "OneForAll",
        "target": PROJECT_ROOT / "arguscaner" / "tools" / "oneforall",
        "entry": "oneforall.py",
        "note": "子域名枚举（Python）",
    },
    {
        "name": "JSFinder",
        "owner": "Threezh1",
        "repo": "JSFinder",
        "target": PROJECT_ROOT / "arguscaner" / "tools" / "jsfinder",
        "entry": "JSFinder.py",
        "note": "JS URL / 子域名提取（Python）",
    },
]


# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------
def log(message: str, level: str = "info") -> None:
    prefix = {
        "info": "[*]",
        "ok": "[+]",
        "warn": "[!]",
        "error": "[-]",
    }.get(level, "[*]")
    line = f"{prefix} {message}"
    print(line, flush=True)
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def section(title: str) -> None:
    print()
    print(f"== {title} ==", flush=True)


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="setup.py",
        description="ArguScanner 一键搭建脚本（Windows / Linux / macOS）",
    )
    parser.add_argument("--dev", action="store_true", help="安装开发依赖（pytest 等）")
    parser.add_argument(
        "--no-venv",
        "--system",
        dest="no_venv",
        action="store_true",
        help="不使用虚拟环境，直接安装到当前 Python",
    )
    parser.add_argument("--recreate-venv", action="store_true", help="删除并重建 .venv")
    parser.add_argument("--check", action="store_true", help="仅检查环境，不做安装")
    parser.add_argument(
        "--fix-tool-paths",
        action="store_true",
        help="把检测到的工具路径写回 settings.yaml（仅修复空值/失效路径）",
    )
    parser.add_argument(
        "--install-optional-tools",
        action="store_true",
        help="安装 OneForAll 和 JSFinder（Nmap 不自动安装）",
    )
    parser.add_argument(
        "--install-redis",
        action="store_true",
        help="单独选择安装 Redis（默认只警告）",
    )
    parser.add_argument("--test", action="store_true", help="安装后运行 pytest")
    parser.add_argument("--run", action="store_true", help="安装完成后启动 Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Web UI 绑定地址")
    parser.add_argument("--port", type=int, default=5000, help="Web UI 端口")
    parser.add_argument("--yes", "-y", action="store_true", help="非交互模式，自动确认")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# Python / venv helpers
# ---------------------------------------------------------------------------
def python_version_ok(version_info: tuple[int, ...]) -> bool:
    return tuple(version_info[:2]) >= MIN_PYTHON


def python_install_hint() -> str:
    if os.name == "nt":
        return (
            "请安装 Python 3.10 或更高版本（推荐 3.12）。\n"
            "  下载：https://www.python.org/downloads/windows/\n"
            "  或：  winget install Python.Python.3.12\n"
            "  安装时请勾选 “Add Python to PATH”。"
        )
    if sys.platform == "darwin":
        return (
            "请安装 Python 3.10+（推荐 3.12）：\n"
            "  brew install python@3.12\n"
            "  或从 https://www.python.org/downloads/macos/ 下载。"
        )
    return (
        "请安装 Python 3.10+（推荐 3.12）：\n"
        "  Ubuntu/Debian: sudo apt install python3 python3-venv\n"
        "  RHEL/CentOS:   sudo dnf install python3\n"
        "  Arch:          sudo pacman -S python"
    )


def venv_python_path(venv_dir: Path = VENV_DIR) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def running_in_project_venv(venv_dir: Path = VENV_DIR) -> bool:
    try:
        return Path(sys.prefix).resolve() == venv_dir.resolve()
    except OSError:  # pragma: no cover - defensive
        return False


def run(
    cmd: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    check: bool = False,
    capture: bool = False,
) -> subprocess.CompletedProcess:
    log("执行：" + " ".join(str(part) for part in cmd))
    return subprocess.run(
        [str(part) for part in cmd],
        cwd=str(cwd),
        check=check,
        capture_output=capture,
        text=True,
    )


def ensure_venv(recreate: bool = False) -> Path:
    python = venv_python_path()
    if recreate and VENV_DIR.exists():
        log("删除旧虚拟环境 .venv", "warn")
        shutil.rmtree(VENV_DIR, ignore_errors=True)
    if not python.exists():
        log("创建虚拟环境 .venv")
        result = run([sys.executable, "-m", "venv", str(VENV_DIR)])
        if result.returncode != 0 or not python.exists():
            log("虚拟环境创建失败。", "error")
            if sys.platform.startswith("linux"):
                log("Debian/Ubuntu 可能需要先安装：sudo apt install python3-venv", "warn")
            raise SystemExit(1)
    return python


def reexec_in_venv(argv: list[str]) -> int:
    python = ensure_venv(recreate="--recreate-venv" in argv)
    log(f"切换到虚拟环境：{python}")
    return subprocess.call(
        [str(python), str(Path(__file__).resolve()), *argv],
        cwd=str(PROJECT_ROOT),
    )


# ---------------------------------------------------------------------------
# install / directory helpers
# ---------------------------------------------------------------------------
def install_dependencies(python: str, dev: bool = False) -> bool:
    section("安装依赖")
    run([python, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])

    target = ".[dev]" if dev else "."
    result = run([python, "-m", "pip", "install", "-e", target])
    if result.returncode == 0:
        log("依赖安装完成。", "ok")
        return True

    log("可编辑安装失败，尝试 requirements.txt", "warn")
    result = run([python, "-m", "pip", "install", "-r", "requirements.txt"])
    if result.returncode == 0:
        log("依赖安装完成（requirements.txt）。", "ok")
        return True
    log("依赖安装失败，请查看上方日志。", "error")
    return False


def ensure_dirs(root: Path = PROJECT_ROOT) -> list[Path]:
    targets = [
        root / "workspace",
        root / "logs",
        root / "arguscaner" / "configs" / "custom_plugins",
        root / "arguscaner" / "configs" / "pipelines",
    ]
    created: list[Path] = []
    for target in targets:
        if not target.exists():
            target.mkdir(parents=True, exist_ok=True)
            created.append(target)
    if created:
        log("已创建目录：" + ", ".join(str(path) for path in created), "ok")
    else:
        log("运行目录已存在。")
    return created


GITIGNORE_LINES = [
    ".venv/",
    "__pycache__/",
    "*.py[cod]",
    ".pytest_cache/",
    "workspace/",
    "logs/",
    "*.log",
]


def ensure_gitignore(root: Path = PROJECT_ROOT) -> bool:
    path = root / ".gitignore"
    existing = ""
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError:
            existing = ""
    missing = [
        line for line in GITIGNORE_LINES
        if line not in {item.strip() for item in existing.splitlines()}
    ]
    if not missing:
        return False
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(prefix + "\n".join(missing) + "\n")
    log("已更新 .gitignore", "ok")
    return True


def ensure_script_permissions(root: Path = PROJECT_ROOT) -> None:
    """Make the shell entrypoints executable on POSIX systems."""
    if os.name == "nt":
        return
    for name in ("setup.sh", "start.sh"):
        path = root / name
        if path.exists():
            try:
                path.chmod(path.stat().st_mode | 0o111)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# settings / tool detection
# ---------------------------------------------------------------------------
def load_settings(path: Path = SETTINGS_PATH) -> dict:
    try:
        import yaml
    except ImportError:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except (OSError, ValueError):
        return {}


def save_settings(settings: dict, path: Path = SETTINGS_PATH) -> None:
    import yaml

    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(settings, handle, allow_unicode=True, sort_keys=False)


def _nested_get(data: dict, dotted: str):
    current = data
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _nested_set(data: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    current = data
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def detect_tools(settings: dict | None = None) -> list[dict]:
    """Return tool resolution metadata without importing third-party modules."""
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from arguscaner.utils.tool_paths import describe_tools

    return describe_tools(settings or {})


def print_tools(tools: list[dict]) -> None:
    section("外部工具")
    if not tools:
        log("无法读取工具信息。", "warn")
        return
    for tool in tools:
        status = "可用" if tool["exists"] else "缺失"
        log(
            f"{tool['label']}: {status} | {tool['source_label']} | "
            f"{tool['path'] or '-'}",
            "ok" if tool["exists"] else "warn",
        )
    missing = [tool["label"] for tool in tools if not tool["exists"]]
    if missing:
        log("缺失工具：" + ", ".join(missing), "warn")
        log("Nmap 需单独安装并加入 PATH，或在设置页指定 nmap_path。", "warn")


def fix_tool_paths(settings_path: Path = SETTINGS_PATH) -> list[str]:
    """Write detected paths back, only when the current value is empty/broken."""
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from arguscaner.core.tool_registry import TOOL_SPECS
    from arguscaner.utils.tool_paths import resolve_tool

    settings = load_settings(settings_path)
    if not settings:
        log("无法读取 settings.yaml，跳过路径修复。", "warn")
        return []

    changes: list[str] = []
    for key, spec in TOOL_SPECS.items():
        setting_keys = spec.get("setting_keys") or []
        if not setting_keys:
            continue
        setting_key = setting_keys[0]
        configured = _nested_get(settings, setting_key)
        resolved = resolve_tool(key, settings)

        if resolved.exists and not configured:
            if resolved.source in ("path", "env"):
                _nested_set(settings, setting_key, resolved.path)
                changes.append(f"{key}: 写入 {resolved.path}")
            continue

        if configured and not resolved.exists:
            fallback_settings = copy.deepcopy(settings)
            _nested_set(fallback_settings, setting_key, "")
            alternative = resolve_tool(key, fallback_settings)
            if not alternative.exists:
                log(f"{spec['label']} 路径失效且没有可用替代：{configured}", "warn")
                continue
            if alternative.source in ("path", "env"):
                _nested_set(settings, setting_key, alternative.path)
                changes.append(f"{key}: {configured} -> {alternative.path}")
            else:
                _nested_set(settings, setting_key, "")
                changes.append(f"{key}: 清除失效路径，改用{alternative.source_label}")

    if changes:
        save_settings(settings, settings_path)
        log("已修复工具路径：" + "；".join(changes), "ok")
    else:
        log("工具路径无需修复。")
    return changes


# ---------------------------------------------------------------------------
# optional tools
# ---------------------------------------------------------------------------
def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    answer = input(f"{prompt} [y/N] ").strip().lower()
    return answer in ("y", "yes")


def _download_zip(owner: str, repo: str, target: Path) -> bool:
    urls = [
        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/master",
        f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/main",
    ]
    for url in urls:
        try:
            log(f"下载 {repo}：{url}")
            request = urllib.request.Request(
                url, headers={"User-Agent": "ArguScanner-Setup/1.0"}
            )
            with urllib.request.urlopen(request, timeout=90) as response:
                payload = response.read()
            with tempfile.TemporaryDirectory() as temp_dir:
                archive = Path(temp_dir) / "repo.zip"
                archive.write_bytes(payload)
                with zipfile.ZipFile(archive) as bundle:
                    bundle.extractall(temp_dir)
                roots = [path for path in Path(temp_dir).iterdir() if path.is_dir()]
                if not roots:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(roots[0]), str(target))
            return True
        except Exception as exc:  # noqa: BLE001 - network/zip failures
            log(f"下载失败：{exc}", "warn")
    return False


def _find_entry(target: Path, entry: str) -> Path | None:
    direct = target / entry
    if direct.exists():
        return direct
    for found in target.rglob(entry):
        if found.is_file():
            return found
    return None


def _find_requirements(entry: Path, target: Path) -> Path | None:
    candidates = [
        target / "requirements.txt",
        entry.parent / "requirements.txt",
        entry.parent.parent / "requirements.txt",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def install_optional_tools(python: str, assume_yes: bool = False) -> list[str]:
    section("可选工具：OneForAll / JSFinder")
    log("Nmap 不会自动安装；如需使用请单独安装并配置路径。", "warn")
    if not _confirm("安装 OneForAll 和 JSFinder？这会下载仓库并安装其依赖。", assume_yes):
        log("已跳过可选工具安装。")
        return []

    git = shutil.which("git")
    installed: list[str] = []
    for item in OPTIONAL_TOOLS:
        target: Path = item["target"]
        entry = _find_entry(target, item["entry"]) if target.exists() else None
        if entry:
            log(f"{item['name']} 已存在：{entry}", "ok")
            installed.append(str(entry))
            continue

        if target.exists():
            shutil.rmtree(target, ignore_errors=True)

        ok = False
        if git:
            result = run(
                [git, "clone", "--depth", "1",
                 f"https://github.com/{item['owner']}/{item['repo']}.git",
                 str(target)]
            )
            ok = result.returncode == 0
        if not ok:
            ok = _download_zip(item["owner"], item["repo"], target)

        if not ok:
            log(f"{item['name']} 安装失败。", "error")
            continue

        entry = _find_entry(target, item["entry"])
        if not entry:
            log(f"{item['name']} 下载完成，但未找到 {item['entry']}。", "warn")
            continue

        requirements = _find_requirements(entry, target)
        if requirements:
            log(f"安装 {item['name']} 依赖：{requirements}")
            result = run([python, "-m", "pip", "install", "-r", str(requirements)])
            if result.returncode != 0:
                log(
                    f"{item['name']} 依赖安装失败，工具仍会写入路径，可稍后手动补装。",
                    "warn",
                )
        installed.append(str(entry))
        log(f"{item['name']} 已安装：{entry}", "ok")
    return installed


# ---------------------------------------------------------------------------
# Redis (optional, explicit)
# ---------------------------------------------------------------------------
def redis_reachable(host: str = "127.0.0.1", port: int = 6379) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _run_maybe_sudo(cmd: list[str]) -> int:
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    return run(cmd).returncode


def install_redis(assume_yes: bool = False) -> bool:
    section("可选组件：Redis")
    if redis_reachable():
        log("Redis 已在 127.0.0.1:6379 运行。", "ok")
        return True

    log("Redis 未运行：Celery 不可用，Web UI 将自动使用线程模式（功能可用）。", "warn")
    if not assume_yes and not _confirm("尝试安装 Redis？", assume_yes):
        log("已跳过 Redis 安装。")
        return False

    system = platform.system()
    if system == "Windows":
        log(
            "Windows 无官方 Redis。可选方案：Memurai、Docker 或 WSL。\n"
            "  Docker: docker run -d -p 6379:6379 redis:7\n"
            "  Memurai: https://www.memurai.com/",
            "warn",
        )
        return False
    if system == "Darwin":
        if not shutil.which("brew"):
            log("未找到 Homebrew，请先安装：https://brew.sh/", "error")
            return False
        code = run(["brew", "install", "redis"]).returncode
        if code == 0:
            log("Redis 已安装，可运行：brew services start redis", "ok")
        return code == 0

    os_release = Path("/etc/os-release")
    release_text = ""
    if os_release.exists():
        try:
            release_text = os_release.read_text(encoding="utf-8").lower()
        except OSError:
            release_text = ""
    if "debian" in release_text or "ubuntu" in release_text:
        _run_maybe_sudo(["apt-get", "update"])
        code = _run_maybe_sudo(["apt-get", "install", "-y", "redis-server"])
        start_hint = "sudo systemctl enable --now redis-server"
    elif "fedora" in release_text or "rhel" in release_text or "centos" in release_text:
        code = _run_maybe_sudo(["dnf", "install", "-y", "redis"])
        start_hint = "sudo systemctl enable --now redis"
    elif "arch" in release_text:
        code = _run_maybe_sudo(["pacman", "-S", "--noconfirm", "redis"])
        start_hint = "sudo systemctl enable --now redis"
    else:
        log("未识别的 Linux 发行版，请手动安装 Redis。", "warn")
        return False

    if code == 0:
        log(f"Redis 已安装，启动命令：{start_hint}", "ok")
        return True
    log("Redis 安装失败，请手动安装。", "error")
    return False


# ---------------------------------------------------------------------------
# smoke checks / summary
# ---------------------------------------------------------------------------
def smoke_check(python: str) -> bool:
    section("冒烟检查")
    import_result = run(
        [python, "-c", "import arguscaner; print(arguscaner.__version__)"],
        capture=True,
    )
    if import_result.returncode != 0:
        log("导入 arguscaner 失败：", "error")
        if import_result.stderr:
            print(import_result.stderr)
        return False
    log(f"arguscaner 导入正常（v{import_result.stdout.strip()}）。", "ok")

    help_result = run(
        [python, "-m", "arguscaner.entrypoint", "--help"],
        capture=True,
    )
    if help_result.returncode != 0:
        log("auto-recon 命令检查失败。", "error")
        if help_result.stderr:
            print(help_result.stderr)
        return False
    log("auto-recon 命令可用。", "ok")
    return True


def print_summary(tools: list[dict], redis_ok: bool, python: str) -> None:
    section("搭建完成")
    if os.name == "nt":
        activate = r".venv\Scripts\activate"
    else:
        activate = "source .venv/bin/activate"
    log(f"Python：{python}")
    log(f"激活环境：{activate}")
    if os.name == "nt":
        log("启动服务：start.bat")
    else:
        log("启动服务：./start.sh")
    log("或直接运行：auto-recon web --host 127.0.0.1 --port 5000")
    log("Redis：" + ("已连接" if redis_ok else "未连接（线程模式可用）"),
        "ok" if redis_ok else "warn")
    missing = [tool["label"] for tool in tools if not tool["exists"]]
    if missing:
        log("仍需配置的工具：" + ", ".join(missing), "warn")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _log_python_info() -> None:
    log(f"Python：{sys.version.split()[0]}（{sys.executable}）")
    if sys.version_info[:2] > TESTED_MAX:
        log(
            f"当前 Python {sys.version.split()[0]} 高于已验证版本 3.12，"
            "如遇依赖问题请改用 3.10–3.12。",
            "warn",
        )
    log(f"项目目录：{PROJECT_ROOT}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not python_version_ok(sys.version_info):
        log(
            f"当前 Python {sys.version.split()[0]} 低于要求（>= 3.10）。",
            "error",
        )
        print(python_install_hint())
        return 1

    os.chdir(PROJECT_ROOT)

    if args.check:
        section("环境检查")
        _log_python_info()
        settings = load_settings()
        tools = detect_tools(settings)
        redis_ok = redis_reachable()
        print_tools(tools)
        log("Redis：" + ("可连接" if redis_ok else "未连接（可选）"),
            "ok" if redis_ok else "warn")
        log("仅检查模式，未执行安装。", "ok")
        return 0

    if not args.no_venv and not running_in_project_venv():
        log(f"检测到 Python {sys.version.split()[0]}（{sys.executable}）")
        return reexec_in_venv(list(argv if argv is not None else sys.argv[1:]))

    section("环境检查")
    _log_python_info()

    settings = load_settings()
    tools = detect_tools(settings)
    redis_ok = redis_reachable()

    ensure_dirs()
    ensure_gitignore()
    ensure_script_permissions()

    if not install_dependencies(sys.executable, args.dev):
        return 1

    # Dependencies (including PyYAML) are now available: reload settings so
    # configured tool paths are honoured during detection.
    settings = load_settings()
    tools = detect_tools(settings)

    installed = []
    if args.install_optional_tools:
        installed = install_optional_tools(sys.executable, args.yes)
    if installed:
        settings = load_settings()
        tools = detect_tools(settings)

    if args.install_redis:
        redis_ok = install_redis(args.yes)
    elif not redis_ok:
        log("Redis 未运行：Celery 不可用，Web UI 将使用线程模式（功能可用）。", "warn")

    if args.fix_tool_paths:
        fix_tool_paths()
        settings = load_settings()
        tools = detect_tools(settings)

    print_tools(tools)

    if not smoke_check(sys.executable):
        return 1

    if args.test:
        section("运行测试")
        result = run([sys.executable, "-m", "pytest", "-q"])
        if result.returncode != 0:
            log("测试未通过。", "error")
            return result.returncode

    print_summary(tools, redis_ok, sys.executable)

    if args.run:
        section("启动 Web UI")
        return run(
            [
                sys.executable,
                "-m",
                "arguscaner.entrypoint",
                "web",
                "--host",
                args.host,
                "--port",
                str(args.port),
            ]
        ).returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())