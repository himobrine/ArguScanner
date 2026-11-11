"""ArguScanner CLI entry point - Typer application with all commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from arguscaner import __version__

app = typer.Typer(
    name="auto-recon",
    help="ArguScanner - 红蓝队一键信息收集工具。",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

CONFIGS_DIR = Path(__file__).parent / "configs"
SETTINGS_YAML = CONFIGS_DIR / "settings.yaml"
PIPELINE_YAML = CONFIGS_DIR / "pipeline.yaml"
CUSTOM_PIPELINES_DIR = CONFIGS_DIR / "pipelines"


def _load_settings() -> dict:
    with open(SETTINGS_YAML, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _save_settings(settings: dict) -> None:
    with open(SETTINGS_YAML, "w", encoding="utf-8") as f:
        yaml.safe_dump(settings, f, allow_unicode=True, sort_keys=False)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: str = typer.Argument(..., help="目标（支持逗号分隔多目标，如：example.com,192.168.1.1,http://10.0.0.1）。"),
    concurrency: int = typer.Option(100, "--concurrency", "-c", help="最大并发数。"),
    workspace: Optional[str] = typer.Option(None, "--workspace", "-w", help="工作目录。"),
    pipeline: Optional[str] = typer.Option(None, "--pipeline", "-p", help="自定义流程名称或文件。"),
    recursive: Optional[bool] = typer.Option(
        None, "--recursive/--no-recursive",
        help="启用/禁用多轮递归扫描（默认读取 settings.recursive.enabled）。",
    ),
    rescan_ips: bool = typer.Option(
        False, "--rescan-ips",
        help="忽略已扫描 IP 清单，强制重新进行端口扫描。",
    ),
) -> None:
    """对目标执行完整扫描流程（支持批量）。"""
    from arguscaner.core.report_generator import ReportGenerator
    from arguscaner.scheduler.scheduler_core import (
        PipelineScheduler,
        generate_task_id,
        load_settings,
    )
    from arguscaner.utils.target_classifier import TargetClassifier

    settings = load_settings(SETTINGS_YAML)
    settings["defaults"]["concurrency"] = concurrency
    _apply_recursive_options(settings, recursive, rescan_ips)

    pipeline_file = _resolve_pipeline(pipeline)
    targets = TargetClassifier.parse_targets(target)

    if not targets:
        console.print("[bold red]无效目标：[/] 目标为空")
        raise typer.Exit(1)

    for tgt in targets:
        try:
            target_type = TargetClassifier.classify(tgt).value
        except ValueError as e:
            console.print(f"[bold red]无效目标：[/] {e}")
            continue

        task_id = generate_task_id()
        workdir = Path(workspace) / task_id if workspace else Path(__file__).parent.parent.parent / "workspace" / task_id
        workdir.mkdir(parents=True, exist_ok=True)

        console.print(f"\n[bold]--- 扫描目标：{tgt} ({target_type}) ---[/]")
        console.print(f"[bold green]任务 ID：[/] {task_id}")
        console.print(f"[bold green]流程：[/] {pipeline_file.name}")
        console.print(f"[bold green]工作目录：[/] {workdir}")

        scheduler = PipelineScheduler(pipeline_file, settings)
        result = scheduler.run(tgt, workdir, task_id, recursive=recursive)

        console.print(f"[bold]流程完成，耗时 {result.total_duration:.2f}s[/]")
        if result.recursive_rounds:
            console.print(f"[bold]递归轮次：[/] {len(result.recursive_rounds)}")

        if result.failed_stages:
            console.print(f"[bold red]失败阶段：[/] {', '.join(result.failed_stages)}")

        report_gen = ReportGenerator(workdir, task_id, settings)
        report_path = report_gen.generate(result)
        console.print(f"[bold green]报告：[/] {report_path}")

        _print_stage_summary(result)


# ---------------------------------------------------------------------------
# batch command
# ---------------------------------------------------------------------------

@app.command()
def batch(
    targets_file: str = typer.Argument(..., help="目标文件（每行一个）。"),
    workspace: Optional[str] = typer.Option(None, "--workspace", "-w", help="工作目录。"),
    concurrency: int = typer.Option(100, "--concurrency", "-c", help="最大并发数。"),
    pipeline: Optional[str] = typer.Option(None, "--pipeline", "-p", help="自定义流程名称或文件。"),
    recursive: Optional[bool] = typer.Option(
        None, "--recursive/--no-recursive",
        help="启用/禁用多轮递归扫描（默认读取 settings.recursive.enabled）。",
    ),
    rescan_ips: bool = typer.Option(
        False, "--rescan-ips",
        help="忽略已扫描 IP 清单，强制重新进行端口扫描。",
    ),
) -> None:
    """从文件读取多个目标批量扫描。"""
    from arguscaner.core.report_generator import ReportGenerator
    from arguscaner.scheduler.scheduler_core import (
        PipelineScheduler,
        generate_task_id,
        load_settings,
    )

    targets_path = Path(targets_file)
    if not targets_path.exists():
        console.print(f"[bold red]文件未找到：[/] {targets_file}")
        raise typer.Exit(1)

    targets = [
        line.strip()
        for line in targets_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    console.print(f"[bold]已加载 {len(targets)} 个目标，来源 {targets_file}[/]")

    settings = load_settings(SETTINGS_YAML)
    settings["defaults"]["concurrency"] = concurrency
    _apply_recursive_options(settings, recursive, rescan_ips)
    pipeline_file = _resolve_pipeline(pipeline)

    ws = Path(workspace) if workspace else Path(__file__).parent.parent.parent / "workspace"

    for i, target in enumerate(targets, 1):
        console.print(f"\n[bold cyan]--- [{i}/{len(targets)}] 目标：{target} ---[/]")

        task_id = generate_task_id()
        workdir = ws / task_id
        workdir.mkdir(parents=True, exist_ok=True)

        scheduler = PipelineScheduler(pipeline_file, settings)
        result = scheduler.run(target, workdir, task_id, recursive=recursive)

        report_gen = ReportGenerator(workdir, task_id, settings)
        report_path = report_gen.generate(result)
        console.print(f"[green]报告：[/] {report_path}")

    console.print(f"\n[bold green]批量完成：{len(targets)} 个目标已处理。[/]")


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------

@app.command()
def status(
    task_id: str = typer.Argument(..., help="要查看的任务 ID。"),
    workspace: Optional[str] = typer.Option(None, "--workspace", "-w", help="工作目录。"),
) -> None:
    """查看扫描任务状态。"""
    from arguscaner.scheduler.logger import ScanLogger

    ws = Path(workspace) if workspace else Path(__file__).parent.parent.parent / "workspace"
    workdir = ws / task_id

    if not workdir.exists():
        console.print(f"[bold red]任务未找到：[/] {task_id}")
        raise typer.Exit(1)

    logger = ScanLogger(workdir, task_id)
    logs = logger.get_logs()

    if not logs:
        console.print(f"[yellow]未找到任务 {task_id} 的日志[/]")
        return

    console.print(f"[bold]任务：{task_id}[/]\n")

    table = Table(title="阶段进度")
    table.add_column("阶段", style="cyan")
    table.add_column("状态", style="green")
    table.add_column("耗时", justify="right")
    table.add_column("记录数", justify="right")
    table.add_column("原因", style="yellow")

    stage_data: dict[str, dict] = {}
    for entry in logs:
        event = entry.get("event", "")
        stage = entry.get("stage", "")

        if event == "stage_start" and stage:
            stage_data.setdefault(stage, {})["status"] = "running"
        elif event == "stage_end" and stage:
            stage_data.setdefault(stage, {})["status"] = entry.get("status", "unknown")
            stage_data[stage]["duration"] = f"{entry.get('duration', 0):.2f}s"
            stage_data[stage]["records"] = str(entry.get("record_count", 0))
        elif event == "stage_skip" and stage:
            stage_data.setdefault(stage, {})["status"] = "skipped"
            stage_data[stage]["reason"] = entry.get("reason", "")

    for stage, data in stage_data.items():
        table.add_row(
            stage,
            data.get("status", "unknown"),
            data.get("duration", ""),
            data.get("records", ""),
            data.get("reason", ""),
        )

    console.print(table)

    task_complete = [e for e in logs if e.get("event") == "task_complete"]
    if task_complete:
        last = task_complete[-1]
        console.print(f"\n[bold]总耗时：[/] {last.get('total_duration', 0):.2f}s")
        if last.get("failed_stages"):
            console.print(f"[bold red]失败：[/] {', '.join(last['failed_stages'])}")


# ---------------------------------------------------------------------------
# resume command
# ---------------------------------------------------------------------------

@app.command()
def resume(
    task_id: str = typer.Argument(..., help="要恢复的任务 ID。"),
    force: bool = typer.Option(False, "--force", "-f", help="强制恢复。"),
    workspace: Optional[str] = typer.Option(None, "--workspace", "-w", help="工作目录。"),
) -> None:
    """恢复中断的扫描（从 task.json 恢复目标）。"""
    from arguscaner.scheduler.scheduler_core import PipelineScheduler, load_settings

    ws = Path(workspace) if workspace else Path(__file__).parent.parent.parent / "workspace"
    workdir = ws / task_id

    if not workdir.exists():
        console.print(f"[bold red]任务未找到：[/] {task_id}")
        raise typer.Exit(1)

    settings = load_settings(SETTINGS_YAML)

    console.print(f"[bold]正在恢复任务：[/] {task_id}")

    scheduler = PipelineScheduler(PIPELINE_YAML, settings)

    if force and workdir / ".done.all":
        (workdir / ".done.all").unlink()

    try:
        result = scheduler.resume(task_id, workdir)
    except ValueError as e:
        console.print(f"[bold red]{e}[/]")
        raise typer.Exit(1)

    console.print(f"[bold green]恢复完成。[/]")
    _print_stage_summary(result)


# ---------------------------------------------------------------------------
# test-plugin command
# ---------------------------------------------------------------------------

@app.command(name="test-plugin")
def test_plugin(
    target: str = typer.Option("example.com", "--target", "-t", help="测试目标。"),
    plugin: Optional[str] = typer.Option(None, "--plugin", "-p", help="要测试的插件名称。"),
    limit: int = typer.Option(5, "--limit", "-l", help="最多显示记录数。"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="显示完整输出。"),
    test_proxy_pool: bool = typer.Option(False, "--test-proxy-pool", help="测试代理池连通性。"),
) -> None:
    """单独测试一个插件（遵循目标类型条件）。"""
    from arguscaner.core.plugins.base_plugin import get_plugin
    from arguscaner.scheduler.scheduler_core import load_settings
    from arguscaner.utils.target_classifier import TargetClassifier

    settings = load_settings(SETTINGS_YAML)

    if test_proxy_pool:
        console.print("[bold]正在测试代理池连通性...[/]")
        proxy_manager_cfg = settings.get("waf_aware", {}).get("recovery", {}).get("proxy_pool", {})
        sources = proxy_manager_cfg.get("sources", [])
        if not sources:
            console.print("[yellow]未配置代理源。[/]")
        else:
            for src in sources:
                console.print(f"  代理：{src}")
        return

    if not plugin:
        console.print("[bold red]请使用 -p 指定插件[/]")
        raise typer.Exit(1)

    try:
        plg = get_plugin(plugin, settings)
    except ValueError as e:
        console.print(f"[bold red]{e}[/]")
        raise typer.Exit(1)

    # Show target type and condition check
    try:
        target_type = TargetClassifier.classify(target).value
    except ValueError as e:
        console.print(f"[bold red]无效目标：[/] {e}")
        raise typer.Exit(1)

    context = {"target_type": target_type, "target": target}
    meets, reason = plg.check_conditions(context)
    console.print(f"[bold]正在测试插件：[/] {plugin}")
    console.print(f"[bold]目标：[/] {target} ({target_type})")
    console.print(f"[bold]支持类型：[/] {[t.value for t in plg.supported_target_types] or 'all'}")
    console.print(f"[bold]条件满足：[/] {'[green]是[/]' if meets else '[red]否[/]'} {'' if meets else f'({reason})'}\n")

    if not meets:
        console.print("[yellow]插件条件不满足，跳过执行。[/]")
        return

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        workdir = Path(tmpdir)
        output_file = plg.execute(target, workdir)
        records = plg.parse_output(output_file)

        console.print(f"[green]输出文件：[/] {output_file}")
        console.print(f"[green]记录数：[/] {len(records)}\n")

        table = Table(title=f"{plugin} 输出（前 {limit} 条记录）")
        if records:
            for key in records[0].keys():
                table.add_column(key, style="cyan")

            for rec in records[:limit]:
                table.add_row(*[str(v) for v in rec.values()])

        console.print(table)

        if verbose and len(records) > limit:
            console.print(f"\n[yellow]... 还有 {len(records) - limit} 条记录[/]")


# ---------------------------------------------------------------------------
# web command
# ---------------------------------------------------------------------------

@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="绑定地址。"),
    port: int = typer.Option(5000, "--port", "-p", help="绑定端口。"),
    debug: bool = typer.Option(False, "--debug", "-d", help="开启调试模式。"),
) -> None:
    """启动 Web 管理界面。"""
    from arguscaner.web.app import create_app

    console.print(f"[bold green]ArguScanner Web 界面已启动：http://{host}:{port}[/]")
    flask_app = create_app()
    flask_app.run(host=host, port=port, debug=debug)


# ---------------------------------------------------------------------------
# pipeline command
# ---------------------------------------------------------------------------

@app.command(name="pipeline")
def pipeline_cmd(
    action: str = typer.Argument(..., help="操作：show | list-plugins | list | save。"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="流程名称。"),
) -> None:
    """管理扫描流程（查看流程定义、条件、插件）。"""
    from arguscaner.scheduler.scheduler_core import PipelineScheduler, load_settings

    if action == "list":
        _list_pipelines()
        return

    settings = load_settings(SETTINGS_YAML)

    if action == "show":
        pipeline_file = _resolve_pipeline(name)
        scheduler = PipelineScheduler(pipeline_file, settings)
        stages = scheduler.get_pipeline_definition()
        table = Table(title=f"流程：{pipeline_file.name}")
        table.add_column("阶段", style="cyan")
        table.add_column("插件", style="magenta")
        table.add_column("依赖")
        table.add_column("条件", style="yellow")
        table.add_column("约束", style="green")
        for s in stages:
            when = s["when"]
            conds = _format_conditions(s)
            table.add_row(
                s["name"],
                s["plugin"],
                ", ".join(s["depends_on"]) or "-",
                str(when) if when else "-",
                conds,
            )
        console.print(table)
        return

    if action == "list-plugins":
        _show_plugins(settings)
        return

    if action == "save":
        if not name:
            console.print("[bold red]请使用 --name 指定流程名称[/]")
            raise typer.Exit(1)
        _save_pipeline_template(name)
        return

    console.print(f"[bold red]未知操作：{action}[/] (use show, list-plugins, list, save)")
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# plugins command
# ---------------------------------------------------------------------------

@app.command()
def plugins(
    action: str = typer.Argument("list", help="操作：list | show | enable | disable | add | remove。"),
    plugin_name: Optional[str] = typer.Argument(None, help="插件名称（用于 show/enable/disable/remove）。"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="插件名称（用于 add）。"),
    command: Optional[str] = typer.Option(None, "--command", "-c", help="命令模板（用于 add）。"),
    types: Optional[str] = typer.Option(None, "--types", "-t", help="支持的目标类型，逗号分隔（用于 add）。"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="插件描述（用于 add）。"),
    output_schema: Optional[str] = typer.Option(None, "--output-schema", "-s", help="输出格式，JSON 字符串（用于 add）。"),
) -> None:
    """管理插件（列表、查看、启用/禁用、添加/删除自定义插件）。"""
    from arguscaner.core.plugins.base_plugin import PluginRegistry
    from arguscaner.scheduler.scheduler_core import load_settings

    settings = load_settings(SETTINGS_YAML)
    registry = PluginRegistry(settings)

    if action == "list":
        _show_plugins(settings)
        return

    if action == "show":
        if not plugin_name:
            console.print("[bold red]请指定插件名称[/]")
            raise typer.Exit(1)
        try:
            plg = registry.get(plugin_name)
            _show_plugin_detail(plg)
        except ValueError as e:
            console.print(f"[bold red]{e}[/]")
            raise typer.Exit(1)
        return

    if action in ("enable", "disable"):
        if not plugin_name:
            console.print("[bold red]请指定插件名称[/]")
            raise typer.Exit(1)
        _set_plugin_enabled(plugin_name, action == "enable")
        return

    if action == "add":
        _add_plugin(registry, name, command, types, description, output_schema)
        return

    if action == "remove":
        if not plugin_name:
            console.print("[bold red]请指定要删除的插件名称[/]")
            raise typer.Exit(1)
        _remove_plugin(registry, plugin_name)
        return

    console.print(f"[bold red]未知操作：{action}[/]")
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# config command
# ---------------------------------------------------------------------------

@app.command()
def config(
    action: str = typer.Argument("show", help="操作：show | get | set。"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="配置键（点号分隔）。"),
    value: Optional[str] = typer.Option(None, "--value", "-v", help="要设置的值。"),
) -> None:
    """查看或修改设置（修改后即时生效）。"""
    if action == "show":
        _show_config()
        return

    if action == "get":
        if not key:
            console.print("[bold red]请使用 --key 指定配置键[/]")
            raise typer.Exit(1)
        settings = _load_settings()
        val = _get_nested(settings, key.split("."))
        console.print(f"{key} = {json.dumps(val, ensure_ascii=False) if val is not None else 'None'}")
        return

    if action == "set":
        if not key or value is None:
            console.print("[bold red]请同时指定 --key 和 --value[/]")
            raise typer.Exit(1)
        _set_config_value(key, value)
        return

    console.print(f"[bold red]未知操作：{action}[/]")
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# proxy command
# ---------------------------------------------------------------------------

@app.command()
def proxy(
    action: str = typer.Argument("list", help="操作：list | add | remove | test。"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="代理 URL。"),
) -> None:
    """管理代理池。"""
    if action == "list":
        _show_proxies()
        return

    if action == "add":
        if not url:
            console.print("[bold red]请使用 --url 指定代理 URL[/]")
            raise typer.Exit(1)
        _add_proxy(url)
        return

    if action == "remove":
        if not url:
            console.print("[bold red]请使用 --url 指定代理 URL[/]")
            raise typer.Exit(1)
        _remove_proxy(url)
        return

    if action == "test":
        _test_proxies()
        return

    console.print(f"[bold red]未知操作：{action}[/]")
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_recursive_options(
    settings: dict,
    recursive: bool | None,
    rescan_ips: bool,
) -> None:
    """Apply CLI recursion overrides to a settings dict."""
    cfg = settings.setdefault("recursive", {})
    if recursive is not None:
        cfg["enabled"] = bool(recursive)
    if rescan_ips:
        cfg["rescan_ips"] = True
        cfg["skip_scanned_ips"] = False


def _resolve_pipeline(name: str | None) -> Path:
    """Resolve a pipeline name/file to a YAML path."""
    if not name:
        return PIPELINE_YAML
    candidate = Path(name)
    if candidate.exists():
        return candidate
    if not candidate.suffix:
        candidate = candidate.with_suffix(".yaml")
    named = CUSTOM_PIPELINES_DIR / candidate.name
    if Path(candidate).exists():
        return Path(candidate)
    if named.exists():
        return named
    console.print(f"[bold red]流程未找到：{name}[/]")
    raise typer.Exit(1)


def _list_pipelines() -> None:
    """List available pipelines."""
    pipelines = [PIPELINE_YAML]
    if CUSTOM_PIPELINES_DIR.exists():
        pipelines += sorted(CUSTOM_PIPELINES_DIR.glob("*.yaml"))

    table = Table(title="可用流程")
    table.add_column("名称")
    table.add_column("路径")
    for p in pipelines:
        table.add_row(p.stem, str(p))
    console.print(table)


def _format_conditions(stage: dict) -> str:
    """Format stage conditions and plugin type support as a compact string."""
    plugin = stage.get("plugin_info", {})
    parts = []
    supported = plugin.get("supported_target_types", ["all"])
    parts.append(f"types={', '.join(supported)}")
    for c in plugin.get("conditions", []):
        if c.get("description"):
            parts.append(c["description"])
    return " | ".join(parts) or "-"


def _show_plugins(settings: dict) -> None:
    """Show plugin list table."""
    from arguscaner.core.plugins.base_plugin import PluginRegistry
    registry = PluginRegistry(settings)

    table = Table(title="已注册插件")
    table.add_column("名称", style="cyan")
    table.add_column("描述")
    table.add_column("支持类型", style="magenta")
    table.add_column("输入依赖")
    table.add_column("来源")
    table.add_column("启用", style="green")

    for info in registry.list():
        status = "[green]是[/]" if info["enabled"] else "[red]否[/]"
        source = info.get("source", "builtin")
        source_style = "yellow" if source == "custom" else "dim"
        table.add_row(
            info["name"],
            info["description"],
            ", ".join(info["supported_target_types"]) if info["supported_target_types"] else "all",
            ", ".join(info["input_requirements"]) or "-",
            f"[{source_style}]{source}[/{source_style}]",
            status,
        )
    console.print(table)


def _show_plugin_detail(plg) -> None:
    """Show detailed info about a single plugin."""
    info = plg.info
    source = info.get("source", "builtin")
    console.print(f"[bold]插件：{info['name']}[/] v{info['version']}  [dim]({source})[/]")
    console.print(f"  描述：{info['description']}")
    console.print(f"  启用：{'[green]是[/]' if info['enabled'] else '[red]否[/]'}")
    console.print(f"  支持类型：{', '.join(info['supported_target_types'])}")
    console.print(f"  输入依赖：{', '.join(info['input_requirements']) or '无'}")
    console.print(f"  命令模板：{info['command_template']}")
    console.print(f"  输出格式：{json.dumps(info['output_schema'], indent=4)}")
    console.print("  约束条件：")
    if info["conditions"]:
        for c in info["conditions"]:
            console.print(f"    - {c['field']} {c['operator']} {c['value']} ({c['description']})")
    else:
        console.print("    - 无")


def _set_plugin_enabled(name: str, enabled: bool) -> None:
    """Enable or disable a plugin persistently in settings."""
    settings = _load_settings()
    settings.setdefault("plugins", {}).setdefault(name, {})["enabled"] = enabled
    _save_settings(settings)
    console.print(f"[green]插件 '{name}' 已{'启用' if enabled else '禁用'}。[/]")


def _add_plugin(registry, name, command, types, description, output_schema) -> None:
    """Add a custom YAML plugin via CLI."""
    from arguscaner.core.plugins.base_plugin import PluginRegistry

    if not name:
        console.print("[bold red]请使用 --name 指定插件名称[/]")
        raise typer.Exit(1)
    if not command:
        console.print("[bold red]请使用 --command 指定命令模板[/]")
        raise typer.Exit(1)

    supported_types = []
    if types:
        supported_types = [t.strip() for t in types.split(",") if t.strip()]

    schema = {}
    if output_schema:
        try:
            schema = json.loads(output_schema)
        except json.JSONDecodeError as e:
            console.print(f"[bold red]输出格式 JSON 无效：[/] {e}")
            raise typer.Exit(1)

    config = {
        "name": name,
        "description": description or f"自定义插件：{name}",
        "version": "1.0.0",
        "command_template": command,
        "output_filename": f"{name}_output.jsonl",
        "output_schema": schema,
        "supported_target_types": supported_types,
        "input_requirements": [],
        "conditions": [],
        "enabled": True,
        "source": "custom",
    }

    try:
        plugin = registry.add_custom(config)
    except ValueError as e:
        console.print(f"[bold red]{e}[/]")
        raise typer.Exit(1)

    console.print(f"[green]自定义插件 '{name}' 添加成功。[/]")
    console.print(f"  YAML 文件：{PluginRegistry.CUSTOM_PLUGINS_DIR / f'{name}.yaml'}")
    _show_plugin_detail(plugin)


def _remove_plugin(registry, name: str) -> None:
    """Remove a custom plugin."""
    if not registry.is_custom(name):
        console.print(f"[bold red]插件 '{name}' 不是自定义插件。[/]只有自定义插件可以删除。")
        raise typer.Exit(1)
    try:
        registry.remove_custom(name)
        console.print(f"[green]自定义插件 '{name}' 已删除。[/]")
    except ValueError as e:
        console.print(f"[bold red]{e}[/]")
        raise typer.Exit(1)


def _save_pipeline_template(name: str) -> None:
    """Create a copy of the default pipeline as a custom template."""
    CUSTOM_PIPELINES_DIR.mkdir(parents=True, exist_ok=True)
    dest = CUSTOM_PIPELINES_DIR / f"{name}.yaml"
    if dest.exists():
        console.print(f"[yellow]流程 '{name}' 已存在，将覆盖。[/]")
    with open(PIPELINE_YAML, "r", encoding="utf-8") as src:
        dest.write_text(src.read(), encoding="utf-8")
    console.print(f"[green]流程已保存到 {dest}[/]")
    console.print("  编辑 YAML 文件来自定义阶段、依赖关系和 when 条件。")


def _show_config() -> None:
    """Display current settings."""
    settings = _load_settings()
    table = Table(title="当前设置")
    table.add_column("键", style="cyan")
    table.add_column("值")
    for key, value in _flatten_dict(settings).items():
        table.add_row(key, json.dumps(value, ensure_ascii=False))
    console.print(table)


def _get_nested(d: dict, keys: list[str]):
    """Get nested dict value by dotted key path."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _set_config_value(key: str, value: str) -> None:
    """Set a config value by dotted key (immediate effect)."""
    settings = _load_settings()
    keys = key.split(".")
    cur = settings
    for k in keys[:-1]:
        if k not in cur or not isinstance(cur[k], dict):
            cur[k] = {}
        cur = cur[k]
    cur[keys[-1]] = _parse_scalar(value)
    _save_settings(settings)
    console.print(f"[green]已设置 {key} = {value}（已保存到 settings.yaml，即时生效。）[/]")


def _parse_scalar(value: str):
    """Parse a string into int/float/bool/list or keep as string."""
    lower = value.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower == "null":
        return None
    if value.startswith("[") and value.endswith("]"):
        import ast
        try:
            return ast.literal_eval(value)
        except Exception:
            return [v.strip() for v in value[1:-1].split(",") if v.strip()]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _flatten_dict(d: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict for display."""
    out = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_dict(v, key))
        else:
            out[key] = v
    return out


def _show_proxies() -> None:
    """Display the proxy pool."""
    settings = _load_settings()
    sources = settings.get("waf_aware", {}).get("recovery", {}).get("proxy_pool", {}).get("sources", [])
    if not sources:
        console.print("[yellow]未配置代理。[/]")
        return
    table = Table(title="代理池")
    table.add_column("URL", style="cyan")
    table.add_column("状态")
    for s in sources:
        table.add_row(s, "[green]已配置[/]")
    console.print(table)


def _add_proxy(url: str) -> None:
    """Add a proxy to the pool."""
    settings = _load_settings()
    pool = settings.setdefault("waf_aware", {}).setdefault("recovery", {}).setdefault("proxy_pool", {})
    sources = pool.setdefault("sources", [])
    if url in sources:
        console.print(f"[yellow]代理已存在：{url}[/]")
        return
    sources.append(url)
    _save_settings(settings)
    console.print(f"[green]已添加代理：{url}[/]")


def _remove_proxy(url: str) -> None:
    """Remove a proxy from the pool."""
    settings = _load_settings()
    pool = settings.get("waf_aware", {}).get("recovery", {}).get("proxy_pool", {})
    sources = pool.get("sources", [])
    if url not in sources:
        console.print(f"[yellow]代理未找到：{url}[/]")
        return
    sources.remove(url)
    _save_settings(settings)
    console.print(f"[green]已移除代理：{url}[/]")


def _test_proxies() -> None:
    """Test proxy pool connectivity (basic)."""
    from arguscaner.utils.proxy_manager import ProxyManager

    settings = _load_settings()
    sources = settings.get("waf_aware", {}).get("recovery", {}).get("proxy_pool", {}).get("sources", [])
    pool = ProxyManager(sources)
    status = pool.get_status()
    print(f"代理总数：{status['total']}")
    print(f"可用数量：{status['available']}")
    if status["total"] == 0:
        print(f"未配置代理。使用：auto-recon proxy add <url>")


# ---------------------------------------------------------------------------
# Display helper
# ---------------------------------------------------------------------------

def _print_stage_summary(result: object) -> None:
    """Print a summary table of stage results."""
    from arguscaner.scheduler.scheduler_core import ScanResult

    if not isinstance(result, ScanResult):
        return

    table = Table(title="阶段摘要")
    table.add_column("阶段", style="cyan")
    table.add_column("状态", style="green")
    table.add_column("耗时", justify="right")
    table.add_column("记录数", justify="right")
    table.add_column("原因", style="yellow")

    for stage_name, sr in result.stages.items():
        if sr.state.value in ("done", "failed"):
            style = "green" if sr.state.value == "done" else "red"
        else:
            style = "yellow"
        table.add_row(
            stage_name,
            f"[{style}]{sr.state.value}[/{style}]",
            f"{sr.duration:.2f}s",
            str(sr.record_count),
            sr.skip_reason or "",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="开启调试输出。"),
) -> None:
    """ArguScanner - 红蓝队一键信息收集工具。"""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
