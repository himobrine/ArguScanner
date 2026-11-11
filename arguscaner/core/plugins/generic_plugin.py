"""GenericPlugin - YAML 声明式插件，从配置文件动态加载。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from arguscaner.core.plugins.base_plugin import BasePlugin, PluginCondition
from arguscaner.utils.target_classifier import TargetType


class GenericPlugin(BasePlugin):
    """从 YAML 配置动态构建的插件。

    用户通过 CLI/Web 添加自定义插件时，系统生成 YAML 文件到
    configs/custom_plugins/ 目录，PluginRegistry 加载后用此类实例化。
    """

    source: str = "custom"

    def __init__(self, config: dict[str, Any], settings: dict[str, Any] | None = None):
        super().__init__(settings)

        self.name = config.get("name", "unnamed")
        self.description = config.get("description", "")
        self.version = config.get("version", "1.0.0")
        self.command_template = config.get("command_template", "")
        self.output_filename = config.get("output_filename", f"{self.name}_output.jsonl")
        self.output_schema = config.get("output_schema", {})
        self.input_requirements = config.get("input_requirements", [])
        self.source = config.get("source", "custom")

        # 解析 supported_target_types
        raw_types = config.get("supported_target_types", [])
        self.supported_target_types: list[TargetType] = []
        type_map = {t.value: t for t in TargetType}
        for t in raw_types:
            if t in type_map:
                self.supported_target_types.append(type_map[t])

        # 解析 conditions
        raw_conds = config.get("conditions", [])
        self.conditions: list[PluginCondition] = []
        for c in raw_conds:
            self.conditions.append(PluginCondition(
                field=c.get("field", ""),
                operator=c.get("operator", "eq"),
                value=c.get("value"),
                description=c.get("description", ""),
            ))

        # enabled 从 settings.plugins.<name>.enabled 读取（同内置插件）
        # 如果 settings 中没有记录，用 YAML 配置里的默认值
        if self.name not in (settings or {}).get("plugins", {}):
            self.enabled = config.get("enabled", True)
        # _load_enabled() 已在 super().__init__ 中调用，会覆盖 enabled

    @classmethod
    def from_yaml_file(cls, yaml_path: Path, settings: dict[str, Any] | None = None) -> "GenericPlugin":
        """从 YAML 文件加载插件配置并实例化。"""
        with open(yaml_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        config.setdefault("source", "custom")
        return cls(config, settings)

    def to_yaml_file(self, yaml_path: Path) -> None:
        """将当前插件配置保存为 YAML 文件。"""
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        config = self._to_config()
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

    def _to_config(self) -> dict[str, Any]:
        """导出为可序列化的配置字典。"""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "command_template": self.command_template,
            "output_filename": self.output_filename,
            "output_schema": self.output_schema,
            "supported_target_types": [t.value for t in self.supported_target_types],
            "input_requirements": self.input_requirements,
            "conditions": [
                {
                    "field": c.field,
                    "operator": c.operator,
                    "value": c.value,
                    "description": c.description,
                }
                for c in self.conditions
            ],
            "enabled": self.enabled,
            "source": self.source,
        }

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        """Execute plugin: run the command template."""
        output_file = self._stage_file(workdir, self.output_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        cmd = self.render_command(target, output_file, proxy)
        self._run_command(cmd, workdir, timeout=self.settings.get("defaults", {}).get("timeout", 300))

        return output_file

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse plugin JSONL output."""
        return self._read_jsonl(output_file)
