# 内置工具目录

ArguScanner 会优先使用本目录中的工具，找不到时再回退到环境变量、`PATH`
或裸命令。设置页的“插件配置”可以为每个插件覆盖路径。

```
tools/
  httpx/httpx.exe        # httpx 1.11.0（MIT）
  urlfinder/URLFinder.exe # URLFinder（MIT）
```

## 路径解析顺序

1. 流水线阶段 `params` 中的路径
2. `settings.yaml` 的 `plugins.<插件>.<工具>_path`
3. 环境变量（`HTTPX_PATH` / `NMAP_PATH` / `URLFINDER_PATH` / `ONEFORALL_PATH` / `JSFINDER_PATH`）
4. 本目录中的内置工具
5. 系统 `PATH`
6. 裸命令名

## 未内置的工具

- **Nmap**：带脚本与数据文件，请通过 `plugins.nmap_scan.nmap_path`
  指向 `nmap.exe` 或 Nmap 安装目录。
- **OneForAll / JSFinder**：Python 项目，请通过
  `plugins.oneforall.oneforall_path` / `plugins.jsfinder.jsfinder_path`
  指向入口脚本。

## 许可证

工具本体仍遵循各自许可证：

- `httpx`：MIT
- `URLFinder`：MIT

ArguScanner 项目主体采用 **AGPL-3.0-or-later**，详见项目根目录的 `LICENSE`。