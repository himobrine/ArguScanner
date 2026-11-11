#!/usr/bin/env bash
# ArguScanner one-click setup (Linux / macOS)
set -euo pipefail
cd "$(dirname "$0")" || exit 1
export PYTHONUTF8=1

pick_python() {
  local candidate
  for candidate in python3.12 python3.11 python3.10 python3 python; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

if ! PYTHON="$(pick_python)"; then
  echo "[!] 未找到 Python 3.10 或更高版本。"
  echo
  echo "    Ubuntu/Debian: sudo apt install python3 python3-venv"
  echo "    RHEL/CentOS:   sudo dnf install python3"
  echo "    Arch:          sudo pacman -S python"
  echo "    macOS:         brew install python@3.12"
  exit 1
fi

exec "$PYTHON" scripts/setup.py "$@"