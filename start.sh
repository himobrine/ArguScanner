#!/usr/bin/env bash
# Start the ArguScanner Web UI using the project virtual environment.
set -euo pipefail
cd "$(dirname "$0")" || exit 1
export PYTHONUTF8=1

if [ ! -x ".venv/bin/python" ]; then
  echo "[!] 未找到 .venv，请先运行：bash setup.sh"
  exit 1
fi

if [ "$#" -eq 0 ]; then
  exec .venv/bin/python -m arguscaner.entrypoint web --host 127.0.0.1 --port 5000
else
  exec .venv/bin/python -m arguscaner.entrypoint web "$@"
fi