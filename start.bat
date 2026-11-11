@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
set "PYTHONUTF8=1"

if not exist ".venv\Scripts\python.exe" (
  echo [!] 未找到 .venv，请先运行 setup.bat
  pause
  exit /b 1
)

if "%~1"=="" (
  ".venv\Scripts\python.exe" -m arguscaner.entrypoint web --host 127.0.0.1 --port 5000
) else (
  ".venv\Scripts\python.exe" -m arguscaner.entrypoint web %*
)
exit /b %ERRORLEVEL%