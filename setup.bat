@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
set "PYTHONUTF8=1"

set "PY_CMD="

where py >nul 2>nul
if not errorlevel 1 (
  py -3.12 -c "import sys" >nul 2>nul && set "PY_CMD=py -3.12"
  if not defined PY_CMD py -3.11 -c "import sys" >nul 2>nul && set "PY_CMD=py -3.11"
  if not defined PY_CMD py -3.10 -c "import sys" >nul 2>nul && set "PY_CMD=py -3.10"
  if not defined PY_CMD py -3 -c "import sys" >nul 2>nul && set "PY_CMD=py -3"
)

if not defined PY_CMD (
  python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul && set "PY_CMD=python"
)

if not defined PY_CMD (
  echo [!] 未找到 Python 3.10 或更高版本。
  echo.
  echo     推荐安装 Python 3.12：https://www.python.org/downloads/windows/
  echo     或使用：winget install Python.Python.3.12
  echo     安装时请勾选 "Add Python to PATH"。
  echo.
  set "RC=1"
  goto :end
)

%PY_CMD% "scripts\setup.py" %*
set "RC=%ERRORLEVEL%"

:end
if "%~1"=="" pause
exit /b %RC%