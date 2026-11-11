# ArguScanner one-click setup (PowerShell)
# Usage: powershell -ExecutionPolicy Bypass -File .\setup.ps1
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONUTF8 = "1"

function Test-Candidate {
    param([string]$Command, [string[]]$Prefix)
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        return $false
    }
    $testArgs = @($Prefix) + @(
        "-c",
        "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $Command @testArgs 1>$null 2>$null
    $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $previous
    return $ok
}

$candidates = @(
    @{ Command = "py"; Prefix = @("-3.12") },
    @{ Command = "py"; Prefix = @("-3.11") },
    @{ Command = "py"; Prefix = @("-3.10") },
    @{ Command = "py"; Prefix = @("-3") },
    @{ Command = "python"; Prefix = @() }
)

$selected = $null
foreach ($candidate in $candidates) {
    if (Test-Candidate -Command $candidate.Command -Prefix $candidate.Prefix) {
        $selected = $candidate
        break
    }
}

if ($null -eq $selected) {
    Write-Host "[!] 未找到 Python 3.10 或更高版本。" -ForegroundColor Yellow
    Write-Host "    推荐安装 Python 3.12：https://www.python.org/downloads/windows/"
    Write-Host "    或使用：winget install Python.Python.3.12"
    Write-Host "    安装时请勾选 'Add Python to PATH'。"
    if ($args.Count -eq 0) { Read-Host "按 Enter 退出" | Out-Null }
    exit 1
}

$runArgs = @($selected.Prefix) + @("scripts/setup.py") + $args
& $selected.Command @runArgs
$exitCode = $LASTEXITCODE

if ($args.Count -eq 0) { Read-Host "按 Enter 退出" | Out-Null }
exit $exitCode