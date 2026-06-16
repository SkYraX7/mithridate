#Requires -Version 5.1
# Mithridate setup -- Windows (PowerShell)
# Usage: .\scripts\setup.ps1  (from project root)
#        OR  cd scripts; .\setup.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Work from the project root regardless of where the script was invoked from
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# ---------------------------------------------------------------------------

function Test-PythonVersion {
    param([string]$Exe)
    try {
        $verStr = "$(& $Exe --version 2>&1)"
        if ($verStr -match '(\d+)\.(\d+)') {
            return ([int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 11)
        }
    } catch {}
    return $false
}

function Find-Python {
    # 1. Python Launcher (py.exe) -- most reliable on Windows; installed even when
    #    Python itself is not on PATH. Tries 3.12 then 3.11.
    $pyCmd = Get-Command "py" -ErrorAction SilentlyContinue
    if ($pyCmd -and $pyCmd.Source -notlike "*WindowsApps*") {
        foreach ($ver in @("-3.12", "-3.11")) {
            try {
                $verStr = "$(& py $ver --version 2>&1)"
                if ($verStr -match 'Python \d') {
                    # Resolve the real interpreter path so venv creation works normally
                    $exePath = "$(& py $ver -c 'import sys; print(sys.executable)' 2>&1)".Trim()
                    if ($exePath -and (Test-Path $exePath)) { return $exePath }
                }
            } catch { continue }
        }
    }

    # 2. PATH-based names
    foreach ($candidate in @("python3.12", "python3.11", "python3", "python")) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        # Skip the Windows Store stub -- it prints an error message and exits non-zero
        if ($cmd.Source -like "*WindowsApps*") { continue }
        if (Test-PythonVersion $cmd.Source) { return $cmd.Source }
    }

    # 3. Known Windows install locations (covers installs not added to PATH)
    $knownPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:ProgramFiles\Python311\python.exe"
    )
    foreach ($path in $knownPaths) {
        if ((Test-Path $path) -and (Test-PythonVersion $path)) { return $path }
    }

    return $null
}

function Update-EnvPath {
    $machine = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
    $user    = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    $env:PATH = "$machine;$user"
}

# ---------------------------------------------------------------------------

Write-Host "=== Mithridate setup ===" -ForegroundColor Cyan
Write-Host ""

$python = Find-Python

if (-not $python) {
    Write-Host "Python 3.11+ not found." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Install options:"
    Write-Host "  1. winget  :  winget install Python.Python.3.11"
    Write-Host "  2. Web     :  https://www.python.org/downloads/"
    Write-Host ""

    $choice = Read-Host "Try installing Python 3.11 via winget now? [y/N]"
    if ($choice -ieq 'y') {
        winget install Python.Python.3.11 --accept-package-agreements --accept-source-agreements
        Update-EnvPath
        $python = Find-Python
    }

    if (-not $python) {
        Write-Host ""
        Write-Host "Install Python 3.11+ and re-run this script." -ForegroundColor Red
        exit 1
    }
}

$pythonVer = "$(& $python --version 2>&1)"
Write-Host "Python: $python ($pythonVer)"
Write-Host ""

# Virtual environment
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..."
    & $python -m venv .venv
}

$venvPython = ".venv\Scripts\python.exe"
$pipExe     = ".venv\Scripts\pip.exe"

Write-Host "Installing dependencies..."
# pip cannot upgrade itself via the pip executable on Windows -- use python -m pip
& $venvPython -m pip install --upgrade pip setuptools wheel -q
& $pipExe install -e ".[dev]" -q

# .env
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
    } else {
        Set-Content ".env" "ANTHROPIC_API_KEY=" -Encoding utf8
    }
    Write-Host ""
    Write-Host "  Created .env -- open it and set your ANTHROPIC_API_KEY." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done!  Activate the environment with:" -ForegroundColor Green
Write-Host "  .\.venv\Scripts\activate"
Write-Host ""
Write-Host "Then verify with:"
Write-Host "  mithridate eval --gate-only"
