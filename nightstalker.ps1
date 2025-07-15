#!/usr/bin/env pwsh

# NightStalker Framework Launcher for PowerShell
# This script launches the NightStalker framework

# Set NightStalker home directory
if (-not $env:NIGHTSTALKER_HOME) {
    $env:NIGHTSTALKER_HOME = "$env:USERPROFILE\.nightstalker"
}

# Set NightStalker directory to current installation
if (-not $env:NIGHTSTALKER_DIR) {
    $env:NIGHTSTALKER_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Activate virtual environment if it exists
$venvActivate = Join-Path $env:NIGHTSTALKER_DIR "venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    & $venvActivate
}

# Add current directory to Python path
$env:PYTHONPATH = "$env:NIGHTSTALKER_DIR;$env:PYTHONPATH"

# Launch NightStalker
Set-Location $env:NIGHTSTALKER_DIR
python -m nightstalker.cli $args 