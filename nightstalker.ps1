#!/usr/bin/env pwsh

# NightStalker CLI Launcher Script for Windows
# Advanced Offensive Security Framework
# Version: 1.1

# Auto-detect NightStalker directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check if we're in the NightStalker project root (has nightstalker/ subdirectory)
if (Test-Path "$ScriptDir\nightstalker") {
    $NightStalkerDir = $ScriptDir
} elseif (Test-Path "$ScriptDir\..\nightstalker") {
    # Script might be in a subdirectory
    $NightStalkerDir = Split-Path -Parent $ScriptDir
} else {
    # Fallback to environment variable or default
    $NightStalkerDir = if ($env:NIGHTSTALKER_HOME) { $env:NIGHTSTALKER_HOME } else { "$env:USERPROFILE\path\to\nightstalker" }
}

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Blue
}

function Write-Banner {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                    🌙 NIGHTSTALKER LAUNCHER                  ║
║                    Advanced Offensive Security Framework      ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Magenta
}

# Function to check if directory exists
function Test-NightStalkerDirectory {
    if (-not (Test-Path $NightStalkerDir)) {
        Write-Error "NightStalker directory not found: $NightStalkerDir"
        Write-Host
        Write-Info "Auto-detection failed. Please set the NIGHTSTALKER_HOME environment variable:"
        Write-Info "  `$env:NIGHTSTALKER_HOME = 'C:\path\to\your\nightstalker'"
        Write-Info "  or run this script from the NightStalker project root directory"
        Write-Host
        Write-Info "Current script location: $ScriptDir"
        Write-Info "Looking for nightstalker/ subdirectory in:"
        Write-Info "  - $ScriptDir"
        Write-Info "  - $(Split-Path -Parent $ScriptDir)"
        return $false
    }
    
    # Verify it's actually a NightStalker project
    if (-not (Test-Path "$NightStalkerDir\nightstalker")) {
        Write-Error "Invalid NightStalker directory: $NightStalkerDir"
        Write-Info "Directory does not contain nightstalker/ subdirectory"
        return $false
    }
    
    Write-Status "NightStalker directory found: $NightStalkerDir"
    return $true
}

# Function to check Python installation
function Test-PythonInstallation {
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Python is not installed or not in PATH"
            Write-Info "Please install Python 3.6+ and try again"
            return $false
        }
        
        Write-Status "Python found: $pythonVersion"
        return $true
    } catch {
        Write-Error "Python is not installed or not in PATH"
        Write-Info "Please install Python 3.6+ and try again"
        return $false
    }
}

# Function to check NightStalker installation
function Test-NightStalkerInstallation {
    Set-Location $NightStalkerDir
    
    # Check if nightstalker module exists
    try {
        python -c "import nightstalker" 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "NightStalker module not found"
            Write-Info "Please ensure NightStalker is properly installed:"
            Write-Info "  cd $NightStalkerDir"
            Write-Info "  pip install -r requirements.txt"
            return $false
        }
        
        Write-Status "NightStalker module found"
        return $true
    } catch {
        Write-Error "NightStalker module not found"
        Write-Info "Please ensure NightStalker is properly installed"
        return $false
    }
}

# Function to run NightStalker CLI
function Start-NightStalkerCLI {
    Set-Location $NightStalkerDir
    
    Write-Status "Starting NightStalker CLI..."
    Write-Host
    
    # Run the CLI with all arguments passed to this script
    python -m nightstalker.cli $args
    
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-Status "NightStalker CLI completed successfully"
    } else {
        Write-Error "NightStalker CLI exited with code: $exitCode"
    }
    
    return $exitCode
}

# Function to show help
function Show-Help {
    Write-Banner
    Write-Host "Usage: .\nightstalker.ps1 [OPTIONS] [COMMAND]"
    Write-Host
    Write-Host "Available commands:"
    Write-Host "  stealth build     - Build stealth reverse shell payload"
    Write-Host "  stealth server    - Start C2 server"
    Write-Host "  stealth demo      - Run stealth payload demonstration"
    Write-Host "  payload build     - Build payloads"
    Write-Host "  pentest           - Run penetration testing"
    Write-Host "  redteam           - Red team operations"
    Write-Host "  webred            - Web red teaming"
    Write-Host "  c2                - Command & Control operations"
    Write-Host "  help              - Show detailed help"
    Write-Host
    Write-Host "Examples:"
    Write-Host "  .\nightstalker.ps1                    # Interactive menu"
    Write-Host "  .\nightstalker.ps1 stealth build      # Build stealth payload"
    Write-Host "  .\nightstalker.ps1 stealth server     # Start C2 server"
    Write-Host "  .\nightstalker.ps1 --help             # Show help"
    Write-Host
    Write-Host "For more information, visit the NightStalker documentation."
}

# Main execution
if ($args -contains "--help" -or $args -contains "-h") {
    Show-Help
    exit 0
}

# Check prerequisites
if (-not (Test-NightStalkerDirectory)) {
    exit 1
}

if (-not (Test-PythonInstallation)) {
    exit 1
}

if (-not (Test-NightStalkerInstallation)) {
    exit 1
}

# Run NightStalker CLI
$exitCode = Start-NightStalkerCLI
exit $exitCode 