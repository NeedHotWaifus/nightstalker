@echo off
REM NightStalker CLI Launcher for Windows
REM Advanced Offensive Security Framework
REM Version: 1.1

REM Auto-detect NightStalker directory
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

REM Check if we're in the NightStalker project root (has nightstalker/ subdirectory)
if exist "%SCRIPT_DIR%\nightstalker" (
    set "NIGHTSTALKER_DIR=%SCRIPT_DIR%"
) else if exist "%SCRIPT_DIR%\..\nightstalker" (
    REM Script might be in a subdirectory
    for %%i in ("%SCRIPT_DIR%\..") do set "NIGHTSTALKER_DIR=%%~fi"
) else (
    REM Fallback to environment variable or default
    if defined NIGHTSTALKER_HOME (
        set "NIGHTSTALKER_DIR=%NIGHTSTALKER_HOME%"
    ) else (
        set "NIGHTSTALKER_DIR=%USERPROFILE%\path\to\nightstalker"
    )
)

REM Check if directory exists
if not exist "%NIGHTSTALKER_DIR%" (
    echo [-] NightStalker directory not found: %NIGHTSTALKER_DIR%
    echo.
    echo [*] Auto-detection failed. Please set the NIGHTSTALKER_HOME environment variable:
    echo [*]   set NIGHTSTALKER_HOME=C:\path\to\your\nightstalker
    echo [*]   or run this script from the NightStalker project root directory
    echo.
    echo [*] Current script location: %SCRIPT_DIR%
    pause
    exit /b 1
)

REM Verify it's actually a NightStalker project
if not exist "%NIGHTSTALKER_DIR%\nightstalker" (
    echo [-] Invalid NightStalker directory: %NIGHTSTALKER_DIR%
    echo [*] Directory does not contain nightstalker/ subdirectory
    pause
    exit /b 1
)

echo [+] NightStalker directory found: %NIGHTSTALKER_DIR%

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Python is not installed or not in PATH
    echo [*] Please install Python 3.6+ and try again
    pause
    exit /b 1
)

echo [+] Python found

REM Change to NightStalker directory and run CLI
cd /d "%NIGHTSTALKER_DIR%"

REM Check if nightstalker module exists
python -c "import nightstalker" >nul 2>&1
if errorlevel 1 (
    echo [-] NightStalker module not found
    echo [*] Please ensure NightStalker is properly installed:
    echo [*]   cd %NIGHTSTALKER_DIR%
    echo [*]   pip install -r requirements.txt
    pause
    exit /b 1
)

echo [+] NightStalker module found
echo [+] Starting NightStalker CLI...
echo.

REM Run the CLI with all arguments passed to this script
python -m nightstalker.cli %*

set "EXIT_CODE=%ERRORLEVEL%"

if %EXIT_CODE% equ 0 (
    echo [+] NightStalker CLI completed successfully
) else (
    echo [-] NightStalker CLI exited with code: %EXIT_CODE%
)

exit /b %EXIT_CODE% 