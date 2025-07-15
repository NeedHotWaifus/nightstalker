@echo off
REM NightStalker Framework Launcher for Windows
REM This script launches the NightStalker framework

REM Set NightStalker home directory
if "%NIGHTSTALKER_HOME%"=="" (
    set NIGHTSTALKER_HOME=%USERPROFILE%\.nightstalker
)

REM Set NightStalker directory to current installation
if "%NIGHTSTALKER_DIR%"=="" (
    set NIGHTSTALKER_DIR=%~dp0
)

REM Activate virtual environment if it exists
if exist "%NIGHTSTALKER_DIR%venv\Scripts\activate.bat" (
    call "%NIGHTSTALKER_DIR%venv\Scripts\activate.bat"
)

REM Add current directory to Python path
set PYTHONPATH=%NIGHTSTALKER_DIR%;%PYTHONPATH%

REM Launch NightStalker
cd /d "%NIGHTSTALKER_DIR%"
python -m nightstalker.cli %* 