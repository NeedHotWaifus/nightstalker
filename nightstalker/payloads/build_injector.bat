@echo off
REM NightStalker Advanced Injector Build Script
REM Builds the injector with different configurations

echo [*] NightStalker Advanced Injector Builder
echo ==========================================

REM Check if Visual Studio is available
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Visual Studio compiler not found
    echo [!] Please run from Visual Studio Developer Command Prompt
    echo [!] Or set up Visual Studio Build Tools
    pause
    exit /b 1
)

REM Build configurations
set CONFIGURATIONS=x64 x86
set OPTIMIZATIONS=Release Debug

for %%c in (%CONFIGURATIONS%) do (
    for %%o in (%OPTIMIZATIONS%) do (
        echo.
        echo [*] Building %%c %%o version...
        
        if "%%c"=="x64" (
            set PLATFORM=x64
            set ARCH_FLAGS=/D_WIN64
        ) else (
            set PLATFORM=x86
            set ARCH_FLAGS=
        )
        
        if "%%o"=="Release" (
            set OPT_FLAGS=/O2 /MT
        ) else (
            set OPT_FLAGS=/Od /MTd /Zi
        )
        
        set OUTPUT_NAME=injector_%%c_%%o.exe
        
        cl.exe %OPT_FLAGS% %ARCH_FLAGS% /DNDEBUG advanced_injector.cpp /link /OUT:%OUTPUT_NAME% /SUBSYSTEM:CONSOLE
        
        if %errorlevel% equ 0 (
            echo [+] Successfully built: %OUTPUT_NAME%
        ) else (
            echo [!] Failed to build: %OUTPUT_NAME%
        )
    )
)

echo.
echo [*] Build complete!
echo.
echo [*] Available executables:
dir injector_*.exe

echo.
echo [*] Usage examples:
echo     injector_x64_Release.exe explorer.exe reflective
echo     injector_x64_Release.exe svchost.exe hollowing
echo     injector_x86_Release.exe winlogon.exe reflective
echo.
echo [*] Remember to replace ENCRYPTED_SHELLCODE with your actual shellcode!
echo [*] Use shellcode_generator.py to create encrypted shellcode.

pause 