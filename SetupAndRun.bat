@echo off
setlocal enabledelayedexpansion

:: ============================================================
:: PureXS Setup & Auto-Update Launcher
:: Place this file anywhere — it handles everything.
:: Installs to C:\PureXS (no admin rights needed for updates)
:: ============================================================

set "INSTALL_DIR=%~dp0"
if "%INSTALL_DIR:~-1%"=="\" set "INSTALL_DIR=%INSTALL_DIR:~0,-1%"
set "REPO_URL=https://github.com/insert-aaron/PureXS-releases.git"
set "EXE_NAME=PureXS.exe"
set "DOTNET_DOWNLOAD=https://dotnet.microsoft.com/en-us/download/dotnet/8.0"

:: Detect architecture
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "ARCH=x64"
    set "EXE_PATH=%INSTALL_DIR%\%EXE_NAME%"
) else if "%PROCESSOR_ARCHITEW6432%"=="AMD64" (
    :: 32-bit process on 64-bit OS — still use x64
    set "ARCH=x64"
    set "EXE_PATH=%INSTALL_DIR%\%EXE_NAME%"
) else (
    set "ARCH=x86"
    set "EXE_PATH=%INSTALL_DIR%\x86\%EXE_NAME%"
)

echo [PureXS] Detected %ARCH% architecture.

:: -----------------------------------------------------------
:: Check for Git
:: -----------------------------------------------------------
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [PureXS] Git is not installed.

    :: Try installing via winget
    where winget >nul 2>&1
    if %errorlevel% neq 0 (
        echo [PureXS] ERROR: Neither Git nor winget found.
        echo [PureXS] Please install Git manually from https://git-scm.com/download/win
        goto :launch_existing
    )

    echo [PureXS] Installing Git via winget... This may take a minute.
    winget install --id Git.Git -e --silent --accept-package-agreements --accept-source-agreements
    if %errorlevel% neq 0 (
        echo [PureXS] ERROR: Failed to install Git.
        goto :launch_existing
    )

    :: Refresh PATH so git is available in this session
    set "PATH=%PATH%;C:\Program Files\Git\cmd;C:\Program Files (x86)\Git\cmd"
    where git >nul 2>&1
    if %errorlevel% neq 0 (
        echo [PureXS] Git installed but not yet on PATH. Please restart this script.
        goto :launch_existing
    )
    echo [PureXS] Git installed successfully.
)

:: -----------------------------------------------------------
:: Check for .NET 8 Desktop Runtime
:: -----------------------------------------------------------
set "DOTNET_OK=0"
where dotnet >nul 2>&1
if %errorlevel% equ 0 (
    dotnet --list-runtimes 2>nul | findstr /i "Microsoft.WindowsDesktop.App 8." >nul 2>&1
    if %errorlevel% equ 0 set "DOTNET_OK=1"
)

:: Self-contained builds include the runtime, so this is a soft warning only
if "%DOTNET_OK%"=="0" (
    echo [PureXS] Note: .NET 8 Desktop Runtime not detected on system.
    echo [PureXS] The app is self-contained and should still run.
    echo [PureXS] If you encounter issues, install the runtime from:
    echo           %DOTNET_DOWNLOAD%
    echo.
)

:: -----------------------------------------------------------
:: First run — clone the repo
:: -----------------------------------------------------------
if not exist "%INSTALL_DIR%\.git" (
    echo [PureXS] First run — downloading PureXS...
    if exist "%INSTALL_DIR%" (
        echo [PureXS] Cleaning existing install directory...
        rmdir /s /q "%INSTALL_DIR%" 2>nul
    )
    git clone "%REPO_URL%" "%INSTALL_DIR%"
    if %errorlevel% neq 0 (
        echo [PureXS] ERROR: Failed to clone repository.
        echo [PureXS] Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo [PureXS] Download complete.
    goto :launch
)

:: -----------------------------------------------------------
:: Check for updates
:: -----------------------------------------------------------
echo [PureXS] Checking for updates...
pushd "%INSTALL_DIR%"

git fetch origin main >nul 2>&1
if %errorlevel% neq 0 (
    echo [PureXS] WARNING: Could not check for updates (network unavailable).
    echo [PureXS] Launching last known version...
    popd
    goto :launch
)

:: Compare local HEAD with remote HEAD
for /f "delims=" %%A in ('git rev-parse HEAD') do set "LOCAL_HASH=%%A"
for /f "delims=" %%A in ('git rev-parse origin/main') do set "REMOTE_HASH=%%A"

if "%LOCAL_HASH%"=="%REMOTE_HASH%" (
    echo [PureXS] Already up to date.
    popd
    goto :launch
)

echo [PureXS] Update available — installing...

:: Kill running instance if any
taskkill /f /im "%EXE_NAME%" >nul 2>&1

:: Pull latest
git reset --hard origin/main >nul 2>&1
if %errorlevel% neq 0 (
    echo [PureXS] WARNING: Update failed. Launching previous version...
    popd
    goto :launch
)

echo [PureXS] Updated successfully.
popd

:: -----------------------------------------------------------
:: Launch the app
:: -----------------------------------------------------------
:launch
if not exist "%EXE_PATH%" (
    echo [PureXS] ERROR: Executable not found at %EXE_PATH%
    echo [PureXS] The installation may be corrupt. Delete %INSTALL_DIR% and re-run this script.
    pause
    exit /b 1
)

:: Create a desktop shortcut if it doesn't exist
set "SHORTCUT_PATH=%USERPROFILE%\Desktop\PureXS.lnk"
if not exist "!SHORTCUT_PATH!" (
    echo [PureXS] Creating Desktop shortcut...
    powershell -NoProfile -Command "$wshell = New-Object -ComObject WScript.Shell; $s = $wshell.CreateShortcut('%USERPROFILE%\Desktop\PureXS.lnk'); $s.TargetPath = '%INSTALL_DIR%\SetupAndRun.bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.IconLocation = '%EXE_PATH%'; $s.Description = 'PureXS Auto-Updater'; $s.Save()"
)

echo [PureXS] Launching PureXS (%ARCH%)...
start "" "%EXE_PATH%"
exit /b 0

:: -----------------------------------------------------------
:: Fallback: launch whatever we have if setup fails
:: -----------------------------------------------------------
:launch_existing
if exist "%EXE_PATH%" (
    echo [PureXS] Attempting to launch last known version...
    start "" "%EXE_PATH%"
    exit /b 0
)
echo [PureXS] No existing installation found. Cannot continue without Git.
pause
exit /b 1
