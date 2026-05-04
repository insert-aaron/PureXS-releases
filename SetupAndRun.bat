@echo off
setlocal EnableDelayedExpansion

:: ============================================================
:: PureXS SetupAndRun.bat
:: Auto-installer + updater + launcher
:: WPF app (PureXS.exe) + bundled Python decoder (python/, decoder/)
::
:: As of 2026-05, the embedded Python interpreter and decoder
:: dependencies (numpy, opencv, scipy, Pillow, pydicom) are
:: bundled into PureXS-releases by CI. No runtime download is
:: required, so the decoder works on offline / firewalled /
:: locked-down workstations where the previous self-install
:: path was failing silently.
::
:: Three-way state detection:
::   .git missing, marker missing  -> fresh clone + post-install + launch
::   .git exists,  marker missing  -> user cloned manually, post-install + launch
::   .git exists,  marker exists   -> returning launch, check for updates + launch
::
:: Flows through source repo (PureXS) and is deployed to
:: PureXS-releases by CI on every push to main.
:: ============================================================

set "INSTALL_DIR=%~dp0"
if "%INSTALL_DIR:~-1%"=="\" set "INSTALL_DIR=%INSTALL_DIR:~0,-1%"
set "REPO_URL=https://github.com/insert-aaron/PureXS-releases.git"
set "BRANCH=main"
set "APP_NAME=PureXS"
set "EXE_NAME=PureXS.exe"
set "SHORTCUT_NAME=PureXS"
set "DATA_DIR=%APPDATA%\PureXS"
set "MARKER=%INSTALL_DIR%\.purexs_installed"

:: Detect architecture
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "ARCH=x64"
    set "EXE_PATH=%INSTALL_DIR%\%EXE_NAME%"
    set "DECODER_DIR=%INSTALL_DIR%\decoder"
    set "BUNDLED_PY=%INSTALL_DIR%\python\python.exe"
) else if "%PROCESSOR_ARCHITEW6432%"=="AMD64" (
    set "ARCH=x64"
    set "EXE_PATH=%INSTALL_DIR%\%EXE_NAME%"
    set "DECODER_DIR=%INSTALL_DIR%\decoder"
    set "BUNDLED_PY=%INSTALL_DIR%\python\python.exe"
) else (
    set "ARCH=x86"
    set "EXE_PATH=%INSTALL_DIR%\x86\%EXE_NAME%"
    set "DECODER_DIR=%INSTALL_DIR%\x86\decoder"
    set "BUNDLED_PY=%INSTALL_DIR%\x86\python\python.exe"
)

title %APP_NAME% Setup and Launcher

:: ── Launcher log ─────────────────────────────────────────────
:: Captures state transitions, the chosen Python interpreter, the
:: result of every external command (git clone, winget, pip), and
:: any error/warning text that the user might miss before the cmd
:: window closes. Read this first when triaging facility issues.
set "LOGFILE=%INSTALL_DIR%\purexs_launcher.log"
echo. >> "%LOGFILE%"
echo ============================================ >> "%LOGFILE%"
echo [%date% %time%] Launcher started >> "%LOGFILE%"
echo   Architecture: %ARCH% >> "%LOGFILE%"
echo   Install dir:  %INSTALL_DIR% >> "%LOGFILE%"
echo   Bundled py:   %BUNDLED_PY% >> "%LOGFILE%"
echo   Launched from: %~f0 >> "%LOGFILE%"
echo ============================================ >> "%LOGFILE%"
echo.
echo Launcher log: %LOGFILE%
echo.

echo.
echo ========================================
echo   %APP_NAME% - Setup and Launcher
echo   Architecture: %ARCH%
echo ========================================
echo.

:: ============================================================
:: Step 1: Check/Install Git
:: ============================================================
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [%APP_NAME%] Git not found. Installing...

    where winget >nul 2>&1
    if %errorlevel% neq 0 (
        echo [%APP_NAME%] ERROR: Neither Git nor winget found.
        echo [%APP_NAME%] Please install Git manually from https://git-scm.com/download/win
        goto :launch_existing
    )

    echo [%APP_NAME%] Installing Git via winget...
    echo [%date% %time%] Running: winget install Git.Git >> "%LOGFILE%"
    winget install --id Git.Git -e --silent --accept-package-agreements --accept-source-agreements >> "%LOGFILE%" 2>&1
    if %errorlevel% neq 0 (
        echo [%APP_NAME%] ERROR: Failed to install Git. See %LOGFILE%.
        echo [%date% %time%] winget install Git FAILED ^(exit !errorlevel!^) >> "%LOGFILE%"
        goto :launch_existing
    )

    set "PATH=%PATH%;C:\Program Files\Git\cmd;C:\Program Files (x86)\Git\cmd"
    where git >nul 2>&1
    if %errorlevel% neq 0 (
        echo [%APP_NAME%] Git installed but not yet on PATH. Please restart this script.
        goto :launch_existing
    )
    echo [%APP_NAME%] Git installed successfully.
) else (
    echo [%APP_NAME%] Git found.
)

:: ============================================================
:: Step 2: Locate Python interpreter for the decoder
::
:: Priority:
::   1. Bundled Python (shipped in PureXS-releases — primary path)
::   2. System Python on PATH (fallback for x86 or hand-rolled installs)
::
:: We deliberately do NOT attempt a runtime download. That path failed
:: silently on locked-down dental-office workstations (firewalled
:: python.org / bootstrap.pypa.io, AV inspection, no admin) and left
:: facilities running with the 14-scanline preview without realizing
:: the decoder was missing. If the bundle is gone, re-clone the
:: release repo to restore it.
:: ============================================================
echo [%APP_NAME%] Locating Python for image decoder...

set "PYTHON_CMD="

if exist "%BUNDLED_PY%" (
    set "PYTHON_CMD=%BUNDLED_PY%"
    echo [%APP_NAME%] Using bundled Python: !PYTHON_CMD!
    echo [%date% %time%] Python: bundled at %BUNDLED_PY% >> "%LOGFILE%"
    goto :verify_python
)

where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python"
    echo [%APP_NAME%] Bundled Python missing — using system Python on PATH.
    echo [%date% %time%] Python: system PATH ^(bundle missing at %BUNDLED_PY%^) >> "%LOGFILE%"
    goto :verify_python
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python3"
    echo [%APP_NAME%] Bundled Python missing — using system python3 on PATH.
    echo [%date% %time%] Python: system PATH ^(python3, bundle missing^) >> "%LOGFILE%"
    goto :verify_python
)

echo [%APP_NAME%] WARNING: No Python found.
echo [%APP_NAME%]   Expected bundled interpreter at: %BUNDLED_PY%
echo [%APP_NAME%]   Re-clone PureXS-releases to restore it, or install Python 3.11+
echo [%APP_NAME%]   manually and ensure it's on PATH.
echo [%APP_NAME%]   Decoder unavailable — image will fall back to scanline preview.
echo [%date% %time%] Python: NOT FOUND ^(bundle missing, no system Python^) >> "%LOGFILE%"
goto :skip_python

:verify_python
:: Confirm the decoder dependencies actually import. The bundle ships
:: with everything pre-installed; this is a sanity check that catches
:: AV-quarantined files, partial corruption, or system-Python misses.
"%PYTHON_CMD%" -c "import numpy, cv2, PIL, scipy, pydicom" >nul 2>&1
if %errorlevel% neq 0 (
    echo [%APP_NAME%] Decoder dependencies missing — attempting pip repair...
    echo [%date% %time%] Decoder deps verify FAILED, attempting repair >> "%LOGFILE%"
    if exist "%DECODER_DIR%\requirements.txt" (
        echo [%date% %time%] Running: pip install -r %DECODER_DIR%\requirements.txt ^(repair^) >> "%LOGFILE%"
        "%PYTHON_CMD%" -m pip install -r "%DECODER_DIR%\requirements.txt" --no-warn-script-location >> "%LOGFILE%" 2>&1
        "%PYTHON_CMD%" -c "import numpy, cv2, PIL, scipy, pydicom" >> "%LOGFILE%" 2>&1
        if !errorlevel! neq 0 (
            echo [%APP_NAME%] WARNING: Repair failed — decoder unavailable. See %LOGFILE%.
            echo [%date% %time%] Decoder deps repair FAILED >> "%LOGFILE%"
            set "PYTHON_CMD="
            goto :skip_python
        )
        echo [%APP_NAME%] Decoder dependencies repaired.
        echo [%date% %time%] Decoder deps repaired >> "%LOGFILE%"
    ) else (
        echo [%APP_NAME%] WARNING: requirements.txt missing — decoder unavailable.
        set "PYTHON_CMD="
        goto :skip_python
    )
)
echo [%APP_NAME%] Python verified: %PYTHON_CMD%
echo [%date% %time%] Python verified >> "%LOGFILE%"
goto :state_detect

:skip_python
echo [%APP_NAME%] Continuing without Python — decoder unavailable.

:: ============================================================
:: Step 3: Three-way state detection
:: ============================================================
:state_detect

:: State 1: .git missing, marker missing -> fresh download
if not exist "%INSTALL_DIR%\.git" (
    if not exist "%MARKER%" (
        echo [%APP_NAME%] Fresh install — cloning repository...
        echo [%date% %time%] State 1: fresh clone ^(.git missing, marker missing^) >> "%LOGFILE%"
        goto :fresh_clone
    )
)

:: State 2: .git exists, marker missing -> user cloned manually, need post-install
if exist "%INSTALL_DIR%\.git" (
    if not exist "%MARKER%" (
        echo [%APP_NAME%] Repository found but not configured — running post-install...
        echo [%date% %time%] State 2: post-install ^(.git exists, marker missing^) >> "%LOGFILE%"
        goto :post_install
    )
)

:: State 3: .git exists, marker exists -> returning launch, check for updates
if exist "%INSTALL_DIR%\.git" (
    if exist "%MARKER%" (
        echo [%APP_NAME%] Checking for updates...
        echo [%date% %time%] State 3: returning launch ^(.git exists, marker exists^) >> "%LOGFILE%"
        goto :check_update
    )
)

:: Fallback: .git missing but marker exists — re-clone needed
echo [%APP_NAME%] Unexpected state — attempting launch...
echo [%date% %time%] FALLBACK: .git missing=%INSTALL_DIR%\.git marker=%MARKER% >> "%LOGFILE%"
goto :launch

:: ============================================================
:: Fresh clone (State 1)
:: ============================================================
:fresh_clone
echo [%date% %time%] Running: git clone --branch %BRANCH% --depth=1 %REPO_URL% >> "%LOGFILE%"
git clone --branch %BRANCH% --single-branch --depth=1 "%REPO_URL%" "%INSTALL_DIR%_tmp" >> "%LOGFILE%" 2>&1
if %errorlevel% neq 0 (
    echo [%APP_NAME%] ERROR: Git clone failed. See %LOGFILE%.
    echo [%date% %time%] git clone FAILED ^(exit !errorlevel!^) >> "%LOGFILE%"
    goto :end_pause_error
)

:: Preserve existing files (e.g. flat_field_norm.npy) if install dir exists
if exist "%INSTALL_DIR%" (
    xcopy /E /Y /Q "%INSTALL_DIR%_tmp\*" "%INSTALL_DIR%\" >nul
    xcopy /E /Y /H /Q "%INSTALL_DIR%_tmp\.git" "%INSTALL_DIR%\.git\" >nul
    rmdir /S /Q "%INSTALL_DIR%_tmp"
) else (
    move "%INSTALL_DIR%_tmp" "%INSTALL_DIR%"
)

echo [%APP_NAME%] Clone complete.
goto :post_install

:: ============================================================
:: Post-install (runs after fresh clone OR after manual git clone)
:: ============================================================
:post_install
echo [%APP_NAME%] Running post-install...

:: Install decoder Python dependencies (no-op if bundle is intact)
if defined PYTHON_CMD (
    if exist "%DECODER_DIR%\requirements.txt" (
        echo [%APP_NAME%] Installing decoder dependencies...
        echo [%date% %time%] Running: pip install -r %DECODER_DIR%\requirements.txt >> "%LOGFILE%"
        "%PYTHON_CMD%" -m pip install -r "%DECODER_DIR%\requirements.txt" --no-warn-script-location >> "%LOGFILE%" 2>&1
        if %errorlevel% neq 0 (
            echo [%APP_NAME%] Warning: Some dependencies may have failed to install. See %LOGFILE%.
            echo [%date% %time%] pip install FAILED ^(exit !errorlevel!^) >> "%LOGFILE%"
        ) else (
            echo [%APP_NAME%] Decoder dependencies installed.
        )
    )
)

:: Create data directories
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\patients" mkdir "%DATA_DIR%\patients"

:: Shortcut creation moved to :launch so it self-heals on every run
:: (e.g. if user deletes shortcut, or first attempt failed silently)

:: Write marker file — post-install complete
echo installed> "%MARKER%"
echo [%APP_NAME%] Post-install complete.

echo.
echo ========================================
echo   %APP_NAME% installation complete!
echo ========================================
echo.

goto :launch

:: ============================================================
:: Check for updates (State 3 — returning launch)
:: ============================================================
:check_update
pushd "%INSTALL_DIR%"
echo [%date% %time%] State 3: check_update >> "%LOGFILE%"

:: Fetch and explicitly update the remote tracking ref (not just FETCH_HEAD)
echo [%date% %time%] Running: git fetch origin +%BRANCH%:refs/remotes/origin/%BRANCH% >> "%LOGFILE%"
git fetch origin +%BRANCH%:refs/remotes/origin/%BRANCH% >> "%LOGFILE%" 2>&1
set "FETCH_ERR=!errorlevel!"
echo [%date% %time%] Fetch exit code: !FETCH_ERR! >> "%LOGFILE%"

:: If fetch failed, skip update and go straight to launch
if !FETCH_ERR! neq 0 echo [%APP_NAME%] WARNING: Could not check for updates (no network?). & goto :update_done

:: Compare local vs remote
for /f "delims=" %%A in ('git rev-parse HEAD') do set "LOCAL_HASH=%%A"
for /f "delims=" %%A in ('git rev-parse origin/%BRANCH%') do set "REMOTE_HASH=%%A"
echo [%date% %time%] LOCAL:  !LOCAL_HASH! >> "%LOGFILE%"
echo [%date% %time%] REMOTE: !REMOTE_HASH! >> "%LOGFILE%"

:: If already up to date, skip update
if "!LOCAL_HASH!"=="!REMOTE_HASH!" echo [%APP_NAME%] Already up to date. & goto :update_done

:: Update available
echo [%APP_NAME%] Update available — installing...
echo [%date% %time%] Update available >> "%LOGFILE%"
taskkill /f /im "%EXE_NAME%" >nul 2>&1
git reset --hard origin/%BRANCH% >> "%LOGFILE%" 2>&1
set "RESET_ERR=!errorlevel!"
if !RESET_ERR! neq 0 echo [%APP_NAME%] WARNING: Update failed. & goto :update_done
echo [%APP_NAME%] Updated successfully.
echo [%date% %time%] Updated successfully >> "%LOGFILE%"

:: Re-install decoder deps in case requirements changed
if defined PYTHON_CMD if exist "%DECODER_DIR%\requirements.txt" (
    echo [%date% %time%] Running: pip install -r %DECODER_DIR%\requirements.txt ^(post-update^) >> "%LOGFILE%"
    "%PYTHON_CMD%" -m pip install -r "%DECODER_DIR%\requirements.txt" --no-warn-script-location >> "%LOGFILE%" 2>&1
)

:update_done
popd
echo [%date% %time%] Update check complete, proceeding to launch >> "%LOGFILE%"
goto :launch

:: ============================================================
:: Launch
:: ============================================================
:launch
if not exist "%EXE_PATH%" (
    echo [%APP_NAME%] ERROR: Executable not found at %EXE_PATH%
    echo [%APP_NAME%] The installation may be corrupt. Delete the install directory and re-run.
    echo [%date% %time%] EXE missing: %EXE_PATH% >> "%LOGFILE%"
    goto :end_pause_error
)

:: ------------------------------------------------------------
:: Ensure Desktop shortcut exists (self-heals every launch)
:: Resolves the real Desktop via [Environment]::GetFolderPath('Desktop')
:: so OneDrive-redirected desktops on Win10/11/11 Pro work correctly.
:: ------------------------------------------------------------
set "DESKTOP_DIR="
for /f "usebackq delims=" %%D in (`powershell -NoProfile -Command "[Environment]::GetFolderPath('Desktop')"`) do set "DESKTOP_DIR=%%D"
if not defined DESKTOP_DIR set "DESKTOP_DIR=%USERPROFILE%\Desktop"
set "SHORTCUT_PATH=!DESKTOP_DIR!\%SHORTCUT_NAME%.lnk"
echo [%date% %time%] Desktop resolved to: !DESKTOP_DIR! >> "%LOGFILE%"

if not exist "!SHORTCUT_PATH!" (
    echo [%APP_NAME%] Creating Desktop shortcut at !DESKTOP_DIR!...
    powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('!SHORTCUT_PATH!'); $sc.TargetPath = '%INSTALL_DIR%\SetupAndRun.bat'; $sc.WorkingDirectory = '%INSTALL_DIR%'; $sc.IconLocation = '%EXE_PATH%'; $sc.Description = 'PureXS - Panoramic X-Ray Pipeline'; $sc.Save()"
    if exist "!SHORTCUT_PATH!" (
        echo [%APP_NAME%] Desktop shortcut created: !SHORTCUT_PATH!
        echo [%date% %time%] Shortcut created: !SHORTCUT_PATH! >> "%LOGFILE%"
    ) else (
        echo [%APP_NAME%] WARNING: Could not create shortcut at !SHORTCUT_PATH!
        echo [%date% %time%] Shortcut creation FAILED at !SHORTCUT_PATH! >> "%LOGFILE%"
    )
)

:: Tell the WPF app where Python is (for the decoder subprocess)
if defined PYTHON_CMD (
    set "PUREXS_PYTHON=%PYTHON_CMD%"
)

:: Create data directory (in case update wiped it)
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

echo [%date% %time%] Launching %EXE_PATH% >> "%LOGFILE%"
echo [%APP_NAME%] Launching %APP_NAME% (%ARCH%)...
start "" "%EXE_PATH%"
goto :end_pause_success

:: ============================================================
:: Fallback: launch whatever we have if setup fails
:: ============================================================
:launch_existing
if exist "%EXE_PATH%" (
    echo [%APP_NAME%] Attempting to launch last known version at %EXE_PATH%...
    echo [%date% %time%] Fallback launch ^(setup did not complete^) >> "%LOGFILE%"
    start "" "%EXE_PATH%"
    goto :end_pause_warn
)
echo [%APP_NAME%] No existing installation found. Cannot continue.
echo [%date% %time%] No EXE at %EXE_PATH% — cannot launch >> "%LOGFILE%"
goto :end_pause_error

:: ============================================================
:: Exit handlers — always show log path and pause so the cmd
:: window doesn't flash shut before the user can read what
:: happened. The PureXS GUI launches in a separate process via
:: `start ""`, so pausing here does not block it.
:: ============================================================
:end_pause_success
echo.
echo ============================================
echo   %APP_NAME% launched. Log: %LOGFILE%
echo ============================================
echo This window will close in 8 seconds (or press any key)...
timeout /t 8 >nul
exit /b 0

:end_pause_warn
echo.
echo ============================================
echo   %APP_NAME% launched in fallback mode.
echo   Setup did not complete cleanly — review:
echo     %LOGFILE%
echo ============================================
echo This window will close in 15 seconds (or press any key)...
timeout /t 15 >nul
exit /b 0

:end_pause_error
echo.
echo ============================================
echo   %APP_NAME% setup failed.
echo   Full log saved to:
echo     %LOGFILE%
echo ============================================
echo Press any key to close this window...
pause >nul
exit /b 1
