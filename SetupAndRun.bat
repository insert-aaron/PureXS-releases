@echo off
setlocal EnableDelayedExpansion

:: ============================================================
:: PureXS SetupAndRun.bat
:: Auto-installer + updater + launcher
:: WPF app (PureXS.exe) + Python decoder (decoder/)
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
) else if "%PROCESSOR_ARCHITEW6432%"=="AMD64" (
    set "ARCH=x64"
    set "EXE_PATH=%INSTALL_DIR%\%EXE_NAME%"
    set "DECODER_DIR=%INSTALL_DIR%\decoder"
) else (
    set "ARCH=x86"
    set "EXE_PATH=%INSTALL_DIR%\x86\%EXE_NAME%"
    set "DECODER_DIR=%INSTALL_DIR%\x86\decoder"
)

title %APP_NAME% Setup and Launcher

:: Log file for debugging shortcut launches
set "LOGFILE=%INSTALL_DIR%\purexs_launcher.log"
echo. >> "%LOGFILE%"
echo ============================================ >> "%LOGFILE%"
echo [%date% %time%] Launcher started >> "%LOGFILE%"
echo   Architecture: %ARCH% >> "%LOGFILE%"
echo   Install dir:  %INSTALL_DIR% >> "%LOGFILE%"
echo   Launched from: %~f0 >> "%LOGFILE%"
echo ============================================ >> "%LOGFILE%"

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
    winget install --id Git.Git -e --silent --accept-package-agreements --accept-source-agreements
    if %errorlevel% neq 0 (
        echo [%APP_NAME%] ERROR: Failed to install Git.
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
:: Step 2: Check/Install Python (for the decoder)
:: ============================================================
echo [%APP_NAME%] Checking Python for image decoder...

set "PYTHON_CMD="

:: Check system Python
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python"
    goto :python_found
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python3"
    goto :python_found
)

:: Check embedded Python in install dir
if exist "%INSTALL_DIR%\python\python.exe" (
    set "PYTHON_CMD=%INSTALL_DIR%\python\python.exe"
    goto :python_found
)

:: Install embedded Python (no admin needed, no system-wide install)
echo [%APP_NAME%] Python not found. Installing embedded Python 3.11...
set "PY_VER=3.11.9"

if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "PY_URL=https://www.python.org/ftp/python/%PY_VER%/python-%PY_VER%-embed-amd64.zip"
) else (
    set "PY_URL=https://www.python.org/ftp/python/%PY_VER%/python-%PY_VER%-embed-win32.zip"
)

powershell -Command "Invoke-WebRequest -Uri '!PY_URL!' -OutFile '%TEMP%\python_embed.zip'"
if not exist "%TEMP%\python_embed.zip" (
    echo [%APP_NAME%] WARNING: Could not download Python. Decoder will be unavailable.
    goto :skip_python
)

if not exist "%INSTALL_DIR%\python" mkdir "%INSTALL_DIR%\python"
powershell -Command "Expand-Archive -Path '%TEMP%\python_embed.zip' -DestinationPath '%INSTALL_DIR%\python' -Force"
del "%TEMP%\python_embed.zip" 2>nul

:: Enable pip in embedded Python (uncomment import site in ._pth file)
for %%f in ("%INSTALL_DIR%\python\python*._pth") do (
    powershell -Command "(Get-Content '%%f') -replace '#import site','import site' | Set-Content '%%f'"
)

:: Install pip
echo [%APP_NAME%] Installing pip...
powershell -Command "Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%TEMP%\get-pip.py'"
"%INSTALL_DIR%\python\python.exe" "%TEMP%\get-pip.py" --no-warn-script-location
del "%TEMP%\get-pip.py" 2>nul

set "PYTHON_CMD=%INSTALL_DIR%\python\python.exe"

:python_found
echo [%APP_NAME%] Python: %PYTHON_CMD%
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
git clone --branch %BRANCH% --single-branch --depth=1 "%REPO_URL%" "%INSTALL_DIR%_tmp"
if %errorlevel% neq 0 (
    echo [%APP_NAME%] ERROR: Git clone failed.
    pause
    exit /b 1
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

:: Install decoder Python dependencies
if defined PYTHON_CMD (
    if exist "%DECODER_DIR%\requirements.txt" (
        echo [%APP_NAME%] Installing decoder dependencies...
        "%PYTHON_CMD%" -m pip install -r "%DECODER_DIR%\requirements.txt" --no-warn-script-location --quiet
        if %errorlevel% neq 0 (
            echo [%APP_NAME%] Warning: Some dependencies may have failed to install.
        ) else (
            echo [%APP_NAME%] Decoder dependencies installed.
        )
    )
)

:: Create data directories
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\patients" mkdir "%DATA_DIR%\patients"

:: Create desktop shortcut (points to this bat = auto-update trick)
set "SHORTCUT_PATH=%USERPROFILE%\Desktop\%SHORTCUT_NAME%.lnk"
if not exist "!SHORTCUT_PATH!" (
    echo [%APP_NAME%] Creating Desktop shortcut...
    powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('%USERPROFILE%\Desktop\%SHORTCUT_NAME%.lnk'); $sc.TargetPath = '%INSTALL_DIR%\SetupAndRun.bat'; $sc.WorkingDirectory = '%INSTALL_DIR%'; $sc.IconLocation = '%EXE_PATH%'; $sc.Description = 'PureXS - Panoramic X-Ray Pipeline'; $sc.Save()"
    if exist "!SHORTCUT_PATH!" (
        echo [%APP_NAME%] Desktop shortcut created.
    ) else (
        echo [%APP_NAME%] Warning: Could not create shortcut.
    )
)

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
if defined PYTHON_CMD if exist "%DECODER_DIR%\requirements.txt" "%PYTHON_CMD%" -m pip install -r "%DECODER_DIR%\requirements.txt" --no-warn-script-location --quiet 2>nul

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
    pause
    exit /b 1
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
exit /b 0

:: ============================================================
:: Fallback: launch whatever we have if setup fails
:: ============================================================
:launch_existing
if exist "%EXE_PATH%" (
    echo [%APP_NAME%] Attempting to launch last known version...
    start "" "%EXE_PATH%"
    exit /b 0
)
echo [%APP_NAME%] No existing installation found. Cannot continue.
pause
exit /b 1
