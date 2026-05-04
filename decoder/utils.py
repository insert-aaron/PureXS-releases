"""
PureXS cross-platform utilities.

Provides two functions used by every module in the PureXS suite:

    get_data_dir()   Decoder debug directory — hb_decoder.log,
                     last_scan_raw.bin, debug_hole_*.png, flat_field_raw.bin.
                     Windows:     %LOCALAPPDATA%/PureXS/debug
                                  (overridable via PUREXS_DATA_DIR env var)
                     macOS/Linux: ~/.purexs/debug

    open_path(path)  Open a file or folder with the OS default application.
                     macOS:   open
                     Windows: os.startfile
                     Linux:   xdg-open

The Windows path mirrors the WPF host's PureXSDataPaths.Debug — both
sides resolve PUREXS_DATA_DIR identically so the consolidated layout
under the chosen root holds for Python and C# alike.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("purexs.utils")


def get_data_dir() -> Path:
    """Return the PureXS decoder debug directory, creating it if needed.

    Resolution order:
      1. PUREXS_DATA_DIR env var → <that>/debug
         (set by SetupAndRun.bat or facility-specific config; lets
         operators relocate all PureXS data to a non-system drive
         without touching code)
      2. Windows: %LOCALAPPDATA%/PureXS/debug
                  (matches WPF host's PureXSDataPaths.Debug)
      3. macOS/Linux: ~/.purexs/debug

    Was previously %APPDATA%/PureXS (Roaming) — moved into the
    consolidated layout so big calibration/debug binaries don't sync
    to a domain server with the user's roaming profile.
    """
    env_root = os.environ.get("PUREXS_DATA_DIR")
    if env_root:
        d = Path(env_root) / "debug"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA",
                                   Path.home() / "AppData" / "Local"))
        d = base / "PureXS" / "debug"
    else:
        d = Path.home() / ".purexs" / "debug"
    d.mkdir(parents=True, exist_ok=True)
    return d


def open_path(path: str | Path) -> None:
    """Open a file or directory with the OS default handler.

    Silently logs and returns on failure — never raises.
    """
    path_str = str(path)
    try:
        if sys.platform == "win32":
            os.startfile(path_str)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path_str])
        else:
            subprocess.Popen(["xdg-open", path_str])
    except Exception as exc:
        log.warning("Failed to open %s: %s", path_str, exc)
