"""
PureXS cross-platform utilities.

Provides two functions used by every module in the PureXS suite:

    get_data_dir()   Base directory for all PureXS data (logs, patients, config).
                     macOS/Linux: ~/.purexs
                     Windows:     %APPDATA%/PureXS  (typically C:/Users/.../AppData/Roaming/PureXS)

    open_path(path)  Open a file or folder with the OS default application.
                     macOS:   open
                     Windows: os.startfile
                     Linux:   xdg-open
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("purexs.utils")


def get_data_dir() -> Path:
    """Return the PureXS base data directory, creating it if needed.

    Windows: %APPDATA%/PureXS   (C:/Users/{user}/AppData/Roaming/PureXS)
    macOS:   ~/.purexs
    Linux:   ~/.purexs
    """
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        d = base / "PureXS"
    else:
        d = Path.home() / ".purexs"
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
