# PureXS

## Install

Download [`SetupAndRun.bat`](SetupAndRun.bat) and double-click it. That's it.

The app installs to `C:\PureXS` and **auto-updates every time you launch it**.

## Requirements

- **Windows** (x64 or x86)
- **Git** — installed automatically on first run if missing
- **.NET 8 Desktop Runtime** — the app is self-contained, but if you encounter issues:
  [Download .NET 8 Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)

## How It Works

`SetupAndRun.bat` is the only file you need. On each launch it:

1. Clones this repo to `C:\PureXS` (first run only)
2. Checks for updates via `git fetch`
3. Pulls new binaries if available
4. Launches the correct binary for your architecture (x64 or x86)

No admin rights required. No installer. No manual updates.

## Development

This repo contains compiled binaries only. For source code and development, see the main [PureXS](https://github.com/insert-aaron/PureXS) repository.
