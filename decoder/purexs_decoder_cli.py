#!/usr/bin/env python3
"""PureXS Decoder CLI — standalone entry point for the imaging pipeline.

Usage:
    purexs_decoder_cli.py --input raw_scan.bin --output panoramic.png

The WPF app calls this as a subprocess (or as a PyInstaller .exe) to
process raw Orthophos XG scan bytes into a finished panoramic PNG.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np

# Ensure the package directory is on sys.path so hb_decoder and utils resolve
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from hb_decoder import _extract_panoramic, _extract_panoramic_simple, reconstruct_image

log = logging.getLogger("purexs_decoder_cli")


def process_raw(input_path: Path, output_path: Path) -> int:
    """Read raw scan bytes, decode scanlines, reconstruct, and save PNG."""
    raw = input_path.read_bytes()
    if len(raw) < 10_000:
        log.error("Input file too small (%d bytes) — not a valid scan", len(raw))
        return 1

    # Try advanced extraction first, fall back to simple
    scanlines = []
    repair_mask = None
    try:
        result = _extract_panoramic(raw)
        if isinstance(result, tuple):
            scanlines, repair_mask = result
        else:
            scanlines = result
    except Exception as exc:
        log.warning("Advanced extraction failed (%s), trying simple fallback", exc)

    if not scanlines:
        scanlines = _extract_panoramic_simple(raw)

    if not scanlines:
        log.error("Could not extract any scanlines from input")
        return 1

    log.info("Extracted %d scanlines, reconstructing panoramic...", len(scanlines))
    img = reconstruct_image(scanlines, repair_mask=repair_mask)
    if img is None:
        log.error("reconstruct_image returned None")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(str(output_path), "PNG")
    log.info("Saved %dx%d panoramic to %s", img.width, img.height, output_path)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="purexs_decoder",
        description="PureXS Decoder — raw scan bytes to panoramic PNG",
    )
    parser.add_argument(
        "--input", "-i", required=True, type=Path,
        help="Path to raw scan .bin file",
    )
    parser.add_argument(
        "--output", "-o", required=True, type=Path,
        help="Path for output panoramic .png",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    sys.exit(process_raw(args.input, args.output))


if __name__ == "__main__":
    main()
