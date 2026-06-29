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

from hb_decoder import (
    _extract_panoramic, _extract_panoramic_simple,
    reconstruct_image, reconstruct_ceph_image,
    check_scan_completeness, check_detector_geometry,
)

# Exit code returned when the scan completed transport but delivered too
# few scanlines for a valid reconstruction. The WPF wrapper distinguishes
# this from a generic decoder failure (exit 1) so it can show a clear
# retake prompt instead of falling through to a useless scanline preview.
EXIT_INCOMPLETE_SCAN = 2

# Exit code returned when the detector geometry doesn't match the Orthophos XG
# this pipeline targets (e.g. a fleet unit with a different detector/firmware).
# Distinct from incomplete (2) so the wrapper shows an "unsupported unit" error
# rather than a retake prompt — retaking won't help; it's a config/hardware fact.
EXIT_DETECTOR_MISMATCH = 3

log = logging.getLogger("purexs_decoder_cli")

_CEPH_TYPES = {"Ceph Lateral", "Ceph Frontal"}


def process_raw(
    input_path: Path,
    output_path: Path,
    exam_type: str = "Panoramic",
    save_tif: bool = False,
) -> int:
    """Read raw scan bytes, decode scanlines, reconstruct, and save PNG.

    When *save_tif* is True, also write an uncompressed 8-bit grayscale TIFF
    with the same pixel data alongside the PNG (same path, .tif extension).
    Used by facilities running per-device LUT calibration against Sidexis.
    """
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

    # Hard geometry gate — refuse if the detector isn't the Orthophos XG this
    # pipeline targets (a different fleet unit/firmware would silently produce
    # garbage). The WPF wrapper looks for the "DETECTOR_MISMATCH:" prefix.
    geo_ok, geo_msg = check_detector_geometry(scanlines)
    if not geo_ok:
        log.error("DETECTOR_MISMATCH: %s", geo_msg)
        return EXIT_DETECTOR_MISMATCH

    # Refuse to reconstruct truncated scans — the WPF wrapper looks for the
    # "INCOMPLETE_SCAN:" prefix to surface a retake message instead of
    # falling through to a useless scanline preview.
    ok, retake_msg = check_scan_completeness(scanlines, exam_type)
    if not ok:
        log.error("INCOMPLETE_SCAN: %s", retake_msg)
        return EXIT_INCOMPLETE_SCAN

    log.info("Extracted %d scanlines, reconstructing %s...", len(scanlines), exam_type)

    if exam_type in _CEPH_TYPES:
        img = reconstruct_ceph_image(scanlines)
    else:
        img = reconstruct_image(scanlines, repair_mask=repair_mask)

    if img is None:
        log.error("Reconstruction returned None")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(str(output_path), "PNG")
    log.info("Saved %dx%d %s to %s", img.width, img.height, exam_type, output_path)

    if save_tif:
        tif_path = output_path.with_suffix(".tif")
        img.save(str(tif_path), format="TIFF", compression="none")
        log.info("Saved TIF (uncompressed) to %s", tif_path)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="purexs_decoder",
        description="PureXS Decoder — raw scan bytes to finished PNG",
    )
    parser.add_argument(
        "--input", "-i", required=True, type=Path,
        help="Path to raw scan .bin file",
    )
    parser.add_argument(
        "--output", "-o", required=True, type=Path,
        help="Path for output .png",
    )
    parser.add_argument(
        "--exam-type", "-e", default="Panoramic",
        choices=["Panoramic", "Ceph Lateral", "Ceph Frontal"],
        help="Exam type for reconstruction pipeline routing",
    )
    parser.add_argument(
        "--save-tif", action="store_true",
        help="Also save an uncompressed 8-bit TIFF alongside the PNG "
             "(same path, .tif extension). Used for per-device Sidexis "
             "LUT calibration; default off because uncompressed TIFs "
             "are ~5× the size of PNGs.",
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

    sys.exit(process_raw(args.input, args.output, args.exam_type, save_tif=args.save_tif))


if __name__ == "__main__":
    main()
