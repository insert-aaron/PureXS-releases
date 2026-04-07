#!/usr/bin/env python3
"""
PureXS DICOM Export — converts Sirona Orthophos panoramic scanlines to DICOM.

Standalone module with no GUI dependencies.  Importable from purexs_gui.py
or usable as a CLI tool for batch conversion.

Produces Digital X-Ray (DX) DICOM files conformant with:
  - DICOM PS3.3 C.8.11.7 — DX Image Module
  - SOP Class: Digital X-Ray Image Storage — For Presentation (1.2.840.10008.5.1.4.1.1.1.1)

Dependencies:
    pip install pydicom numpy

Usage (standalone):
    python dicom_export.py --first John --last Smith --dob 01/15/1985 \
           --id abc123 --exam Panoramic --kv 70.0 \
           --scanlines test --outdir ./out

Usage (from GUI):
    from dicom_export import PureXSDICOM
    dcm_path = PureXSDICOM().export(patient_dict, scanline_list, kv_peak, outdir)
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

try:
    import pydicom
    from pydicom.dataset import Dataset, FileDataset
    from pydicom.sequence import Sequence
    from pydicom.uid import (
        ExplicitVRLittleEndian,
        generate_uid,
    )
    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False

# ── Logging ──────────────────────────────────────────────────────────────────

from utils import get_data_dir

LOG_DIR = get_data_dir()

log = logging.getLogger("purexs.dicom")
if not log.handlers:
    _fh = logging.FileHandler(LOG_DIR / "dicom_export.log", encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s"))
    log.addHandler(_fh)
    log.setLevel(logging.DEBUG)


# ── Constants ────────────────────────────────────────────────────────────────

# Digital X-Ray Image Storage — For Presentation
DX_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.1.1"

PUREXS_IMPLEMENTATION_CLASS_UID = "1.2.826.0.1.3680043.8.1055.1"
PUREXS_IMPLEMENTATION_VERSION = "PUREXS_100"


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  PureXSDICOM
# ╚══════════════════════════════════════════════════════════════════════════════

class PureXSDICOM:
    """Exports Sirona Orthophos panoramic scans as DICOM DX files."""

    def export(
        self,
        patient: dict[str, Any],
        scanline_buffer: list[Any],
        kv_peak: float,
        output_dir: str | Path,
        exposure_time_ms: int = 4000,
    ) -> str:
        """Build a DICOM file from scanline data and patient context.

        Args:
            patient: Dict with keys: first, last, dob (MM/DD/YYYY), id, exam, set.
            scanline_buffer: List of Scanline objects (each has .pixels: np.ndarray uint16,
                             .pixel_count: int).  Each scanline becomes one image column.
            kv_peak: Peak kV recorded during the exposure.
            output_dir: Directory to write the .dcm file into.
            exposure_time_ms: Nominal exposure duration in milliseconds.

        Returns:
            Absolute path to the saved .dcm file.

        Raises:
            RuntimeError: pydicom not installed, empty buffer, or patient not set.
        """
        if not HAS_PYDICOM:
            raise RuntimeError(
                "pydicom is required for DICOM export. "
                "Install with: pip install pydicom"
            )

        # ── Validation ───────────────────────────────────────────────────
        if not patient.get("set"):
            raise RuntimeError("Patient context not set — cannot export DICOM")
        if not scanline_buffer:
            raise RuntimeError("Scanline buffer is empty — no image data to export")

        log.info(
            "DICOM export: patient=%s^%s  scanlines=%d  kV=%.1f",
            patient["last"], patient["first"],
            len(scanline_buffer), kv_peak,
        )

        # ── Build pixel array ────────────────────────────────────────────
        # Each scanline is a vertical strip; stitch into columns
        pixel_array = self._build_pixel_array(scanline_buffer)
        rows, cols = pixel_array.shape
        log.info("Pixel array: %d x %d  dtype=%s", rows, cols, pixel_array.dtype)

        if rows == 0 or cols == 0:
            raise RuntimeError(
                f"Invalid pixel array dimensions: {rows}x{cols}"
            )

        # ── Build output path ────────────────────────────────────────────
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        dob_nodash = patient["dob"].replace("/", "")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{patient['last']}_{patient['first']}_{dob_nodash}_{ts}.dcm"
        dcm_path = output_dir / filename

        # ── File meta info ───────────────────────────────────────────────
        file_meta = pydicom.dataset.FileMetaDataset()
        file_meta.FileMetaInformationVersion = b"\x00\x01"
        file_meta.MediaStorageSOPClassUID = DX_SOP_CLASS_UID
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.ImplementationClassUID = PUREXS_IMPLEMENTATION_CLASS_UID
        file_meta.ImplementationVersionName = PUREXS_IMPLEMENTATION_VERSION

        # ── Dataset ──────────────────────────────────────────────────────
        ds = FileDataset(
            str(dcm_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
        )

        now = datetime.now()
        study_uid = generate_uid()
        series_uid = generate_uid()

        # ── Patient Module (C.7.1.1) ─────────────────────────────────────
        ds.PatientName = f"{patient['last']}^{patient['first']}"
        ds.PatientID = patient.get("id", "")
        ds.PatientBirthDate = self._dob_to_dicom(patient.get("dob", ""))
        ds.PatientSex = ""  # Unknown

        # ── General Study Module (C.7.2.1) ────────────────────────────────
        ds.StudyInstanceUID = study_uid
        ds.StudyDate = now.strftime("%Y%m%d")
        ds.StudyTime = now.strftime("%H%M%S")
        ds.ReferringPhysicianName = ""
        ds.StudyID = patient.get("id", "")
        ds.AccessionNumber = ""

        # ── General Series Module (C.7.3.1) ───────────────────────────────
        exam = patient.get("exam", "Panoramic")
        is_ceph = exam.startswith("Ceph")
        ds.Modality = "DX" if is_ceph else "PX"  # DX for ceph, PX for panoramic
        ds.SeriesInstanceUID = series_uid
        ds.SeriesNumber = 1
        ds.SeriesDescription = exam

        # ── General Equipment Module (C.7.5.1) ────────────────────────────
        ds.Manufacturer = "Dentsply Sirona"
        ds.InstitutionName = ""
        ds.ManufacturerModelName = "Orthophos"
        ds.SoftwareVersions = "PureXS 1.0"
        ds.DeviceSerialNumber = ""

        # ── General Image Module (C.7.6.1) ────────────────────────────────
        ds.InstanceNumber = 1
        ds.ContentDate = now.strftime("%Y%m%d")
        ds.ContentTime = now.strftime("%H%M%S")
        ds.ImageType = ["ORIGINAL", "PRIMARY"]
        ds.AcquisitionDate = now.strftime("%Y%m%d")
        ds.AcquisitionTime = now.strftime("%H%M%S")

        # ── Image Pixel Module (C.7.6.3) ──────────────────────────────────
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.Rows = rows
        ds.Columns = cols
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 0  # unsigned
        ds.PlanarConfiguration = 0

        # Pixel data: DICOM expects little-endian uint16
        # Our scanlines are big-endian uint16 → byteswap to LE
        pixel_le = pixel_array.astype("<u2")
        ds.PixelData = pixel_le.tobytes()

        # ── DX Image Module (C.8.11.7) ────────────────────────────────────
        ds.KVP = f"{kv_peak:.1f}"
        ds.ExposureTime = str(exposure_time_ms)
        ds.Exposure = str(int(kv_peak * 8))  # mAs estimate
        ds.BodyPartExamined = "SKULL" if is_ceph else "JAW"
        view_positions = {"Ceph Lateral": "LAT", "Ceph Frontal": "AP"}
        ds.ViewPosition = view_positions.get(exam, "PA")
        ds.DistanceSourceToDetector = "1500" if is_ceph else "500"  # mm, ceph uses longer SID
        ds.DistanceSourceToPatient = "1350" if is_ceph else "400"   # mm

        # ── Pixel spacing & detector (from Sidexis reference DICOM) ───────
        if is_ceph:
            ds.PixelSpacing = [0.094549, 0.094549]         # calibrated at mid-plane
            ds.ImagerPixelSpacing = [0.104004, 0.104004]   # detector native
            ds.DetectorType = "SCINTILLATOR"
            ds.PatientOrientation = ["A", "F"]             # Anterior/Feet (lateral)
            ds.PresentationIntentType = "FOR PRESENTATION"

        # ── SOP Common Module (C.12.1) ────────────────────────────────────
        ds.SOPClassUID = DX_SOP_CLASS_UID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SpecificCharacterSet = "ISO_IR 100"

        # ── Write ────────────────────────────────────────────────────────
        # enforce_file_format=True is the pydicom v4+ replacement for
        # write_like_original=False.  Fall back for pydicom < 3.0.
        try:
            ds.save_as(str(dcm_path), enforce_file_format=True)
        except TypeError:
            ds.save_as(str(dcm_path), write_like_original=False)

        log.info("DICOM saved: %s (%d bytes)", dcm_path, dcm_path.stat().st_size)
        log.info(
            "  Patient: %s  Study: %s  Series: %s",
            ds.PatientName, study_uid[:40], series_uid[:40],
        )
        log.info(
            "  Image: %dx%d  16-bit  MONOCHROME2  kVP=%s",
            cols, rows, ds.KVP,
        )

        # ── Verify readback ──────────────────────────────────────────────
        self._verify(dcm_path, rows, cols)

        return str(dcm_path)

    def export_image(
        self,
        patient: dict[str, Any],
        image: Any,
        kv_peak: float,
        output_dir: str | Path,
        exposure_time_ms: int = 4000,
    ) -> str:
        """Export a processed image as DICOM.

        Accepts 8-bit (uint8) or 16-bit (uint16) grayscale input.
        The native dtype is preserved — uint16 is NOT downsampled to uint8.
        BitsAllocated/BitsStored/HighBit and WindowCenter/WindowWidth are
        set automatically based on the input dtype.

        Args:
            patient: Dict with keys: first, last, dob (MM/DD/YYYY), id, exam, set.
            image: PIL Image (mode "L" or "I;16") or numpy array (uint8/uint16).
            kv_peak: Peak kV recorded during the exposure.
            output_dir: Directory to write the .dcm file into.
            exposure_time_ms: Nominal exposure duration in milliseconds.

        Returns:
            Absolute path to the saved .dcm file.
        """
        if not HAS_PYDICOM:
            raise RuntimeError(
                "pydicom is required for DICOM export. "
                "Install with: pip install pydicom"
            )
        if not patient.get("set"):
            raise RuntimeError("Patient context not set — cannot export DICOM")

        pixel_array = np.array(image)
        if pixel_array.ndim != 2:
            raise RuntimeError(f"Expected 2D grayscale image, got shape {pixel_array.shape}")

        # Preserve native dtype — do NOT force-convert uint16 to uint8
        if pixel_array.dtype == np.uint16:
            bits = 16
        elif pixel_array.dtype == np.uint8:
            bits = 8
        else:
            # Coerce other dtypes to uint16 to avoid data loss
            pixel_array = np.clip(pixel_array, 0, 65535).astype(np.uint16)
            bits = 16

        rows, cols = pixel_array.shape
        log.info(
            "DICOM export (processed): patient=%s^%s  %dx%d  dtype=%s  %d-bit  kV=%.1f",
            patient["last"], patient["first"], cols, rows,
            pixel_array.dtype, bits, kv_peak,
        )
        print(
            f"[DICOM] Embedding pixel data: {cols}x{rows}  "
            f"dtype={pixel_array.dtype}  bits={bits}  "
            f"min={pixel_array.min()}  max={pixel_array.max()}  "
            f"mean={pixel_array.mean():.1f}"
        )

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        dob_nodash = patient["dob"].replace("/", "")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{patient['last']}_{patient['first']}_{dob_nodash}_{ts}.dcm"
        dcm_path = output_dir / filename

        file_meta = pydicom.dataset.FileMetaDataset()
        file_meta.FileMetaInformationVersion = b"\x00\x01"
        file_meta.MediaStorageSOPClassUID = DX_SOP_CLASS_UID
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.ImplementationClassUID = PUREXS_IMPLEMENTATION_CLASS_UID
        file_meta.ImplementationVersionName = PUREXS_IMPLEMENTATION_VERSION

        ds = FileDataset(
            str(dcm_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
        )

        now = datetime.now()

        # Patient Module
        ds.PatientName = f"{patient['last']}^{patient['first']}"
        ds.PatientID = patient.get("id", "")
        ds.PatientBirthDate = self._dob_to_dicom(patient.get("dob", ""))
        ds.PatientSex = ""

        # Study / Series
        ds.StudyInstanceUID = generate_uid()
        ds.StudyDate = now.strftime("%Y%m%d")
        ds.StudyTime = now.strftime("%H%M%S")
        ds.ReferringPhysicianName = ""
        ds.StudyID = patient.get("id", "")
        ds.AccessionNumber = ""
        exam = patient.get("exam", "Panoramic")
        is_ceph = exam.startswith("Ceph")
        ds.Modality = "DX" if is_ceph else "PX"
        ds.SeriesInstanceUID = generate_uid()
        ds.SeriesNumber = 1
        ds.SeriesDescription = exam

        # Equipment
        ds.Manufacturer = "Dentsply Sirona"
        ds.InstitutionName = ""
        ds.ManufacturerModelName = "Orthophos XG"
        ds.SoftwareVersions = "PureXS 1.0"

        # Image
        ds.InstanceNumber = 1
        ds.ContentDate = now.strftime("%Y%m%d")
        ds.ContentTime = now.strftime("%H%M%S")
        ds.ImageType = ["DERIVED", "PRIMARY"]
        ds.AcquisitionDate = now.strftime("%Y%m%d")
        ds.AcquisitionTime = now.strftime("%H%M%S")

        # Pixel Module
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"  # 0=black, processed image is display-ready
        ds.Rows = rows
        ds.Columns = cols
        ds.BitsAllocated = bits
        ds.BitsStored = bits
        ds.HighBit = bits - 1
        ds.PixelRepresentation = 0
        ds.PixelData = pixel_array.astype(f"<u{bits // 8}").tobytes()

        # Window/Level for 8-bit display
        if bits == 8:
            ds.WindowCenter = "128"
            ds.WindowWidth = "256"
        else:
            ds.WindowCenter = "32768"
            ds.WindowWidth = "65536"

        # DX-specific
        ds.KVP = f"{kv_peak:.1f}"
        ds.ExposureTime = str(exposure_time_ms)
        ds.BodyPartExamined = "SKULL" if is_ceph else "JAW"
        view_positions = {"Ceph Lateral": "LAT", "Ceph Frontal": "AP"}
        ds.ViewPosition = view_positions.get(exam, "PA")
        ds.DistanceSourceToDetector = "1500" if is_ceph else "500"
        ds.DistanceSourceToPatient = "1350" if is_ceph else "400"

        # Pixel spacing & detector (from Sidexis reference DICOM)
        if is_ceph:
            ds.PixelSpacing = [0.094549, 0.094549]
            ds.ImagerPixelSpacing = [0.104004, 0.104004]
            ds.DetectorType = "SCINTILLATOR"
            ds.PatientOrientation = ["A", "F"]
            ds.PresentationIntentType = "FOR PRESENTATION"

        # SOP Common
        ds.SOPClassUID = DX_SOP_CLASS_UID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SpecificCharacterSet = "ISO_IR 100"

        try:
            ds.save_as(str(dcm_path), enforce_file_format=True)
        except TypeError:
            ds.save_as(str(dcm_path), write_like_original=False)

        log.info("DICOM saved: %s (%d bytes)", dcm_path, dcm_path.stat().st_size)
        self._verify(dcm_path, rows, cols)
        return str(dcm_path)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _build_pixel_array(scanline_buffer: list[Any]) -> np.ndarray:
        """Stitch scanlines into a 2D uint16 array.

        Each scanline becomes one column of the output image.
        Scanlines with inconsistent pixel counts are padded/truncated
        to match the most common count.
        """
        if not scanline_buffer:
            return np.zeros((0, 0), dtype=np.uint16)

        # Determine target height (most common pixel count)
        counts: dict[int, int] = {}
        for sl in scanline_buffer:
            pc = sl.pixel_count
            counts[pc] = counts.get(pc, 0) + 1
        target_h = max(counts, key=counts.get)

        valid = [sl for sl in scanline_buffer if sl.pixel_count == target_h]
        if not valid:
            valid = scanline_buffer  # fallback: use all

        width = len(valid)
        height = target_h

        arr = np.zeros((height, width), dtype=np.uint16)
        for col, sl in enumerate(valid):
            pixels = sl.pixels
            n = min(len(pixels), height)
            arr[:n, col] = pixels[:n]

        return arr

    @staticmethod
    def _dob_to_dicom(dob_str: str) -> str:
        """Convert MM/DD/YYYY to DICOM DA format YYYYMMDD."""
        dob_str = dob_str.strip()
        if not dob_str:
            return ""
        try:
            dt = datetime.strptime(dob_str, "%m/%d/%Y")
            return dt.strftime("%Y%m%d")
        except ValueError:
            log.warning("Invalid DOB format: %r (expected MM/DD/YYYY)", dob_str)
            return ""

    @staticmethod
    def _verify(dcm_path: Path, expected_rows: int, expected_cols: int) -> None:
        """Read back and verify critical DICOM tags."""
        try:
            ds = pydicom.dcmread(str(dcm_path))
            assert ds.Rows == expected_rows, f"Rows mismatch: {ds.Rows} != {expected_rows}"
            assert ds.Columns == expected_cols, f"Cols mismatch: {ds.Columns} != {expected_cols}"
            assert ds.BitsAllocated in (8, 16)
            assert ds.SamplesPerPixel == 1
            pixel_len = len(ds.PixelData)
            bpp = ds.BitsAllocated // 8
            expected_len = expected_rows * expected_cols * bpp
            assert pixel_len == expected_len, (
                f"PixelData length {pixel_len} != expected {expected_len}"
            )
            log.info("DICOM verification PASSED: %s", dcm_path.name)
        except Exception as exc:
            log.error("DICOM verification FAILED: %s — %s", dcm_path.name, exc)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  CLI
# ╚══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="dicom_export",
        description="PureXS DICOM Export — convert panoramic scan to DICOM DX",
    )
    parser.add_argument("--first", default="Test", help="Patient first name")
    parser.add_argument("--last", default="Patient", help="Patient last name")
    parser.add_argument("--dob", default="01/01/1990", help="DOB (MM/DD/YYYY)")
    parser.add_argument("--id", default="test001", help="Patient ID")
    parser.add_argument("--exam", default="Panoramic", help="Exam type")
    parser.add_argument("--kv", type=float, default=70.0, help="Peak kV")
    parser.add_argument(
        "--scanlines", default="test",
        help="'test' for synthetic data, or path to raw scanline binary",
    )
    parser.add_argument("--outdir", "-o", default="./dicom_out", help="Output directory")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(message)s")

    if not HAS_PYDICOM:
        print("ERROR: pydicom not installed. Run: pip install pydicom", file=sys.stderr)
        return 1

    patient = {
        "first": args.first, "last": args.last, "dob": args.dob,
        "id": args.id, "exam": args.exam, "set": True,
    }

    # Build image from source
    if args.scanlines == "test":
        print("Using synthetic test image (1280x2440)")

        class MockScanline:
            def __init__(self, sid: int, count: int = 240):
                self.scanline_id = sid
                self.pixel_count = count
                base = np.linspace(500, 8000, count, dtype=np.uint16)
                noise = np.random.randint(0, 200, count, dtype=np.uint16)
                self.pixels = base + noise

        scanline_buffer = [MockScanline(0x40 + i) for i in range(13)]
        exporter = PureXSDICOM()
        dcm_path = exporter.export(patient, scanline_buffer, args.kv, args.outdir)
    else:
        # Load from raw scan buffer and run full processing pipeline
        raw_path = Path(args.scanlines)
        if not raw_path.exists():
            print(f"ERROR: File not found: {raw_path}", file=sys.stderr)
            return 1

        print(f"Loading raw scan: {raw_path} ({raw_path.stat().st_size} bytes)")

        # Import the processing pipeline
        try:
            from hb_decoder import _extract_panoramic, reconstruct_image
        except ImportError:
            print("ERROR: hb_decoder.py not found in path", file=sys.stderr)
            return 1

        with open(raw_path, "rb") as f:
            raw_data = f.read()
        scanlines = _extract_panoramic(raw_data)
        image = reconstruct_image(scanlines)

        if image is None:
            print("ERROR: Image reconstruction failed", file=sys.stderr)
            return 1

        print(f"Processed image: {image.size[0]}x{image.size[1]}")

        exporter = PureXSDICOM()
        dcm_path = exporter.export_image(patient, image, args.kv, args.outdir)

    print(f"\nDICOM exported: {dcm_path}")

    # Quick readback test
    ds = pydicom.dcmread(dcm_path)
    print(f"  PatientName:      {ds.PatientName}")
    print(f"  PatientID:        {ds.PatientID}")
    print(f"  PatientBirthDate: {ds.PatientBirthDate}")
    print(f"  Modality:         {ds.Modality}")
    print(f"  Image:            {ds.Columns}x{ds.Rows} {ds.BitsAllocated}-bit")
    print(f"  Photometric:      {ds.PhotometricInterpretation}")
    print(f"  KVP:              {ds.KVP}")
    print(f"  BodyPart:         {ds.BodyPartExamined}")
    print(f"  SOPClass:         {ds.SOPClassUID}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
