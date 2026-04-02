#!/usr/bin/env python3
"""
PureXS HB Decoder — Sirona Orthophos P2K wire protocol decoder.

Parses Wireshark text dumps from Sirona ORTHOPHOS (192.168.139.170:12837)
to extract:
  - Session handshake frames  (0x20xx / 0x21xx / 0x10xx func codes)
  - Heartbeat (HB) keep-alive pairs  (0x200B request / 0x200C response)
  - kV ramp-up table during exposure  (f4 53 markers = kV=500 threshold)
  - Exposure trigger point  (ff 12 pattern = kV at max)
  - Scanline image data  (16-bit BE pixel blocks with NN 00 01 00 f0 headers)
  - Event log messages  (Recording started/stopped, Imagetransfer, Released)
  - E7 14 02 ERR_SIDEXIS_API error sequences (treat as post-scan success)

Also provides a LIVE TCP client for real-time device monitoring.

Wire format (confirmed from ff.txt Wireshark capture):
  Session header: 20 bytes, big-endian
    +0x00  BYTE   func_hi        command family (0x20=session, 0x10=data, 0x21=caps)
    +0x01  BYTE   func_lo        sub-command
    +0x02  WORD   magic          0x072D
    +0x04  WORD   port           0x07D0 = 2000
    +0x06  WORD   version        0x0001
    +0x08  WORD   flags          0x000E or 0x000F
    +0x0A  10B    reserved       zeros
  HB pair: func=0x200B (host→device), func=0x200C (device→host), 20B each
  kV ramp data: repeating 15-byte records in 1460B TCP segments:
    +0x00  BYTE   01             record marker
    +0x01  WORD   kV_raw         tube voltage (big-endian)
    +0x03  BYTE   01             separator
    +0x04  WORD   field2         exposure-related counter
    +0x06  BYTE   01             separator
    +0x07  WORD   field3         ramp value (rises to ff 12 = expose trigger)
    +0x09  BYTE   01             separator
    +0x0A  WORD   counter        monotonic position counter (big-endian)
    +0x0C  BYTE   0E             record type marker
    +0x0D  BYTE   01             fixed
    +0x0E  varies zeros/flags
  Scanline header (within image data stream):
    4B     preamble     varies (checksum / metadata)
    BYTE   01           marker
    BYTE   scanline_id  increments 0x40, 0x41, 0x42 ...
    BYTE   00           separator
    BYTE   01           marker
    WORD   pixel_count  0x00F0 = 240 pixels per scanline
    WORD   row_param    0x0034 = 52 (row metadata)
    N×WORD pixels       16-bit big-endian grayscale values

Usage:
    # Parse a Wireshark dump
    python hb_decoder.py parse /path/to/ff.txt --outdir ./decoded

    # Live monitor (connects to Sirona device)
    python hb_decoder.py live --host 192.168.139.170 --port 12837

    # Quick summary of a dump
    python hb_decoder.py summary /path/to/ff.txt
"""

from __future__ import annotations

import argparse
import io
import logging
import os
import re
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import numpy as np
from PIL import Image

# ── Logging ──────────────────────────────────────────────────────────────────

from utils import get_data_dir

LOG_DIR = get_data_dir()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "hb_decoder.log", encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
log = logging.getLogger("hb_decoder")


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Protocol Constants (confirmed from ff.txt analysis)
# ╚══════════════════════════════════════════════════════════════════════════════

# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Diagnostic State
# ╚══════════════════════════════════════════════════════════════════════════════
_fill_call_count = 0

def _verify_fill_written(result_segment, bs, be, predicted):
    """Q4 Check: Spot-check that predicted values were actually written to the result."""
    written = []
    for byte_pos in range(bs, be, 2):
        if byte_pos + 1 < len(result_segment):
            val = (result_segment[byte_pos] << 8) | result_segment[byte_pos + 1]
            written.append(val)
    expected = [int(p) for p in predicted[:len(written)]]
    match = sum(1 for w, e in zip(written, expected) if abs(w-e) < 5)
    print(f"[FILL VERIFY] {match}/{len(written)} pixels correctly written")
    if match < len(written) * 0.9:
        print("  WARNING: Fill writes are not persisting in result_segment!")
        print(f"  First 5 written: {written[:5]}")
        print(f"  First 5 expected: {expected[:5]}")


MAGIC = 0x072D
PORT_MARKER = 0x07D0  # 2000 decimal — appears in every session frame

# Session frame function codes (byte[0] << 8 | byte[1])
FC_SESSION_OPEN_REQ = 0x205C   # SYN-like: host opens session
FC_SESSION_OPEN_ACK = 0x205D   # device acknowledges session
FC_SESSION_INIT = 0x2001       # host sends session params
FC_SESSION_CONFIRM = 0x2002    # device confirms with session_id + flags
FC_HB_REQUEST = 0x200B         # heartbeat request (host → device)
FC_HB_RESPONSE = 0x200C        # heartbeat response (device → host)
FC_HB_STATUS_REQ = 0x200D     # status poll (host → device, required every 5 HBs)
FC_HB_STATUS_RESP = 0x200E    # status poll response (device → host)
FC_CAPS_REQ = 0x2110           # capabilities request
FC_CAPS_RESP = 0x2111          # capabilities response (38 bytes)
FC_DATA_SEND = 0x1000          # host sends patient/exam data (176 bytes)
FC_DATA_ACK = 0x1001           # device acks patient data
FC_DATA_ACK = 0x1001           # device acks patient data
FC_STATUS_RESP = 0x1002        # status response with kV ramp data
FC_EXPOSE_NOTIFY = 0x1005      # device → host: exposure starting (physical button)
FC_IMAGE_ACK = 0x1008          # host → device: image data received
FC_IMAGE_ACK_RESP = 0x1009     # device → host: ack of image ack

# Device readiness status codes (returned in status query response payload)
DEVICE_STATUS_READY  = 0x0000
DEVICE_STATUS_BUSY   = 0x0001
DEVICE_STATUS_ERROR  = 0x0002
DEVICE_STATUS_WARMUP = 0x0003

SESSION_HEADER_SIZE = 20

# kV ramp record structure
KV_RECORD_SIZE = 15            # bytes per kV sample in ramp data
EXPOSE_TRIGGER_KV_HI = 0xFF   # ff XX pattern = tube at full voltage
KV_THRESHOLD_MARKER = 0xF453  # f4 53 = 62547 decimal — seen during ramp-up

# Scanline image structure
SCANLINE_MARKER = b'\x00\x01\x00\xf0'   # pixel_count=240 as BE word
SCANLINE_PIXELS = 0x00F0                 # 240 pixels per row
SCANLINE_ROW_PARAM = 0x0034             # row metadata = 52
PIXEL_BYTES = 2                          # 16-bit big-endian per pixel

# ── Panoramic image extraction constants (from ff.txt Wireshark analysis) ────
#
# The Orthophos XG (DX41) sends the full detector readout as a continuous
# 16-bit big-endian pixel stream, split across 0x1003 continuation frames.
#
# Each 0x1003 frame is 65 586 bytes total:
#   +0x00  20 B   session header   (func=0x1003, magic, port, flags)
#   +0x14  30 B   echo payload     (FC 30 ... 80 00 — patient config echo)
#   +0x32  var    pixel data       (continuous 16-bit BE pixels)
#
# The very first 0x1003 frame has an extra 8-byte padding block between
# the echo and the pixel data:  00 00 00 01 00 00 00 34.
#
# Before the pixel stream, the initial 0x1002 data frame contains:
#   - Patient echo (~350 B)
#   - kV ramp records (~2–5 KB)
#   - Position/status telemetry records
#   - Transition marker: D6 D6 4C 1F + 8 B header
#   - Then continuous pixel data begins
#
# The device 0x00 bytes appear as 0x20 in the TCP stream received by the
# host (observed consistently — echo, padding, and telemetry all show this).
#
# Image dimensions are reported in the post-scan 0x1004 frame:
#   offset +0x0A  WORD  height  (0x0524 = 1316 for ORTHOPHOS XG)
#   offset +0x0C  WORD  width   (0x0A92 = 2706 for ORTHOPHOS XG)
#
# Default panoramic dimensions (DX41 / ORTHOPHOS XG):
PANO_DEFAULT_WIDTH  = 2706
PANO_DEFAULT_HEIGHT = 1316

# Per-0x1003-frame overhead
ECHO_PAYLOAD_SIZE = 30           # FC 30 … 80 00 patient config echo (minimum)
ECHO_PAYLOAD_MAX  = 200          # upper bound — some frames carry extra kV telemetry
FIRST_FRAME_PADDING = 8          # 00 00 00 01 00 00 00 34 (first frame only)

# Pixel stream transition marker (signals end of kV ramp, start of pixels)
PIXEL_TRANSITION_MARKER = b'\xd6\xd6\x4c'

# Inline scanline marker embedded in the pixel stream (8 bytes)
#   01 <scanline_id> 00 01 00 F0 00 34
_INLINE_SCANLINE_HDR = b'\x00\x01\x00\xf0\x00\x34'  # tail 6 bytes of the 8-byte marker

# Event log patterns (ASCII in TCP payload)
RE_RECORDING_START = re.compile(
    rb"Recording started - Value: (\d+)", re.IGNORECASE
)
RE_RECORDING_STOP = re.compile(rb"Recording stopped", re.IGNORECASE)
RE_IMAGE_TRANSFER_START = re.compile(rb"Imagetransfer started", re.IGNORECASE)
RE_IMAGE_TRANSFER_STOP = re.compile(rb"Imagetransfer stopped", re.IGNORECASE)
RE_STATE_RELEASED = re.compile(
    rb"Image state switched to Released", re.IGNORECASE
)
RE_E7_ERROR = re.compile(
    rb"E7 14 02 \(ERR_SIDEXIS_API\)", re.IGNORECASE
)
RE_TIMESTAMP = re.compile(
    rb"(\d{4}-\d{2}-\d{2}, \d{2}:\d{2}:\d{2})"
)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Data Classes
# ╚══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionFrame:
    """One parsed P2K session-layer frame."""
    frame_no: int
    timestamp: float
    direction: str          # "C2S" (client→server) or "S2C" (server→client)
    func_code: int
    func_name: str
    payload_len: int
    raw_header: bytes
    raw_payload: bytes

    @property
    def is_hb(self) -> bool:
        return self.func_code in (FC_HB_REQUEST, FC_HB_RESPONSE)


@dataclass
class KVSample:
    """One kV ramp sample from the exposure data stream."""
    position: int           # monotonic counter from record
    kv_raw: int             # raw 16-bit kV value
    field2: int             # exposure counter
    field3: int             # ramp value (rises to 0xFF12 at trigger)

    @property
    def is_expose_trigger(self) -> bool:
        """True when field3 reaches ff XX (tube at full voltage)."""
        return (self.field3 >> 8) == EXPOSE_TRIGGER_KV_HI


@dataclass
class Scanline:
    """One decoded image scanline."""
    scanline_id: int
    pixel_count: int
    pixels: np.ndarray      # uint16 array, length = pixel_count

    @property
    def pixels_8bit(self) -> np.ndarray:
        """Normalize to 8-bit for display."""
        if self.pixels.max() == 0:
            return np.zeros(len(self.pixels), dtype=np.uint8)
        norm = self.pixels.astype(np.float32) / self.pixels.max() * 255
        return norm.astype(np.uint8)


@dataclass
class ScanEvent:
    """Timeline event extracted from embedded ASCII log messages."""
    timestamp_str: str
    event_type: str         # "recording_start", "recording_stop", etc.
    detail: str = ""


@dataclass
class DecodedCapture:
    """Complete decoded capture file."""
    frames: list[SessionFrame] = field(default_factory=list)
    hb_pairs: list[tuple[SessionFrame, SessionFrame]] = field(default_factory=list)
    kv_samples: list[KVSample] = field(default_factory=list)
    scanlines: list[Scanline] = field(default_factory=list)
    events: list[ScanEvent] = field(default_factory=list)
    expose_trigger_idx: int = -1
    repair_mask: np.ndarray | None = None


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Wireshark Text Dump Parser
# ╚══════════════════════════════════════════════════════════════════════════════

# Matches hex data lines:  "0000  20 5c 07 2d ..."
_HEX_LINE = re.compile(
    r"^([0-9a-f]{4})  ((?:[0-9a-f]{2} ){1,16})"
)
# Matches frame info line with PSH flag (data-bearing):
_FRAME_INFO = re.compile(
    r"Frame (\d+):.*?(\d+) bytes"
)
_TCP_INFO = re.compile(
    r"Src Port: (\d+), Dst Port: (\d+).*?Seq: (\d+).*?Len: (\d+)"
)
_TIME_INFO = re.compile(
    r"^\s+\d+ ([\d.]+)\s+(\S+)\s+(\S+)"
)


def _parse_hex_block(lines: list[str]) -> bytes:
    """Parse contiguous Wireshark hex dump lines into raw bytes."""
    result = bytearray()
    for line in lines:
        m = _HEX_LINE.match(line.rstrip())
        if m:
            hex_part = m.group(2).strip()
            result.extend(bytes.fromhex(hex_part.replace(" ", "")))
    return bytes(result)


def parse_wireshark_dump(path: str | Path) -> DecodedCapture:
    """Parse a Wireshark text export and extract all protocol elements."""
    path = Path(path)
    log.info("Parsing %s (%s)", path.name, _human_size(path.stat().st_size))

    capture = DecodedCapture()
    current_hex_lines: list[str] = []
    current_frame_no = 0
    current_time = 0.0
    current_src_port = 0
    current_dst_port = 0
    current_data_len = 0
    in_data_section = False

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f, 1):
            line = raw_line.rstrip()

            # Frame header
            fm = _FRAME_INFO.match(line)
            if fm:
                # Flush previous hex block
                if current_hex_lines and current_data_len > 0:
                    _process_hex_block(
                        capture, current_hex_lines, current_frame_no,
                        current_time, current_src_port, current_dst_port,
                    )
                current_hex_lines = []
                current_frame_no = int(fm.group(1))
                in_data_section = False
                continue

            # Timestamp + IP info
            tm = _TIME_INFO.match(line)
            if tm:
                try:
                    current_time = float(tm.group(1))
                except ValueError:
                    pass
                continue

            # TCP info
            ti = _TCP_INFO.search(line)
            if ti:
                current_src_port = int(ti.group(1))
                current_dst_port = int(ti.group(2))
                current_data_len = int(ti.group(4))
                continue

            # Data section marker
            if line.startswith("Data ("):
                in_data_section = True
                current_hex_lines = []
                continue

            # Hex data line
            if in_data_section and _HEX_LINE.match(line):
                current_hex_lines.append(line)
                continue

            # Inside data section: skip blank lines (Wireshark puts one
            # between the "Data (N bytes)" header and the hex dump)
            if in_data_section and line.strip() == "":
                # Only end the section if we already collected hex lines
                if current_hex_lines:
                    _process_hex_block(
                        capture, current_hex_lines, current_frame_no,
                        current_time, current_src_port, current_dst_port,
                    )
                    current_hex_lines = []
                    in_data_section = False
                # Otherwise keep waiting for hex lines
                continue

            # Any non-hex, non-blank line ends the data section
            if in_data_section:
                if current_hex_lines:
                    _process_hex_block(
                        capture, current_hex_lines, current_frame_no,
                        current_time, current_src_port, current_dst_port,
                    )
                    current_hex_lines = []
                in_data_section = False

    # Flush final block
    if current_hex_lines:
        _process_hex_block(
            capture, current_hex_lines, current_frame_no,
            current_time, current_src_port, current_dst_port,
        )

    # Post-process: pair HB request/response
    _pair_heartbeats(capture)

    log.info(
        "Parsed: %d frames, %d HB pairs, %d kV samples, "
        "%d scanlines, %d events",
        len(capture.frames), len(capture.hb_pairs),
        len(capture.kv_samples), len(capture.scanlines),
        len(capture.events),
    )
    return capture


def _process_hex_block(
    capture: DecodedCapture,
    hex_lines: list[str],
    frame_no: int,
    timestamp: float,
    src_port: int,
    dst_port: int,
) -> None:
    """Decode one hex payload block and add results to capture."""
    raw = _parse_hex_block(hex_lines)
    if not raw:
        return

    direction = "C2S" if src_port == 50930 else "S2C"

    # ── 1. Session-layer frames (20-byte header with 07 2D magic) ────────
    if (
        len(raw) >= SESSION_HEADER_SIZE
        and len(raw) <= 300
        and raw[2:4] == b'\x07\x2d'
    ):
        func_code = (raw[0] << 8) | raw[1]
        func_name = _fc_name(func_code)
        payload = raw[SESSION_HEADER_SIZE:]

        frame = SessionFrame(
            frame_no=frame_no,
            timestamp=timestamp,
            direction=direction,
            func_code=func_code,
            func_name=func_name,
            payload_len=len(payload),
            raw_header=raw[:SESSION_HEADER_SIZE],
            raw_payload=payload,
        )
        capture.frames.append(frame)
        return

    # For large data payloads, try all extractors (they can coexist)

    # ── 2. kV ramp data (large payloads with repeating 15-byte records) ──
    if len(raw) > 50:
        samples = _extract_kv_samples(raw)
        for s in samples:
            if s.is_expose_trigger and capture.expose_trigger_idx < 0:
                capture.expose_trigger_idx = len(capture.kv_samples)
                log.info(
                    "EXPOSE TRIGGER at position %d (ff %02x)",
                    s.position, s.field3 & 0xFF,
                )
            capture.kv_samples.append(s)

    # ── 3. Scanline image data ───────────────────────────────────────────
    scanlines = _extract_scanlines(raw)
    if scanlines:
        capture.scanlines.extend(scanlines)

    # ── 4. ASCII event log messages ──────────────────────────────────────
    events = _extract_events(raw)
    capture.events.extend(events)


def _fc_name(fc: int) -> str:
    """Human name for a function code."""
    names = {
        FC_SESSION_OPEN_REQ: "SESSION_OPEN_REQ",
        FC_SESSION_OPEN_ACK: "SESSION_OPEN_ACK",
        FC_SESSION_INIT: "SESSION_INIT",
        FC_SESSION_CONFIRM: "SESSION_CONFIRM",
        FC_HB_REQUEST: "HB_REQUEST",
        FC_HB_RESPONSE: "HB_RESPONSE",
        FC_HB_STATUS_REQ: "HB_STATUS_REQ",
        FC_HB_STATUS_RESP: "HB_STATUS_RESP",
        FC_CAPS_REQ: "CAPS_REQ",
        FC_CAPS_RESP: "CAPS_RESP",
        FC_DATA_SEND: "DATA_SEND",
        FC_DATA_ACK: "DATA_ACK",
        FC_STATUS_RESP: "STATUS_RESP",
        FC_EXPOSE_NOTIFY: "EXPOSE_NOTIFY",
        FC_IMAGE_ACK: "IMAGE_ACK",
        FC_IMAGE_ACK_RESP: "IMAGE_ACK_RESP",
    }
    return names.get(fc, f"0x{fc:04X}")


def _contains_kv_records(data: bytes) -> bool:
    """Heuristic: does this payload contain kV ramp sample records?

    kV records have a repeating pattern:
      01 XX XX 01 YY YY 01 ZZ ZZ 01 WW WW 0E 01
    with 0E as a record-type marker appearing every ~15 bytes.
    """
    if len(data) < 30:
        return False
    # Count 0E 01 pairs — kV records have these every ~15 bytes
    marker = b'\x0e\x01'
    count = 0
    idx = 0
    while True:
        idx = data.find(marker, idx)
        if idx < 0:
            break
        count += 1
        idx += 2
    # Need at least 5 records to qualify
    return count >= 5 and count > len(data) // 20


def _extract_kv_samples(data: bytes) -> list[KVSample]:
    """Extract kV ramp samples from a data payload.

    Record pattern (15 bytes):
      01 KV_HI KV_LO 01 F2_HI F2_LO 01 F3_HI F3_LO 01 CNT_HI CNT_LO 0E 01 ...
    """
    samples = []
    # Find all 0E 01 markers and work backward to find record starts
    idx = 0
    while idx < len(data) - KV_RECORD_SIZE:
        # Look for the 0E 01 marker that ends each record
        marker_pos = data.find(b'\x0e\x01', idx)
        if marker_pos < 0 or marker_pos < 12:
            break

        # Record starts 12 bytes before the 0E marker
        rec_start = marker_pos - 12
        if rec_start < 0:
            idx = marker_pos + 2
            continue

        rec = data[rec_start:marker_pos + 2]
        if len(rec) < 14:
            idx = marker_pos + 2
            continue

        # Validate structure: bytes at positions 0, 3, 6, 9 should be 0x01
        if rec[0] == 0x01 and rec[3] == 0x01 and rec[6] == 0x01 and rec[9] == 0x01:
            kv_raw = (rec[1] << 8) | rec[2]
            field2 = (rec[4] << 8) | rec[5]
            field3 = (rec[7] << 8) | rec[8]
            counter = (rec[10] << 8) | rec[11]

            samples.append(KVSample(
                position=counter,
                kv_raw=kv_raw,
                field2=field2,
                field3=field3,
            ))

        idx = marker_pos + 2

    return samples


def _extract_scanlines(data: bytes) -> list[Scanline]:
    """Extract 16-bit scanlines from image data blocks.

    Scanline header pattern:
      [preamble] 01 SCANLINE_ID 00 01 00 F0 00 34 [240 × 2 bytes pixel data]
    """
    scanlines = []
    idx = 0
    while idx < len(data) - 10:
        pos = data.find(SCANLINE_MARKER, idx)
        if pos < 0:
            break

        # The scanline_id is 2 bytes before the marker
        if pos < 2:
            idx = pos + 4
            continue

        scanline_id = data[pos - 1]
        marker_byte = data[pos - 2]

        # Verify the 01 marker byte
        if marker_byte != 0x01:
            idx = pos + 4
            continue

        # Read row parameter (2 bytes after the 00 F0 marker)
        param_offset = pos + 4
        if param_offset + 2 > len(data):
            break
        row_param = (data[param_offset] << 8) | data[param_offset + 1]

        # Pixel data starts after the row parameter
        pixel_start = param_offset + 2
        pixel_byte_count = SCANLINE_PIXELS * PIXEL_BYTES

        if pixel_start + pixel_byte_count > len(data):
            # Partial scanline at end of payload — take what we can
            available = len(data) - pixel_start
            pixel_count = available // PIXEL_BYTES
            if pixel_count < 10:
                idx = pos + 4
                continue
        else:
            pixel_count = SCANLINE_PIXELS

        pixel_data = data[pixel_start:pixel_start + pixel_count * PIXEL_BYTES]
        pixels = np.frombuffer(pixel_data, dtype=">u2")  # big-endian uint16

        scanlines.append(Scanline(
            scanline_id=scanline_id,
            pixel_count=len(pixels),
            pixels=pixels,
        ))

        idx = pixel_start + len(pixel_data)

    return scanlines


# ── Session header signature for stripping embedded headers ───────────
_SESSION_SIG = b'\x07\x2d\x07\xd0'   # MAGIC + PORT at offsets 2-5


def _strip_session_headers(data: bytes) -> bytes:
    """Strip ALL 20-byte P2K session headers AND their echo payloads
    from the raw TCP stream.

    Each 0x1003 frame structure:
      [0x1003 = 2B][magic 07 2D 07 D0 = 4B][flags/port = 14B] = 20B header
      [echo payload = 30B for normal frames, 30+8*N for telemetry frames]
      [pixel data = remainder of frame up to next header]

    Echo payload sizes (confirmed from live capture analysis):
      Normal frames (frame_index % 10 != 0): exactly 30 bytes
      Telemetry frames (frame_index % 10 == 0): 30 + 8*(N//10 + 1) bytes
      where N = frame_index (0-based)
    """
    result      = bytearray()
    idx         = 0
    frame_index = 0

    while idx < len(data):
        # Find next session header
        pos = data.find(_SESSION_SIG, idx)
        if pos < 0:
            # No more headers — append remaining bytes as pixel data
            result.extend(data[idx:])
            break

        hdr_start = pos - 2
        if hdr_start < idx:
            result.extend(data[idx:pos + 4])
            idx = pos + 4
            continue

        # Validate it's a real header
        func_hi = data[hdr_start] if hdr_start >= 0 else 0
        if func_hi not in (0x10, 0x20, 0x21):
            result.extend(data[idx:pos + 4])
            idx = pos + 4
            continue

        # Append pixel data before this header
        result.extend(data[idx:hdr_start])

        # Skip 20-byte session header
        payload_start = hdr_start + SESSION_HEADER_SIZE

        # Skip echo payload based on frame index
        if func_hi == 0x10 and hdr_start + 1 < len(data) and data[hdr_start + 1] == 0x03:
            # 0x1003 continuation frame — has echo payload
            echo_size = 30 + (8 * (frame_index // 10 + 1)) \
                        if frame_index % 10 == 0 else 30
            echo_size = min(echo_size, 200)  # safety cap
            payload_start += echo_size
            frame_index += 1

        idx = payload_start

    # VALIDATION: remainder must be 0
    total_px  = len(result) // 2
    remainder = total_px % PANO_DEFAULT_HEIGHT
    if remainder != 0:
        # Trim tail to nearest 1316-row boundary
        trim = remainder * 2
        log.warning("Strip remainder=%d pixels — trimming %d tail bytes",
                    remainder, trim)
        result = result[:-trim]

    return bytes(result)


def _detect_echo_end(payload: bytes, min_echo: int = 30,
                     max_scan: int = 200, frame_index: int = -1) -> int:
    """Return the byte offset where pixel data begins inside a 0x1003 payload.

    The device embeds kV telemetry in every 10th 0x1003 frame.  The
    telemetry block follows the 30-byte FC30 echo and always ends with
    the signature ``... 0x0001 XXXX 0x0034`` (row parameter = 52).

    For non-telemetry frames the standard 30-byte echo applies.

    Detection strategy:
      - If frame_index is known and frame is NOT a telemetry frame
        (N%10 != 0), return exactly 30 bytes (deterministic).
      - For telemetry frames (N%10 == 0), search for the ``0x0034``
        row-parameter anchor preceded by ``0x0001``.
      - Fallback: value-based heuristic scan (only when frame_index
        is unknown).
    """
    # ── Deterministic path: non-telemetry frames always have 30-byte echo
    if frame_index >= 0 and frame_index % 10 != 0:
        return 30

    # ── Pass 1: structural anchor (0x0001 … 0x0034) ──────────────────
    #   Only search within a narrow window. Fallback to formula.
    ANCHOR_LIMIT = min(150, max_scan, len(payload) - 1)
    found_echo = -1
    for off in range(30, ANCHOR_LIMIT):
        # Explicit 0x0001 .... 0x0034 check
        if payload[off+1] == 0x34 and payload[off] in (0x00, 0x20):
            if off >= 4 and payload[off-3] == 0x01 and payload[off-4] in (0x00, 0x20):
                found_echo = off + 2
                break
                
    if frame_index >= 0 and frame_index % 10 == 0:
        # Formula-driven expectation for telemetry frames
        expected = 30 + (frame_index // 10 + 1) * 8
        # Prefer found anchor if close, otherwise trust formula
        if found_echo > 0 and abs(found_echo - expected) < 16:
            return found_echo
        return expected
    
    # Non-telemetry frames (N%10 != 0) are strictly 30 bytes
    return 30

    # ── Telemetry frame but anchor not found — use formula as fallback
    if frame_index >= 0 and frame_index % 10 == 0:
        expected = 30 + (frame_index // 10 + 1) * 8
        log.warning("Frame %d: no anchor found, using formula echo=%d",
                    frame_index, expected)
        return expected

    # ── Pass 2: value-based heuristic (only for unknown frame index) ──
    RUN = 20
    PIXEL_MIN = 0x0600
    ZERO_SCAN = 100
    ZERO_THRESH = 0x0200

    limit = min(max_scan, len(payload) - RUN * 2)
    for off in range(min_echo, limit, 2):
        ok = True
        for j in range(RUN):
            val = (payload[off + j * 2] << 8) | payload[off + j * 2 + 1]
            if val < PIXEL_MIN:
                ok = False
                break
        if not ok:
            continue
        zero_count = 0
        scan_end = min(off + ZERO_SCAN, len(payload) - 1)
        for k in range(off, scan_end, 2):
            v = (payload[k] << 8) | payload[k + 1]
            if v < ZERO_THRESH:
                zero_count += 1
                if zero_count >= 2:
                    break
        if zero_count < 2:
            return off
    return min_echo  # fallback


# ── Telemetry block ADC offsets ──────────────────────────────────────────────
#
# The 72-byte telemetry block structure (36 × BE uint16 words):
#
#   Word  0     : position counter (column index in scan)
#   Words 1–3   : kV/mA exposure metadata
#   Words 4–6   : detector status / frame counter
#   Words 7–27  : 21 × ADC reference pixel readings (light references at
#                 fixed row positions on the detector, read every frame)
#   Words 28–32 : checksum / reserved
#   Word  33    : scan-line row-position word (XX XX in tail sig)
#   Words 34–35 : tail marker bytes (00/20 01 … 00/20 34)
#
# The ADC reference pixels are the detector's built-in calibration pixels —
# they receive a fixed amount of light from an LED source inside the sensor
# housing calibrated during manufacture.  Their readings therefore encode
# the detector's real-time gain and offset at the instant of the frame.
#
# Byte layout within the 72 bytes (0-indexed):
_TELEM_ADC_WORD_START = 7    # first ADC reference word index
_TELEM_ADC_WORD_COUNT = 21   # number of ADC reference words
_TELEM_COL_WORD       = 0    # column position word index
_TELEM_KV_WORD        = 1    # kV word index

# Cache for the flat-field 2-D array so we only load it once per process
_FF2D_CACHE: np.ndarray | None = None
_FF2D_MEAN:  float = 0.0


def _load_flat_field_2d() -> tuple[np.ndarray | None, float]:
    """Load the full 2-D flat-field array from flat_field_raw.bin.

    The file lives in the data directory (~/.purexs/ or %APPDATA%/PureXS)
    and, if not found there, falls back to the parent of the source tree
    (the location used during development).  Returns a float32 array with
    shape (height, width) normalised so that the mean over a centre crop
    equals 1.0, plus the raw mean pixel value used for renormalisation.

    Returns (None, 0.0) when the file cannot be found or loaded.
    """
    global _FF2D_CACHE, _FF2D_MEAN
    if _FF2D_CACHE is not None:
        return _FF2D_CACHE, _FF2D_MEAN

    search_paths = [
        get_data_dir() / "flat_field_raw.bin",
        Path(__file__).parent.parent / "flat_field_raw.bin",  # dev tree sibling
        Path(__file__).parent / "flat_field_raw.bin",
    ]
    ff_path: Path | None = None
    for p in search_paths:
        if p.exists():
            ff_path = p
            break

    if ff_path is None:
        log.debug("flat_field_raw.bin not found — calibration-driven fill disabled")
        return None, 0.0

    try:
        raw = np.fromfile(str(ff_path), dtype=">u2")  # big-endian uint16
        total = raw.size
        # Try to reshape using the known detector dimensions
        H, W = PANO_DEFAULT_HEIGHT, PANO_DEFAULT_WIDTH
        if total >= H * W:
            arr = raw[:H * W].reshape(H, W).astype(np.float32)
        else:
            # Unknown dimensions — try square-ish reshape
            W2 = int(np.sqrt(total))
            arr = raw[:W2 * W2].reshape(W2, W2).astype(np.float32)

        # Normalise to median ≈ 1.0 using centre crop (avoids edge shadow)
        ch0, ch1 = arr.shape[0] // 4, arr.shape[0] * 3 // 4
        cw0, cw1 = arr.shape[1] // 4, arr.shape[1] * 3 // 4
        centre_med = float(np.median(arr[ch0:ch1, cw0:cw1]))
        if centre_med < 1.0:
            centre_med = 1.0
        arr /= centre_med

        _FF2D_CACHE = arr
        _FF2D_MEAN  = centre_med
        assert ff_path is not None  # guarded by early return above
        log.info("Flat-field 2D loaded: %s → shape %s, median=%.0f",
                 ff_path.name, arr.shape, centre_med)
        return arr, centre_med
    except Exception as exc:
        log.debug("flat_field_raw.bin load failed: %s", exc)
        return None, 0.0


def _parse_telemetry_block(block: bytes | bytearray) -> dict:
    """Parse a 72-byte telemetry block and extract its calibration fields.

    Returns a dict with:
      - ``col``      : detector column position counter (uint16)
      - ``kv``       : tube kV word (uint16)
      - ``adc``      : numpy float32 array of 21 ADC reference readings
      - ``adc_mean`` : mean of the 21 ADC readings (float)
      - ``adc_std``  : std-dev of the 21 ADC readings (float)
      - ``adc_valid``: True when the readings look like real light-reference
                       data (non-zero, within plausible detector ADC range)

    The ADC readings are de-stuffed: 0x20-prefixed bytes (protocol
    byte-stuffing) are transparently handled because we read the raw
    72-byte block which was already identified by its tail pattern.
    """
    WORD = 2
    if len(block) < 72:
        return {"col": 0, "kv": 0, "adc": np.zeros(21, np.float32),
                "adc_mean": 0.0, "adc_std": 0.0, "adc_valid": False}

    def w(i: int) -> int:
        """Read big-endian uint16 at word index i."""
        o = i * WORD
        return (block[o] << 8) | block[o + 1]

    col = w(_TELEM_COL_WORD)
    kv  = w(_TELEM_KV_WORD)

    adc_vals = []
    # Real 0x07xx formatted ADC readings are at specific byte positions:
    for o in (2, 4, 6, 8, 12, 14, 16, 18, 22, 24, 26, 28, 40, 42, 44, 48, 50, 52):
        if o + 1 < len(block):
            v = (block[o] << 8) | block[o+1]
            if 0 < v < 4000:
                adc_vals.append(v)
    
    if adc_vals:
        adc_words = np.array(adc_vals, dtype=np.float32)
        mean, std = float(adc_words.mean()), float(adc_words.std())
        valid = (len(adc_vals) > 5) and (std < 500) and (200 < mean < 3500)
    else:
        adc_words = np.zeros(21, dtype=np.float32)
        mean, std, valid = 0.0, 0.0, False

    return {
        "col":       col,
        "kv":        kv,
        "adc":       adc_words,
        "adc_mean":  mean,
        "adc_std":   std,
        "adc_valid": valid,
    }



DEBUG_FILL = True
_debug_holes_count = 0
_debug_col_log = []

def _safe_dose_sample(segment: bytearray, start_idx: int, direction: int, max_steps: int = 20) -> tuple[int | None, bool]:
    pixels = []
    idx = start_idx
    step_bytes = direction * 2
    for _ in range(max_steps):
        if idx < 0 or idx + 1 >= len(segment):
            break
        val = (segment[idx] << 8) | segment[idx + 1]
        pixels.append(val)
        idx += step_bytes
        
    if not pixels:
        return None, False
        
    median_val = __import__('numpy').median(pixels)
    walk_triggered = False
    for i, p in enumerate(pixels):
        if abs(p - median_val) / max(median_val, 1) < 0.15:
            if i > 0: walk_triggered = True
            return p, walk_triggered
    return int(median_val), True

def _detect_hole_column(global_byte_offset: int, img_height: int) -> int:
    return global_byte_offset // (img_height * 2)

def _validate_calibration_alignment(ff_shape, predicted) -> bool:
    import numpy as np
    import logging
    log = logging.getLogger(__name__)
    if np.std(ff_shape) > 1e-5 and np.std(predicted) > 1e-5:
        corr = np.corrcoef(ff_shape, predicted)[0, 1]
        if corr < 0.85:
            log.warning("Calibration validation warning: correlation %.2f is below 0.85, using linear fallback", corr)
            return False
    return True

def _calibration_driven_fill(
    block_start: int,
    telem: dict,
    segment: bytearray,
    ff2d,
    ff2d_mean: float,
    segment_row_offset: int = 0,
    segment_col_offset: int = 0,
) -> 'np.ndarray | None':
    global _fill_call_count, _debug_holes_count
    import logging
    import numpy as np
    log = logging.getLogger(__name__)

    TELEM_SIZE   = 72
    TELEM_PIXELS = 36
    bs = block_start
    be = bs + TELEM_SIZE

    # Q1 Check: confirmed execution
    exact_col_idx = _detect_hole_column((segment_col_offset * 1316 * 2) + (segment_row_offset * 2) + bs, 1316)
    _fill_call_count += 1
    print(f"[FILL CALLED] count={_fill_call_count}, col={exact_col_idx}, "
          f"bs={bs}, be={be}, len(segment)={len(segment)}")

    val_top, walk_top = _safe_dose_sample(segment, bs - 2, -1, max_steps=20)
    val_bot, walk_bot = _safe_dose_sample(segment, be, 1, max_steps=20)
    
    val_top = float(val_top) if val_top is not None else float(val_bot or 0.0)
    val_bot = float(val_bot) if val_bot is not None else float(val_top or 0.0)
    if val_top == 0.0 and val_bot == 0.0:
        return None

    t_arr = np.linspace(1.0 / (TELEM_PIXELS + 1), TELEM_PIXELS / (TELEM_PIXELS + 1),
                        TELEM_PIXELS, dtype=np.float32)
    predicted = val_top * (1.0 - t_arr) + val_bot * t_arr

    first_px  = bs // 2
    first_row = (segment_row_offset + first_px) % 1316
    row_indices = [(first_row + j) % 1316 for j in range(TELEM_PIXELS)]
    
    global_byte_offset = (segment_col_offset * 1316 * 2) + (segment_row_offset * 2) + bs
    exact_col_idx = _detect_hole_column(global_byte_offset, 1316)

    global _debug_col_log
    
    predicted_warped = predicted.copy()
    if ff2d is not None and len(ff2d) > max(row_indices):
        col_idx = min(max(exact_col_idx, 0), ff2d.shape[1] - 1)
        ff_shape = np.array([ff2d[r, col_idx] for r in row_indices], dtype=np.float32)
        
        ff_trend = np.linspace(ff_shape[0], ff_shape[-1], len(ff_shape), dtype=np.float32)
        ff_trend = np.maximum(ff_trend, 1.0)
        ff_texture = ff_shape / ff_trend
        
        predicted_warped = predicted_warped * ff_texture
        
        if not _validate_calibration_alignment(ff_shape, predicted_warped):
            pass
        else:
            predicted = predicted_warped
            
    if DEBUG_FILL and _debug_holes_count < 5:
        _debug_col_log.append({
            "hole_number": _debug_holes_count + 1,
            "exact_col_idx": exact_col_idx,
            "global_byte_offset": global_byte_offset,
            "computed_col": exact_col_idx, # global_byte_offset // (img_height * 2) is just exact_col_idx
            "val_top": val_top,
            "val_bot": val_bot,
            "walk_top": walk_top,
            "walk_bot": walk_bot,
            "row_start": row_indices[0],
            "row_end": row_indices[-1],
        })
        log.info(f"--- DEBUG_FILL HOLE {_debug_holes_count+1} ---")
        log.info(f"Target Column: {exact_col_idx} (from global byte offset: {global_byte_offset})")
        log.info(f"Dose Bounds: top={val_top:.0f} bot={val_bot:.0f} (Walk top={walk_top}, Walk bot={walk_bot})")
        log.info(f"Row Indices (target patch): {row_indices[0]} to {row_indices[-1]}")
        
        import os
        from PIL import Image
        flank_extract = 20
        raw_pixels = []
        for i in range(max(0, bs - flank_extract*2), min(len(segment), be + flank_extract*2), 2):
            raw_pixels.append((segment[i] << 8) | segment[i+1])
            
        filled_pixels = list(raw_pixels)
        patch_offset = (bs - max(0, bs - flank_extract*2)) // 2
        for i, p in enumerate(predicted):
            if patch_offset + i < len(filled_pixels):
                filled_pixels[patch_offset + i] = int(p)
            
        max_p = max(raw_pixels + filled_pixels + [1])
        raw_arr = (np.array(raw_pixels) / max_p * 255).astype(np.uint8)
        fill_arr = (np.array(filled_pixels) / max_p * 255).astype(np.uint8)
        
        img_arr = np.column_stack([np.tile(raw_arr, (50, 1)).T, np.zeros((len(raw_arr), 10), dtype=np.uint8), np.tile(fill_arr, (50, 1)).T])
        try:
            _dbg_path = LOG_DIR / f"debug_hole_{_debug_holes_count+1}.png"
            Image.fromarray(img_arr).save(str(_dbg_path))
            log.info("Saved %s", _dbg_path)
        except Exception:
            pass
        
        _debug_holes_count += 1

    return predicted

def _repair_inline_telemetry(
    segment: bytearray,
    return_positions: bool = False,
    segment_row_offset: int = 0,
    segment_col_offset: int = 0,
) -> bytearray | tuple[bytearray, list[int]]:
    """Replace inline telemetry blocks with calibration-driven predicted pixels.

    The Orthophos XG embeds 72-byte kV/position telemetry records into
    the pixel stream at intervals of exactly 2632 bytes (= 1316 pixels
    = one detector column height).  These records OVERWRITE pixel data
    at fixed row positions — they do NOT add extra bytes.

    Each 72-byte block ends with a 6-byte tail signature.  In the Sidexis
    (de-stuffed) format the tail is ``00 01 XX XX 00 34``.  In a direct
    network capture the protocol uses 0x20 byte-stuffing, so the same
    tail appears as ``20 01 XX XX 20 34``.  Both variants are detected.

    **Calibration-driven fill (primary path):**
      1. Parse the 21 ADC reference readings from each 72-byte block.
      2. Load the 2-D flat-field to get per-pixel gain profiles.
      3. Combine ADC scale + flat-field shape + neighbour anchors to
         predict the missing 36 pixel values with detector physics.

    **Fallback path (when flat-field is unavailable or ADC readings are
    corrupt):** linear interpolation between the border pixels with
    matched noise, identical to the previous behaviour.

    If *return_positions* is True, also returns the byte offsets within
    the segment where blocks were repaired (for downstream 2D
    reconstruction).
    """
    TELEM_SIZE   = 72
    TELEM_PIXELS = TELEM_SIZE // 2  # 36 pixels overwritten per block

    # Find all telemetry blocks by tail pattern.
    # Support both plain (00 01 XX XX 00 34) and byte-stuffed (20 01 XX XX 20 34).
    block_starts: list[int] = []
    # Strict search for telemetry holes:
    # Pattern: [00 01] [?? ??] [00 34] at 72-byte intervals
    for off in range(TELEM_SIZE - 2, len(segment) - 1):
        # FAST SKIP: Tail signature is [00 34] (row param 52)
        if segment[off + 1] != 0x34:
            continue
        if segment[off] not in (0x00, 0x20):
            continue
            
        # Robust check: 0x00 0x01 should precede by 4 bytes
        if off < 4 or segment[off-3] != 0x01:
            continue
            
        # Value check: bytes [off-2:off] contain either an ADC reading
        # (1800-3000) or a frame counter/parameter (e.g. 0x0305 = 773).
        # The structural checks + marker_count are sufficient to avoid
        # false positives, so accept any value here.
        # (Previously rejected blocks with counter values like 773.)

        blk_start = off - (TELEM_SIZE - 2)
        if blk_start < 0:
            continue
        # Validate: the 72-byte block should contain multiple 0x20 or
        # 0x00 escape/marker bytes (telemetry has many low-value or
        # 0x20-stuffed fields, unlike normal 0x08xx pixel data).
        marker_count = 0
        for j in range(0, TELEM_SIZE, 2):
            hi = segment[blk_start + j]
            if hi == 0x20 or hi == 0x00:
                marker_count += 1
        if marker_count >= 3:
            block_starts.append(blk_start)

    if not block_starts:
        return (segment, []) if return_positions else segment

    import random

    # Try to load flat-field once (cached after first load)
    ff2d, ff2d_mean = _load_flat_field_2d()

    result = bytearray(segment)  # copy — we'll overwrite in place

    # Number of real pixels on each side to sample for noise estimation
    NOISE_WINDOW = 20  # pixels (40 bytes)

    cal_count  = 0  # blocks filled via calibration
    interp_count = 0  # blocks filled via fallback interpolation

    for bs in block_starts:
        be = bs + TELEM_SIZE

        # ── Parse ADC telemetry from the block ────────────────────────────
        telem = _parse_telemetry_block(segment[bs:be])

        # ── Try calibration-driven prediction first ────────────────────
        predicted = _calibration_driven_fill(
            bs, telem, result, ff2d, ff2d_mean, 
            segment_row_offset=segment_row_offset,
            segment_col_offset=segment_col_offset,
        )

        # Validate calibration prediction against border pixel values.
        # If the prediction mean deviates >15% from the border mean,
        # the flat-field profile doesn't match this scan — fall back
        # to linear interpolation which uses actual border values.
        use_calibration = False
        if predicted is not None and telem["adc_valid"]:
            val_before = (result[bs - 2] << 8) | result[bs - 1] if bs >= 2 else 0
            val_after = (result[be] << 8) | result[be + 1] if be + 1 < len(result) else 0
            border_mean = (val_before + val_after) / 2.0
            pred_mean = float(np.mean(predicted))
            if border_mean > 100 and abs(pred_mean / border_mean - 1.0) < 0.15:
                use_calibration = True

        if use_calibration:
            # Write calibration-predicted values (with matched noise)
            # Estimate local noise from surrounding pixels
            noise_diffs: list[float] = []
            px_before_start = max(0, bs - NOISE_WINDOW * 2)
            for k in range(px_before_start, bs - 2, 2):
                v0 = (result[k] << 8) | result[k + 1]
                v1 = (result[k + 2] << 8) | result[k + 3]
                noise_diffs.append(float(v1 - v0))
            px_after_end = min(len(result), be + NOISE_WINDOW * 2)
            for k in range(be, px_after_end - 2, 2):
                v0 = (result[k] << 8) | result[k + 1]
                v1 = (result[k + 2] << 8) | result[k + 3]
                noise_diffs.append(float(v1 - v0))

            if len(noise_diffs) >= 4:
                diff_std   = (sum(d * d for d in noise_diffs) / len(noise_diffs)) ** 0.5
                noise_std  = diff_std / 1.414
            else:
                noise_std = 0.0

            for j in range(TELEM_PIXELS):
                val = float(predicted[j])
                if noise_std > 0:
                    val += random.gauss(0, noise_std)
                val = max(0, min(65535, int(val)))
                pos = bs + j * 2
                result[pos]     = (val >> 8) & 0xFF
                result[pos + 1] =  val       & 0xFF
            cal_count += 1

        else:
            # ── Fallback: linear interpolation with matched noise ──────────
            if bs >= 2 and be + 1 < len(result):
                val_before = (result[bs - 2] << 8) | result[bs - 1]
                val_after  = (result[be] << 8) | result[be + 1]
            elif bs >= 2:
                val_before = val_after = (result[bs - 2] << 8) | result[bs - 1]
            else:
                val_before = val_after = (result[be] << 8) | result[be + 1]

            noise_diffs = []
            px_before_start = max(0, bs - NOISE_WINDOW * 2)
            for k in range(px_before_start, bs - 2, 2):
                v0 = (result[k] << 8) | result[k + 1]
                v1 = (result[k + 2] << 8) | result[k + 3]
                noise_diffs.append(float(v1 - v0))
            px_after_end = min(len(result), be + NOISE_WINDOW * 2)
            for k in range(be, px_after_end - 2, 2):
                v0 = (result[k] << 8) | result[k + 1]
                v1 = (result[k + 2] << 8) | result[k + 3]
                noise_diffs.append(float(v1 - v0))

            if len(noise_diffs) >= 4:
                diff_std  = (sum(d * d for d in noise_diffs) / len(noise_diffs)) ** 0.5
                noise_std = diff_std / 1.414
            else:
                noise_std = 0.0

            for j in range(TELEM_PIXELS):
                t   = (j + 1) / (TELEM_PIXELS + 1)
                val = val_before * (1 - t) + val_after * t
                if noise_std > 0:
                    val += random.gauss(0, noise_std)
                val = max(0, min(65535, int(val)))
                pos = bs + j * 2
                result[pos]     = (val >> 8) & 0xFF
                result[pos + 1] =  val       & 0xFF
            interp_count += 1

    log.debug(
        "Telemetry repair: %d calibration-driven, %d interpolated (ff2d=%s)",
        cal_count, interp_count, ff2d is not None,
    )

    if return_positions:
        return result, block_starts
    return result


def _find_pixel_start(data: bytes, search_start: int = 60000,
                      search_end: int = 90000) -> int:
    """Find where actual pixel data begins using column-correlation.

    Scans byte offsets in the raw buffer looking for the position where
    adjacent 1316-pixel columns are most strongly correlated, indicating
    a genuine detector readout rather than kV telemetry / protocol data.
    """
    H = PANO_DEFAULT_HEIGHT
    best_off = search_start
    best_corr = -1.0

    for byte_off in range(search_start, min(search_end, len(data) - H * 4), 2):
        c1 = np.frombuffer(data[byte_off:byte_off + H * 2], dtype=">u2").astype(np.float32)
        c2 = np.frombuffer(data[byte_off + H * 2:byte_off + H * 4], dtype=">u2").astype(np.float32)
        c1z = c1 - c1.mean()
        c2z = c2 - c2.mean()
        d = np.sqrt(np.dot(c1z, c1z) * np.dot(c2z, c2z))
        ncc = np.dot(c1z, c2z) / (d + 1e-10) if d > 0 else 0.0
        if ncc > best_corr:
            best_corr = ncc
            best_off = byte_off

    log.info("Pixel start scan: best offset %d (corr=%.4f)", best_off, best_corr)
    return best_off


def _extract_panoramic_simple(data: bytes, detector_height: int = 0) -> list[Scanline]:
    """Simple panoramic extraction — strip headers, find pixel start, reshape.

    This is the original proven extraction that worked reliably with live
    device captures.  No inline telemetry repair, no correlation-based
    pixel start detection, no asserts.  Used as a fallback when the
    advanced _extract_panoramic fails.
    """
    if len(data) < 10000:
        return []

    # 1. Build list of all session headers
    headers: list[tuple[int, int]] = []
    idx = 0
    while idx < len(data) - 6:
        pos = data.find(_SESSION_SIG, idx)
        if pos < 0:
            break
        hdr_start = pos - 2
        if hdr_start < idx:
            idx = pos + 4
            continue
        func_hi = data[hdr_start] if hdr_start >= 0 else 0
        if func_hi in (0x10, 0x20, 0x21):
            func_code = (data[hdr_start] << 8) | data[hdr_start + 1]
            headers.append((hdr_start, func_code))
        idx = pos + 4

    if not headers:
        log.warning("Simple panoramic: no session headers found in %d bytes", len(data))
        return []

    # 2. Strip headers + echo payloads -> clean byte stream
    clean = bytearray()
    read_pos = 0
    first_1003 = True

    for hdr_pos, func_code in headers:
        if hdr_pos > read_pos:
            clean.extend(data[read_pos:hdr_pos])
        after_hdr = hdr_pos + SESSION_HEADER_SIZE
        if func_code == 0x1003:
            skip = ECHO_PAYLOAD_SIZE
            if first_1003:
                skip += FIRST_FRAME_PADDING
                first_1003 = False
            read_pos = after_hdr + skip
        else:
            read_pos = after_hdr

    if read_pos < len(data):
        clean.extend(data[read_pos:])

    log.info("Simple panoramic: %d raw -> %d clean bytes", len(data), len(clean))

    # 3. Find pixel start via transition marker
    marker_pos = clean.find(PIXEL_TRANSITION_MARKER)
    if marker_pos < 0:
        log.warning("Simple panoramic: transition marker D6 D6 4C not found")
        return []

    pixel_start = marker_pos + 12
    if pixel_start % 2 != 0:
        pixel_start += 1

    pixel_data = bytes(clean[pixel_start:])
    total_pixels = len(pixel_data) // 2
    if total_pixels < 100000:
        log.warning("Simple panoramic: too few pixels (%d)", total_pixels)
        return []

    # 4. Reshape
    img_height = detector_height if detector_height > 0 else PANO_DEFAULT_HEIGHT
    img_width = total_pixels // img_height
    expected_width = PANO_DEFAULT_WIDTH
    if abs(img_width - expected_width) < 100:
        img_width = expected_width

    usable_bytes = img_width * img_height * 2
    if usable_bytes > len(pixel_data):
        img_width = len(pixel_data) // (img_height * 2)
        usable_bytes = img_width * img_height * 2

    pixels = np.frombuffer(pixel_data[:usable_bytes], dtype=">u2")
    img_array = pixels.reshape(img_width, img_height)

    log.info("Simple panoramic: %d x %d, range %d-%d",
             img_width, img_height, img_array.min(), img_array.max())

    # 5. Repair artifact rows (simple threshold-based)
    img_2d = img_array.T.astype(np.float32)
    row_means = np.mean(img_2d, axis=1)
    row_diffs = np.abs(np.diff(row_means))
    diff_median = np.median(row_diffs)
    diff_std = np.std(row_diffs)
    threshold = diff_median + 6 * diff_std

    repaired_rows = []
    for r in range(1, img_height - 1):
        if r < len(row_diffs) and row_diffs[r] > threshold:
            repaired_rows.append(r)
            if r + 1 < img_height - 1:
                repaired_rows.append(r + 1)
    repaired_rows = sorted(set(repaired_rows))

    if repaired_rows:
        repaired_set = set(repaired_rows)
        for r in repaired_rows:
            above = r - 1
            while above in repaired_set and above > 0:
                above -= 1
            below = r + 1
            while below in repaired_set and below < img_height - 1:
                below += 1
            if above >= 0 and below < img_height:
                t = (r - above) / max(below - above, 1)
                img_2d[r] = img_2d[above] * (1 - t) + img_2d[below] * t
        img_array = img_2d.T.astype(np.uint16)
        log.info("Simple panoramic: repaired %d artifact rows", len(repaired_rows))

    # 6. Build Scanline objects
    scanlines = []
    for col_idx in range(img_width):
        scanlines.append(Scanline(
            scanline_id=col_idx & 0xFF,
            pixel_count=img_height,
            pixels=img_array[col_idx] if img_array.dtype == np.uint16
            else img_array[col_idx].astype(np.uint16),
        ))
    return scanlines


def _extract_panoramic(data: bytes, detector_height: int = 0) -> tuple[list[Scanline], np.ndarray | None] | list[Scanline]:
    """Extract a full panoramic image from the raw scan data stream.

    The Orthophos XG (DX41) sends the full detector readout as a continuous
    stream of 16-bit big-endian pixels, split across 0x1003 continuation
    frames.  Each frame has a 20-byte session header and a *variable-length*
    echo payload (30-120 bytes, depending on session config) before pixels.

    The echo size depends on a 2-byte field in the DATA_SEND payload
    (offset 18-19: 0xDB04 for Sidexis, was 0xE300 for PureXS).  With
    the Sidexis value, all frames get clean 30-byte echoes.  With the
    old PureXS value, some frames got 30-120 byte echoes with embedded
    kV telemetry that caused image artifacts.

    Processing steps:
      1. Locate 0x1003 session headers in the raw buffer.
      2. Auto-detect where pixel data begins (correlation-based scan).
      3. For each 0x1003 frame, dynamically detect the echo payload end.
      4. Strip inline scanline markers embedded in the pixel stream.
      5. Reshape the clean pixel stream at the correct detector height.
      6. Repair any remaining artifact rows via neighbour interpolation.

    Returns a list of Scanline objects, one per image column.
    """
    if len(data) < 10000:
        return [], None

    # ── 1. Locate all 0x1003 session headers ──────────────────────────────
    headers_1003: list[int] = []
    idx = 0
    while idx < len(data) - 6:
        pos = data.find(_SESSION_SIG, idx)
        if pos < 0:
            break
        hdr_start = pos - 2
        if hdr_start < idx:
            idx = pos + 4
            continue
        func_hi = data[hdr_start] if hdr_start >= 0 else 0
        if func_hi == 0x10 and hdr_start + 1 < len(data) and data[hdr_start + 1] == 0x03:
            headers_1003.append(hdr_start)
        idx = pos + 4

    if not headers_1003:
        log.warning("Panoramic: no 0x1003 frames found in %d bytes", len(data))
        return [], None

    log.info("Panoramic: found %d 0x1003 frames", len(headers_1003))

    # ── 2. Find where pixel data starts ───────────────────────────────────
    first_frame = headers_1003[0]
    scan_lo = first_frame + SESSION_HEADER_SIZE + ECHO_PAYLOAD_SIZE
    scan_hi = min(scan_lo + 30000, len(data) - PANO_DEFAULT_HEIGHT * 4)
    pixel_start = _find_pixel_start(data, scan_lo, scan_hi)

    # ── 3. Build clean pixel stream with echo + inline telemetry stripping ─
    clean = bytearray()
    read_pos = pixel_start

    echo_sizes_log: list[int] = []
    telem_blocks_repaired = 0
    # Track byte offsets of repaired telemetry blocks in the clean stream
    # so we can do a second-pass 2D repair after reshape.
    repaired_byte_offsets: list[int] = []

    # ── Segment tracking for remainder diagnosis ──
    _seg_log: list[tuple[str, int, int, int]] = []  # (label, raw_len, repaired_len, clean_pos)

    for i, hdr_pos in enumerate(headers_1003):
        if hdr_pos < pixel_start:
            continue

        # Pixels between the previous frame's echo end and this header
        if hdr_pos > read_pos:
            segment = bytearray(data[read_pos:hdr_pos])
            # The start of this chunk corresponds to a specific physical row wrapping on the detector
            segment_row_offset = (len(clean) // 2) % 1316
            segment_col_offset = (len(clean) // 2) // 1316
            repaired, block_positions = _repair_inline_telemetry(
                segment, return_positions=True,
                segment_row_offset=segment_row_offset,
                segment_col_offset=segment_col_offset,
            )
            telem_blocks_repaired += (len(segment) - len(repaired) == 0)
            # Map block positions from segment-local to clean-stream-global
            base = len(clean)
            for bp in block_positions:
                repaired_byte_offsets.append(base + bp)
            _seg_log.append((f"F{i}", len(segment), len(repaired), len(clean)))
            clean.extend(repaired)

        after_hdr = hdr_pos + SESSION_HEADER_SIZE

        # Echo is ALWAYS exactly 30 bytes (FC30 patient config echo).
        # The old _detect_echo_end formula for "telemetry frames" was
        # accidentally matching inline telemetry block anchors (0x0034)
        # embedded in the pixel stream, not echo-level anchors.
        # Telemetry anchor spacing confirms: all 108 frame boundaries
        # have exactly 50 bytes overhead (20 header + 30 echo).
        echo_end = ECHO_PAYLOAD_SIZE  # always 30

        echo_sizes_log.append(echo_end)
        read_pos = after_hdr + echo_end

    # Tail: stop at 0x1004/0x1005 end markers (post-scan report is not pixels)
    tail_limit = len(data)
    for end_sig in [b'\x10\x04\x07\x2d\x07\xd0', b'\x10\x05\x07\x2d\x07\xd0']:
        pos = data.find(end_sig, read_pos)
        if 0 < pos < tail_limit:
            tail_limit = pos
    if tail_limit > read_pos:
        segment = bytearray(data[read_pos:tail_limit])
        segment_row_offset = (len(clean) // 2) % 1316
        segment_col_offset = (len(clean) // 2) // 1316
        repaired, block_positions = _repair_inline_telemetry(
            segment, return_positions=True,
            segment_row_offset=segment_row_offset,
            segment_col_offset=segment_col_offset
        )
        base = len(clean)
        for bp in block_positions:
            repaired_byte_offsets.append(base + bp)
        _seg_log.append(("TAIL", len(segment), len(repaired), len(clean)))
        clean.extend(repaired)

    # ── Segment analysis: find where remainder bytes accumulate ──
    H2 = PANO_DEFAULT_HEIGHT * 2
    cum_remainder = 0
    seg_problems = []
    for label, raw_len, rep_len, clean_pos in _seg_log:
        if raw_len != rep_len:
            seg_problems.append(f"  {label}: len changed {raw_len} -> {rep_len} "
                                f"(delta={rep_len - raw_len})")
    if seg_problems:
        log.warning("Segments with length changes:\n%s", "\n".join(seg_problems))

    # Show per-frame cumulative remainder
    _frame_remainders: list[tuple[str, int]] = []
    running = 0
    for label, raw_len, rep_len, clean_pos in _seg_log:
        running += rep_len
        rem = (running // 2) % PANO_DEFAULT_HEIGHT
        _frame_remainders.append((label, rem))

    # Find where remainder first appears
    first_nonzero = None
    for label, rem in _frame_remainders:
        if rem != 0 and first_nonzero is None:
            first_nonzero = (label, rem)

    print(f"[SEGMENT ANALYSIS]")
    print(f"  Total segments: {len(_seg_log)}")
    print(f"  First remainder: {first_nonzero}")
    print(f"  Final remainder: {_frame_remainders[-1] if _frame_remainders else 'N/A'}")
    # Show first 5 and last 5 remainders
    for label, rem in _frame_remainders[:5]:
        print(f"  {label}: cum_remainder={rem}")
    print(f"  ...")
    for label, rem in _frame_remainders[-5:]:
        print(f"  {label}: cum_remainder={rem}")

    if echo_sizes_log:
        from collections import Counter
        dist = Counter(echo_sizes_log)
        log.info("Echo sizes: %s", dict(sorted(dist.items())))

    log.info(
        "Panoramic extract: %d raw -> %d clean bytes (from offset %d)",
        len(data), len(clean), pixel_start,
    )

    pixel_data = bytes(clean)
    total_pixels = len(pixel_data) // 2

    if total_pixels < 100000:
        log.warning("Panoramic: too few pixels (%d)", total_pixels)
        return [], None

    # ── 5. Determine image dimensions ─────────────────────────────────────
    img_height = detector_height if detector_height > 0 else PANO_DEFAULT_HEIGHT

    # ── RESHAPE INTEGRITY CHECK ──────────────────────────────────────
    SESSION_SIG = b'\x07\x2d\x07\xd0'

    # Pass 1: count residual session headers (07 2D 07 D0 at offset +2)
    residual_headers = []
    i = 0
    while i < len(clean) - 6:
        if clean[i+2:i+6] == SESSION_SIG:
            func_hi = clean[i]
            if func_hi in (0x10, 0x20, 0x21):
                residual_headers.append(i)
        i += 2

    # Pass 2: count echo payload remnants
    arr_check = np.frombuffer(bytes(clean), dtype='>u2')
    out_of_range = int(np.sum((arr_check < 800) | (arr_check > 62000)))

    print(f"[RESHAPE CHECK]")
    print(f"  clean length:        {len(clean)} bytes")
    print(f"  total pixels:        {len(clean)//2}")
    print(f"  remainder mod 1316:  {(len(clean)//2) % img_height}")
    print(f"  residual headers:    {len(residual_headers)}")
    print(f"  out-of-range pixels: {out_of_range} / {len(arr_check)}")
    if residual_headers:
        print(f"  header positions:    {residual_headers[:10]}")
        # Dump surrounding bytes for first 3 contamination points
        for ci, cpos in enumerate(residual_headers[:3]):
            start = max(0, cpos - 4)
            end = min(len(clean), cpos + 16)
            print(f"  contamination[{ci}] @{cpos}: {bytes(clean[start:end]).hex()}")
    # ── END RESHAPE INTEGRITY CHECK ──────────────────────────────────

    # Trim tail to nearest column boundary if remainder exists
    # (echo detection inaccuracies can leave a small residual)
    remainder_px = (len(clean) // 2) % img_height
    if remainder_px != 0:
        trim_bytes = remainder_px * 2
        log.warning("Reshape: trimming %d remainder pixels (%d bytes) from tail",
                    remainder_px, trim_bytes)
        clean = clean[:-trim_bytes]

    # Verify clean buffer is evenly divisible (trim if not)
    if len(clean) % (img_height * 2) != 0:
        remainder = (len(clean) // 2) % img_height
        log.warning(
            "Clean buffer %d bytes not divisible by %d — "
            "trimming %d remainder pixels",
            len(clean), img_height * 2, remainder,
        )
        trim = remainder * 2
        clean = clean[:-trim]

    width = len(clean) // 2 // img_height
    arr = np.frombuffer(clean, dtype='>u2')
    img_array = arr.reshape(width, img_height)

    img_width = width
    log.info("Reshape: %d × %d (remainder=0 confirmed)", img_height, width)
    print(f"TOTAL FILL CALLS: {_fill_call_count}")  # (cols, rows)

    # ── DEBUG: Save raw reshaped image before any corrections ──────────
    _raw_img = img_array.T.astype(np.float32)  # (height, width)
    _raw_norm = ((_raw_img - _raw_img.min()) / max(_raw_img.max() - _raw_img.min(), 1) * 255).astype(np.uint8)
    from PIL import Image as _PILImage
    _PILImage.fromarray(_raw_norm).save("debug_raw_reshape_BEFORE_corrections.png")
    log.info("Saved raw reshape debug image: debug_raw_reshape_BEFORE_corrections.png")

    log.info(
        "Panoramic: %d columns x %d rows, pixel range %d-%d, mean %.0f",
        img_width, img_height,
        img_array.min(), img_array.max(), img_array.mean(),
    )

    # ── 5b. 2D telemetry repair ──────────────────────────────────────────
    # Disabled: The 1D flat-field texture fill is structurally seamless.
    # Replacing it with cloned adjacent tissue introduces mathematical noise 
    # and jagged boundaries along image gradients.

    img_2d = img_array.T.astype(np.float32)  # (height, width)
    repaired_rows: list[int] = []

    row_means = np.mean(img_2d, axis=1)
    row_diffs = np.abs(np.diff(row_means))
    diff_median = np.median(row_diffs)
    diff_std = np.std(row_diffs)
    threshold = diff_median + 6 * diff_std

    for r in range(1, img_height - 1):
        if r < len(row_diffs) and row_diffs[r] > threshold:
            repaired_rows.append(r)
            if r + 1 < img_height - 1:
                repaired_rows.append(r + 1)

    repaired_rows = sorted(set(repaired_rows))

    if repaired_rows:
        repaired_set = set(repaired_rows)
        for r in repaired_rows:
            above = r - 1
            while above in repaired_set and above > 0:
                above -= 1
            below = r + 1
            while below in repaired_set and below < img_height - 1:
                below += 1
            if above >= 0 and below < img_height:
                t = (r - above) / max(below - above, 1)
                img_2d[r] = img_2d[above] * (1 - t) + img_2d[below] * t

        img_array = img_2d.T.astype(np.uint16)
        log.info("Panoramic: repaired %d artifact rows", len(repaired_rows))

    # ── 7. Column realignment ────────────────────────────────────────────
    #   With inline telemetry properly repaired (including 0x20 byte-
    #   stuffed variants), real vertical shifts should be rare.  Any
    #   remaining shifts come from unrepaired telemetry residue.
    #
    #   Guard against false positives from:
    #     - Noisy early columns (scan start, before X-ray exposure)
    #     - Telemetry frame boundaries where repaired blocks decorrelate
    #       adjacent columns without any actual vertical shift
    #
    #   A shift is only accepted when the improved correlation exceeds an
    #   absolute minimum (0.85), not just a relative improvement.  The
    #   first 5% of columns are skipped to avoid scan-start noise.
    img_f = img_array.T.astype(np.float32) if img_array.dtype != np.float32 else img_array.T.copy()
    # img_f is (height, width)

    col_corrs = np.zeros(img_width)
    for c in range(1, img_width):
        c1 = img_f[:, c - 1]; c2 = img_f[:, c]
        c1z = c1 - c1.mean(); c2z = c2 - c2.mean()
        d = np.sqrt(np.dot(c1z, c1z) * np.dot(c2z, c2z))
        col_corrs[c] = np.dot(c1z, c2z) / (d + 1e-10) if d > 0 else 0

    median_corr = np.median(col_corrs[1:])
    shift_thresh = median_corr - 0.20
    MAX_SHIFT = 15
    MIN_SHIFTED_CORR = 0.85   # absolute minimum after shifting
    SKIP_COLS = max(img_width // 20, 50)  # skip noisy scan start

    cumshift = 0
    col_shifts = np.zeros(img_width, dtype=int)
    realigned_count = 0

    for c in range(1, img_width):
        if c < SKIP_COLS or col_corrs[c] >= shift_thresh:
            col_shifts[c] = cumshift
            continue
        c_prev = img_f[:, c - 1]
        c_curr = img_f[:, c]
        best_s = 0
        best_nc = col_corrs[c]
        for s in range(-MAX_SHIFT, MAX_SHIFT + 1):
            if s == 0:
                continue
            if s > 0:
                a = c_prev[s:]; b = c_curr[:img_height - s]
            else:
                a = c_prev[:img_height + s]; b = c_curr[-s:]
            if len(a) < 200:
                continue
            az = a - a.mean(); bz = b - b.mean()
            dd = np.sqrt(np.dot(az, az) * np.dot(bz, bz))
            nc = np.dot(az, bz) / (dd + 1e-10)
            if nc > best_nc + 0.10:
                best_nc = nc
                best_s = s
        if best_s != 0 and best_nc >= MIN_SHIFTED_CORR:
            cumshift += best_s
            realigned_count += 1
        col_shifts[c] = cumshift

    if realigned_count:
        aligned = np.zeros_like(img_f)
        for c in range(img_width):
            s = int(col_shifts[c])
            if s == 0:
                aligned[:, c] = img_f[:, c]
            elif s > 0:
                aligned[s:, c] = img_f[:img_height - s, c]
                aligned[:s, c] = img_f[s, c]
            else:
                aligned[:img_height + s, c] = img_f[-s:, c]
                aligned[img_height + s:, c] = img_f[img_height + s - 1, c]
        img_array = aligned.T.astype(np.uint16)
        log.info("Column realignment: %d shift points corrected "
                 "(range %d to %d pixels)",
                 realigned_count, col_shifts.min(), col_shifts.max())
    else:
        log.info("Column realignment: no shifts needed")

    # ── 8. Build Scanline objects (one per column) ────────────────────────
    scanlines = []
    for col_idx in range(img_width):
        scanlines.append(Scanline(
            scanline_id=col_idx & 0xFF,
            pixel_count=img_height,
            pixels=img_array[col_idx] if img_array.dtype == np.uint16
            else img_array[col_idx].astype(np.uint16),
        ))

    # Build repair mask (height × width) for downstream inpainting
    TELEM_PX = 36
    _repair_mask = np.zeros((img_height, img_width), dtype=np.uint8)
    for byte_off in repaired_byte_offsets:
        pixel_off = byte_off // 2
        c = pixel_off // img_height
        r = pixel_off % img_height
        if 0 <= c < img_width:
            _repair_mask[r:min(r + TELEM_PX, img_height), c] = 255

    return scanlines, _repair_mask


def _protected_row_smooth(img_array: np.ndarray, 
                           hole_columns: list[int], 
                           smooth_kernel: int = 3,
                           protection_radius: int = 2) -> np.ndarray:
    """
    BUG 5 FIX: Runs horizontal row smoothing everywhere EXCEPT within 
    protection_radius pixels of any confirmed telemetry hole column.
    
    Prevents:
    - Blurring of calibration fill boundaries
    - Corruption of dose sample pixels used by _safe_dose_sample
    - Loss of tooth/bone edge sharpness near hole zones
    
    Args:
        img_array: 2D numpy array (rows x cols), float or uint16
        hole_columns: list of exact_col_idx values from _detect_hole_column
        smooth_kernel: width of horizontal smoothing window (default 3)
        protection_radius: cols on each side of hole to leave unsmoothed
    
    Returns:
        Smoothed image array with hole zones fully preserved
    """
    import numpy as np
    from scipy.ndimage import uniform_filter1d

    if img_array.shape[1] == 0:
        return img_array

    # Build protection mask — True means DO NOT SMOOTH this column
    protected = np.zeros(img_array.shape[1], dtype=bool)
    for col in hole_columns:
        if 0 <= col < img_array.shape[1]:
            lo = max(0, col - protection_radius)
            hi = min(img_array.shape[1], col + protection_radius + 1)
            protected[lo:hi] = True

    smoothed = uniform_filter1d(img_array.astype(float), 
                                 size=smooth_kernel, 
                                 axis=1)

    # Restore protected columns from original
    result = smoothed.copy()
    result[:, protected] = img_array[:, protected]

    return result.astype(img_array.dtype)


def _save_glow_region_diff(raw_img: np.ndarray,
                            repaired_img: np.ndarray,
                            hole_columns: list[int],
                            output_path: str = "",
                            row_context: int = 100,
                            col_context: int = 60) -> None:
    """
    Saves a side-by-side PNG showing raw vs repaired for each 
    of the first 3 hole columns, cropped to the glow region 
    (brightest 100 rows surrounding the hole).
    
    Use this to visually confirm:
    - No edge tear at hole boundary (top/bottom of fill)
    - No brightness step between fill and surrounding tissue
    - Smooth gradient continuity across the hole
    """
    import numpy as np
    from PIL import Image, ImageDraw

    if not hole_columns:
        log.warning("No hole columns provided for glow region diff.")
        return

    panels = []
    for col in hole_columns[:3]:
        if col >= raw_img.shape[1]: continue
        
        # Find brightest row region near this column
        col_slice = raw_img[:, max(0, col-5):col+5].mean(axis=1)
        brightest_row = int(np.argmax(col_slice))
        r0 = max(0, brightest_row - row_context // 2)
        r1 = min(raw_img.shape[0], r0 + row_context)
        c0 = max(0, col - col_context // 2)
        c1 = min(raw_img.shape[1], c0 + col_context)

        raw_crop = raw_img[r0:r1, c0:c1].astype(float)
        rep_crop = repaired_img[r0:r1, c0:c1].astype(float)

        if raw_crop.size == 0 or rep_crop.size == 0: continue

        # Normalize each crop independently for visibility
        def norm(arr):
            mn, mx = arr.min(), arr.max()
            return ((arr - mn) / max(mx - mn, 1) * 255).astype(np.uint8)

        raw_norm = norm(raw_crop)
        rep_norm = norm(rep_crop)

        # Diff map — amplify differences 3x for visibility
        diff = np.clip(np.abs(rep_crop - raw_crop) / max(raw_crop.max(), 1) * 3 * 255, 
                       0, 255).astype(np.uint8)

        # Stack raw | repaired | diff horizontally
        spacer = np.zeros((raw_norm.shape[0], 5), dtype=np.uint8)
        panel = np.hstack([raw_norm, spacer, rep_norm, spacer, diff])
        panels.append(panel)

    if not panels:
        return

    # Stack all hole panels vertically
    max_w = max(p.shape[1] for p in panels)
    padded_panels = []
    for p in panels:
        if p.shape[1] < max_w:
            p_pad = np.pad(p, ((0, 0), (0, max_w - p.shape[1])), mode='constant')
            padded_panels.append(p_pad)
        else:
            padded_panels.append(p)
            
    spacer_h = np.zeros((10, max_w), dtype=np.uint8)
    final_rows = []
    for i, p in enumerate(padded_panels):
        final_rows.append(p)
        if i < len(padded_panels) - 1:
            final_rows.append(spacer_h)
    
    final = np.vstack(final_rows)

    img_out = Image.fromarray(final)
    draw = ImageDraw.Draw(img_out)
    draw.text((5, 5), "RAW | REPAIRED | DIFF (x3)", fill=255)
    if not output_path:
        output_path = str(LOG_DIR / "bug2_glow_diff.png")
    try:
        img_out.save(output_path)
        log.info("Saved glow region diff: %s", output_path)
    except Exception:
        pass


def _extract_events(data: bytes) -> list[ScanEvent]:
    """Extract ASCII log events embedded in TCP payloads."""
    events = []

    for pattern, event_type in [
        (RE_RECORDING_START, "recording_start"),
        (RE_RECORDING_STOP, "recording_stop"),
        (RE_IMAGE_TRANSFER_START, "imagetransfer_start"),
        (RE_IMAGE_TRANSFER_STOP, "imagetransfer_stop"),
        (RE_STATE_RELEASED, "state_released"),
        (RE_E7_ERROR, "e7_error"),
    ]:
        for m in pattern.finditer(data):
            # Try to find a preceding timestamp
            ts_str = ""
            search_start = max(0, m.start() - 80)
            ts_match = RE_TIMESTAMP.search(data[search_start:m.start()])
            if ts_match:
                ts_str = ts_match.group(1).decode("ascii", errors="replace")

            detail = ""
            if event_type == "recording_start" and m.lastindex:
                detail = f"Value: {m.group(1).decode()}"
            elif event_type == "e7_error":
                detail = "ERR_SIDEXIS_API (treat as post-scan success)"

            events.append(ScanEvent(
                timestamp_str=ts_str,
                event_type=event_type,
                detail=detail,
            ))

    return events


def _pair_heartbeats(capture: DecodedCapture) -> None:
    """Match HB_REQUEST frames with their HB_RESPONSE partners."""
    requests = [f for f in capture.frames if f.func_code == FC_HB_REQUEST]
    responses = [f for f in capture.frames if f.func_code == FC_HB_RESPONSE]

    for req in requests:
        # Find the closest response after this request
        best = None
        for resp in responses:
            if resp.timestamp >= req.timestamp:
                if best is None or resp.timestamp < best.timestamp:
                    best = resp
        if best:
            capture.hb_pairs.append((req, best))
            responses.remove(best)  # don't reuse


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Image Reconstruction
# ╚══════════════════════════════════════════════════════════════════════════════

def reconstruct_image(
    scanlines: list[Scanline],
    invert: bool = True,
    repair_mask: np.ndarray | None = None,
    mode: str = "full",
) -> Image.Image | None:
    """Reconstruct a panoramic image from decoded scanlines.

    Each scanline contributes one column of the panoramic image.  The
    Orthophos detector sweeps horizontally, so each scanline is a
    vertical strip of *height* pixels.

    Args:
        scanlines: List of Scanline objects (one per column).
        repair_mask: Optional (height, width) uint8 mask where 255 marks
            telemetry-repaired pixels.  Used for linear-domain inpainting.
        invert: If True (default), invert for dental convention
                (MONOCHROME1 — bone/tooth = white, air = black).
        mode: Processing mode — "full" for the complete correction
              pipeline, "clean" for a minimal percentile-stretch approach
              with only essential corrections (dark, die gap, dead rows).

    Returns:
        PIL Image (8-bit grayscale) or None.
    """
    if not scanlines:
        return None

    # Determine consistent pixel count (most common)
    counts: dict[int, int] = {}
    for sl in scanlines:
        counts[sl.pixel_count] = counts.get(sl.pixel_count, 0) + 1
    target_count = max(counts, key=counts.get)

    # Filter to scanlines with the expected pixel count
    valid = [sl for sl in scanlines if sl.pixel_count == target_count]
    if not valid:
        return None

    log.info(
        "Reconstructing image: %d scanlines x %d pixels",
        len(valid), target_count,
    )

    # Build the image array: each scanline becomes one column
    width = len(valid)
    height = target_count

    img_array = np.zeros((height, width), dtype=np.uint16)
    for col, sl in enumerate(valid):
        img_array[:, col] = sl.pixels[:height]

    img_f = img_array.astype(np.float32)

    # ── Flat-field calibration (if available) ────────────────────────
    #   If a pre-computed flat-field normalization map exists, apply it
    #   as a 2D pixel-by-pixel gain correction.  This eliminates tile
    #   grid artifacts at the source and replaces the downstream column
    #   correction pipeline.  Falls through to the old pipeline if the
    #   flat-field file is not present.
    import os as _os
    _FF_PATH = _os.path.join(_os.path.dirname(__file__), "flat_field_norm.npy")
    if _os.path.exists(_FF_PATH) and height == 1316 and width == 2706:
        try:
            import cv2
            _ff_norm = np.load(_FF_PATH)
            if _ff_norm.shape == (height, width):
                log.info("Flat-field calibration: loading %s", _FF_PATH)

                # Interpolate known dead rows (wide Gaussian-weighted kernel, ±8 rows)
                for _dr in [426, 853]:
                    if 8 <= _dr < height - 8:
                        _kern_hw = 8  # half-width
                        _weights = np.exp(-0.5 * (np.arange(-_kern_hw, _kern_hw + 1) / 3.0) ** 2)
                        _weights[_kern_hw] = 0  # exclude dead row itself
                        _weights /= _weights.sum()
                        _neighbors = np.array([img_f[_dr + k, :] for k in range(-_kern_hw, _kern_hw + 1)])
                        img_f[_dr, :] = (_weights[:, np.newaxis] * _neighbors).sum(axis=0)
                        _neighbors_ff = np.array([_ff_norm[_dr + k, :] for k in range(-_kern_hw, _kern_hw + 1)])
                        _ff_norm[_dr, :] = (_weights[:, np.newaxis] * _neighbors_ff).sum(axis=0)

                # Dark subtraction
                _dark_pt = np.median(img_f[:, :80], axis=1)
                _pt_dark = np.maximum(img_f - _dark_pt[:, np.newaxis], 0)

                # 2D flat-field correction — skip shadow zones
                _safe = _ff_norm > 0.3
                _corrected = np.where(_safe,
                                      _pt_dark / np.maximum(_ff_norm, 0.3),
                                      _pt_dark)
                log.info("Flat-field shadow zone: %.1f%% pixels skipped",
                         (~_safe).mean() * 100)

                # Column normalization (removes residual beam shape)
                from scipy.ndimage import gaussian_filter1d as _gf1d_ff
                _col_m = _corrected[40:min(1220, height), :].mean(axis=0)
                _col_t = _gf1d_ff(_col_m.astype(np.float64), sigma=200)
                _col_n = _col_t.mean() / np.maximum(_col_t, 1)
                _corrected = _corrected * _col_n[np.newaxis, :]

                # Fine column normalization (catches die-boundary residual grid)
                _col_m2 = _corrected[100:min(1100, height), :].mean(axis=0)
                _col_t2 = _gf1d_ff(_col_m2.astype(np.float64), sigma=30)
                _col_n2 = _col_t2.mean() / np.maximum(_col_t2, 1)
                _corrected = _corrected * _col_n2[np.newaxis, :]

                # CLAHE tone mapping on active zone (rows 40-1220)
                _ACTIVE_TOP, _ACTIVE_BOT = 40, min(1220, height)
                _active = _corrected[_ACTIVE_TOP:_ACTIVE_BOT, :]
                _p01 = np.percentile(_active[:, 400:min(width, 2300)], 2)
                _p999 = np.percentile(_active[:, 400:min(width, 2300)], 90)
                _img16 = np.clip((_active - _p01) / max(_p999 - _p01, 1) * 65535,
                                 0, 65535).astype(np.uint16)
                _clahe = cv2.createCLAHE(clipLimit=1.5, tileGridSize=(16, 16))
                _img_clahe = _clahe.apply(_img16)
                _img8 = 255 - (_img_clahe / 257).astype(np.uint8)

                # Resize active zone to standard output (2440x1280)
                _final = np.array(
                    Image.fromarray(_img8).resize((2440, 1280), Image.LANCZOS)
                )

                # Center crop to remove collimator borders, then zoom back
                _final = np.array(
                    Image.fromarray(_final[100:550, 350:2100]).resize(
                        (2440, 1280), Image.LANCZOS
                    )
                )

                # Flip vertically (sensor rows are bottom-to-top)
                _final = np.flipud(_final)

                # Sharpen
                _img_pil = Image.fromarray(_final, mode="L")
                try:
                    from PIL import ImageFilter
                    _img_pil = _img_pil.filter(
                        ImageFilter.UnsharpMask(radius=2, percent=80, threshold=3)
                    )
                except Exception:
                    pass

                log.info("Flat-field calibration complete: %dx%d",
                         _final.shape[1], _final.shape[0])
                return _img_pil
            else:
                log.warning("Flat-field shape mismatch: %s vs (%d,%d)",
                            _ff_norm.shape, height, width)
        except Exception as _exc:
            log.warning("Flat-field calibration failed: %s", _exc)

    # ── Dark current correction ──────────────────────────────────────
    #   The first ~100 columns are pre-exposure dark frames (before the
    #   X-ray turns on) and the last ~25 columns are post-exposure.
    #   Compute the per-row dark baseline from these regions and subtract
    #   it, interpolating linearly across the scan to account for thermal
    #   drift during the sweep.
    DARK_PRE_COLS = min(100, width // 10)
    DARK_POST_COLS = min(25, width // 20)
    if DARK_PRE_COLS >= 10 and DARK_POST_COLS >= 5:
        from scipy.ndimage import uniform_filter1d as _uf1d
        dark_pre = np.median(img_f[:, :DARK_PRE_COLS], axis=1)
        dark_post = np.median(img_f[:, -DARK_POST_COLS:], axis=1)
        # Filter out anomalous rows (telemetry spikes) in dark profiles
        dp_med = np.median(dark_pre)
        dq_med = np.median(dark_post)
        for r in range(height):
            if abs(dark_pre[r] - dp_med) > 500:
                dark_pre[r] = dp_med
            if abs(dark_post[r] - dq_med) > 500:
                dark_post[r] = dq_med
        dark_pre = _uf1d(dark_pre, size=11)
        dark_post = _uf1d(dark_post, size=11)
        # Subtract with linear interpolation across scan
        for c in range(width):
            t = c / max(width - 1, 1)
            img_f[:, c] -= dark_pre * (1 - t) + dark_post * t
        img_f = np.maximum(img_f, 0)
        log.info("Dark correction: pre=%.0f, post=%.0f, drift=%.0f",
                 dp_med, dq_med, dq_med - dp_med)

    # DEBUG: save after dark correction
    _dbg = ((img_f - img_f.min()) / max(img_f.max() - img_f.min(), 1) * 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage01_dark_corrected.png")
    log.info("DEBUG saved: debug_stage01_dark_corrected.png")

    # ── Detect left/right exposure boundaries (pre-gain correction) ──
    #   After dark subtraction, pre-exposure columns are exactly zero.
    #   Detect boundaries now (clean signal) for use in display-domain
    #   collimator masking later.
    _col_means_dc = np.mean(img_f[height // 4:height * 3 // 4, :], axis=0)
    _dc_peak = np.max(_col_means_dc)
    _dc_thresh = max(_dc_peak * 0.03, 0.5)
    _exposure_left = 0
    for c in range(width):
        if _col_means_dc[c] > _dc_thresh:
            _exposure_left = c
            break
    _exposure_right = width - 1
    for c in range(width - 1, -1, -1):
        if _col_means_dc[c] > _dc_thresh:
            _exposure_right = c
            break
    log.info("Exposure boundaries (dark-corrected): left=%d, right=%d",
             _exposure_left, _exposure_right)

    # ── Flat-field row gain correction ──────────────────────────────
    #   Apply per-row detector gain profile from a blank (no-patient)
    #   exposure capture.  Corrects die-edge fall-off and inter-die
    #   gain variation.  The profile is a 1316-element array normalised
    #   to median=1.0.  If the file is missing, this step is skipped.
    try:
        ff_path = Path(__file__).parent / "flat_field_row_profile.npy"
        if ff_path.exists():
            ff_row = np.load(ff_path)
            if len(ff_row) == height:
                ff_row = np.clip(ff_row, 0.5, 2.0)
                img_f /= ff_row[:, np.newaxis]
                log.info("Flat-field row correction applied (range %.2f–%.2f)",
                         ff_row.min(), ff_row.max())
            else:
                log.warning("Flat-field row profile has %d rows, expected %d — skipped",
                            len(ff_row), height)
    except Exception as exc:
        log.debug("Flat-field row correction skipped: %s", exc)

    # ── SGF per-pixel gain correction ─────────────────────────────────
    #   Apply per-frame, per-row gain profile derived from a blank
    #   (no-patient) exposure.  This corrects frame-level gain steps,
    #   die-edge discontinuities, and per-pixel detector non-uniformity.
    #   The profile is a (num_frames, height) array stored alongside
    #   the flat-field row profile.
    try:
        sgf_path = Path(__file__).parent / "sgf_frame_gain.npy"
        if sgf_path.exists():
            sgf_gain = np.load(sgf_path)  # (num_frames, height)
            n_sgf_frames = sgf_gain.shape[0]
            cpf = 32768.0 / height
            for c in range(width):
                fi = c / cpf
                f0 = min(int(fi), n_sgf_frames - 1)
                f1 = min(f0 + 1, n_sgf_frames - 1)
                t = fi - f0
                gain_col = sgf_gain[f0] * (1 - t) + sgf_gain[f1] * t
                with np.errstate(divide="ignore", invalid="ignore"):
                    corr = np.where(gain_col > 0.5, 1.0 / gain_col, 1.0)
                corr = np.clip(corr, 0.5, 2.0)
                img_f[:, c] *= corr
            log.info("SGF gain correction applied (%d frames × %d rows)",
                     n_sgf_frames, sgf_gain.shape[1])
    except Exception as exc:
        log.debug("SGF gain correction skipped: %s", exc)

    # ── Die junction stitching ────────────────────────────────────────
    #   The DX41 detector has two vertically stacked CMOS dies.  They
    #   may have a dead-row gap AND/OR a gain mismatch.
    #
    #   Detection: look for a STEP discontinuity in the row signal
    #   (not just a smooth gradient from beam geometry).  A real die
    #   junction has a sharp gain change over 1-3 rows.  A beam gradient
    #   is smooth over hundreds of rows.
    #
    #   Sidexis calls this "DoLinearSegmentCorrection".
    from scipy.ndimage import gaussian_filter1d as _gf1d
    active_col_lo = max(width // 5, 50)
    active_col_hi = min(width * 4 // 5, width - 50)
    row_signal = np.mean(img_f[:, active_col_lo:active_col_hi], axis=1)
    mid = height // 2

    telem_row_lo = 1007
    telem_row_hi = 1043

    # ── Find the real die junction by looking for dead/near-dead rows ──
    # The DX41 has a physical gap (1-3 completely dead rows) between dies,
    # located near the center of the 1316-row detector (~row 580).
    # Search only the central 40% to avoid telemetry blocks and
    # collimator shadow regions at the detector edges.
    search_lo = height // 4       # ~329
    search_hi = height * 3 // 4   # ~987 (well above telemetry at 1007)
    local_med = np.median(row_signal[search_lo:search_hi])
    dead_threshold = local_med * 0.10
    dead_mask = row_signal < dead_threshold
    dead_indices = np.nonzero(dead_mask)[0]
    central_dead = dead_indices[(dead_indices >= search_lo) &
                                (dead_indices < search_hi)]

    if len(central_dead) >= 1:
        # Found dead rows — this is the real die junction
        junction_row = int(np.median(central_dead))

        # Expand the dead zone to include adjacent low-signal rows
        # (the gap may be wider than just the completely dead rows)
        gap_start = int(central_dead[0])
        gap_end = int(central_dead[-1])
        # Extend to include any rows within 50% of local signal
        extend_thresh = local_med * 0.50
        while gap_start > 1 and row_signal[gap_start - 1] < extend_thresh:
            gap_start -= 1
        while gap_end < height - 2 and row_signal[gap_end + 1] < extend_thresh:
            gap_end += 1

        # Interpolate across the dead gap using healthy rows on each side
        ab = max(gap_start - 1, 0)
        bl = min(gap_end + 1, height - 1)
        for r in range(gap_start, gap_end + 1):
            t = (r - gap_start + 1) / (gap_end - gap_start + 2)
            img_f[r] = img_f[ab] * (1 - t) + img_f[bl] * t

        log.info("Die junction: row %d, interpolated dead rows %d-%d (%d rows)",
                 junction_row, gap_start, gap_end, gap_end - gap_start + 1)

        # Check for gain step across the gap
        STEP_W = 10
        above_mean = np.mean(row_signal[max(0, gap_start - STEP_W):gap_start])
        below_mean = np.mean(row_signal[gap_end + 1:min(height, gap_end + 1 + STEP_W)])
        if above_mean > 10 and below_mean > 10:
            step_ratio = above_mean / below_mean
            step_pct = abs(step_ratio - 1.0) * 100
            if step_pct > 3.0:
                ratio = max(0.85, min(step_ratio, 1.20))
                blend_half = 120
                for r in range(height):
                    dist = r - junction_row
                    sigmoid = 1.0 / (1.0 + np.exp(-dist / (blend_half / 4)))
                    img_f[r] *= 1.0 * (1 - sigmoid) + ratio * sigmoid
                log.info("Die junction: gain correction %.3f (step=%.1f%%)",
                         ratio, step_pct)
            else:
                log.info("Die junction: step=%.1f%% (no gain correction needed)",
                         step_pct)
    else:
        junction_row = mid
        log.info("Die junction: no dead rows found, skipping correction")

    # DEBUG: save after die junction
    _dbg = ((img_f - img_f.min()) / max(img_f.max() - img_f.min(), 1) * 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage02_die_junction.png")
    log.info("DEBUG saved: debug_stage02_die_junction.png")

    # ── Row repair ─────────────────────────────────────────────────────
    #   1. Telemetry-repair spike rows: the 36-pixel interpolated blocks
    #      drift across columns, creating single-row brightness spikes.
    #   2. Dead/anomalous rows from die gaps and center junction.
    row_means = np.mean(img_f, axis=1)
    global_med = np.median(row_means[row_means > 0]) if np.any(row_means > 0) else 1.0
    spike_thresh = max(global_med * 0.05, 20)  # 5% of signal or minimum 20
    spike_rows: set[int] = set()
    for r in range(1, height - 1):
        baseline = (row_means[r - 1] + row_means[r + 1]) / 2.0
        spike = abs(row_means[r] - baseline)
        if spike > spike_thresh and spike > abs(row_means[r - 1] - row_means[r + 1]) * 2 + 1:
            spike_rows.add(r)

    row_std = np.std(img_f, axis=1)
    for r in range(height):
        if row_std[r] < 5:
            spike_rows.add(r)
        elif row_means[r] > global_med * 5:
            spike_rows.add(r)

    for r in sorted(spike_rows):
        above = r - 1
        while above in spike_rows and above > 0:
            above -= 1
        below = r + 1
        while below in spike_rows and below < height - 1:
            below += 1
        if (above >= 0 and below < height
                and above not in spike_rows and below not in spike_rows):
            t = (r - above) / max(below - above, 1)
            img_f[r] = img_f[above] * (1 - t) + img_f[below] * t
    if spike_rows:
        log.info("Row repair: %d rows interpolated", len(spike_rows))

    # DEBUG: save after row repair
    _dbg = ((img_f - img_f.min()) / max(img_f.max() - img_f.min(), 1) * 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage03_row_repair.png")
    log.info("DEBUG saved: debug_stage03_row_repair.png")

    # ── "Clean" mode: minimal processing, early return ──────────────────
    #   After dark correction, die junction fix, and dead-row repair,
    #   apply a simple percentile contrast stretch (like the scanline
    #   preview) and return.  Skips MUSICA, frame EQ, column corrections,
    #   deband passes — preserves the natural tonal range.
    if mode == "clean":
        # Percentile contrast stretch on non-zero pixels
        nz = img_f[img_f > 0]
        if len(nz) > 0:
            low = np.percentile(nz, 2)
            high = np.percentile(nz, 98)
        else:
            low, high = 0.0, 1.0
        if high <= low:
            high = low + 1
        clipped = np.clip(img_f, low, high)
        normalized = (clipped - low) / (high - low)

        if invert:
            normalized = 1.0 - normalized

        img_8 = (normalized * 255).astype(np.uint8)

        # Mild unsharp mask for a touch of crispness
        img_pil = Image.fromarray(img_8, mode="L")
        try:
            from PIL import ImageFilter
            img_pil = img_pil.filter(
                ImageFilter.UnsharpMask(radius=2, percent=60, threshold=3)
            )
        except Exception:
            pass

        log.info("Clean mode: %dx%d  percentile=[%.0f, %.0f]",
                 width, height, low, high)
        return img_pil

    # ── Frame gain equalization (per-die) ──────────────────────────────
    #   Each TCP frame (~24.9 columns) has slightly different detector
    #   gain.  The two CMOS dies have independent gain characteristics,
    #   so equalization must be computed and applied per-die (Sidexis
    #   does this as "Segment Correction" before enhancement).
    #
    #   For each die region, compute the median gain per frame, smooth
    #   across frames to get the expected exposure trend, then correct
    #   each frame so frame-to-frame steps vanish.
    from scipy.ndimage import uniform_filter1d

    COLS_PER_FRAME = 32768.0 / height  # pixels-per-frame / detector-height
    num_frames = int(width / COLS_PER_FRAME) + 1
    min_signal_global = np.max(np.median(img_f, axis=0)) * 0.05

    # Define per-die stable measurement bands (avoiding junction + telemetry)
    telem_row_lo, telem_row_hi = 1007, 1043
    die_regions = [
        # (label, stable_lo, stable_hi, apply_lo, apply_hi)
        ("upper", height // 6, min(junction_row - 40, height * 5 // 8),
         0, junction_row),
        ("lower", max(junction_row + 40, junction_row + 80),
         min(height - 20, height),
         junction_row, height),
    ]

    def _apply_frame_eq_region(row_lo, row_hi, apply_lo, apply_hi,
                                smooth_sz, clip_lo, clip_hi, label):
        """Apply one pass of frame gain equalization to a row region."""
        # Exclude telemetry rows from measurement
        meas_rows = [r for r in range(row_lo, row_hi)
                     if not (telem_row_lo <= r < telem_row_hi)]
        if len(meas_rows) < 20:
            return
        col_prof = np.median(img_f[meas_rows, :], axis=0)

        gains = np.zeros(num_frames)
        for fi in range(num_frames):
            c0 = int(fi * COLS_PER_FRAME)
            c1 = min(int((fi + 1) * COLS_PER_FRAME), width)
            if c0 < width and c1 > c0:
                gains[fi] = np.median(col_prof[c0:c1])

        ms = np.max(gains) * 0.05
        if ms < 1:
            return
        ag = gains.copy()
        ag[ag < ms] = np.nan
        vm = ~np.isnan(ag)
        if not np.any(vm):
            return
        fv = int(np.argmax(vm))
        lv = len(ag) - 1 - int(np.argmax(vm[::-1]))
        ag[:fv] = ag[fv]
        ag[lv + 1:] = ag[lv]
        nans = np.isnan(ag)
        if np.any(nans):
            ag[nans] = np.interp(
                np.where(nans)[0], np.where(~nans)[0], ag[~nans]
            )
        trend = uniform_filter1d(ag, size=smooth_sz)
        with np.errstate(divide='ignore', invalid='ignore'):
            fc = np.where(gains > ms, trend / gains, 1.0)
        fc = np.clip(fc, clip_lo, clip_hi)
        for c in range(width):
            ff = c / COLS_PER_FRAME
            f0 = int(ff)
            f1 = min(f0 + 1, num_frames - 1)
            t = ff - f0
            corr = fc[f0] * (1 - t) + fc[f1] * t
            img_f[apply_lo:apply_hi, c] *= corr

    for label, stable_lo, stable_hi, apply_lo, apply_hi in die_regions:
        # Pass 1: broad equalization
        _apply_frame_eq_region(stable_lo, stable_hi, apply_lo, apply_hi,
                                smooth_sz=11, clip_lo=0.80, clip_hi=1.25,
                                label=label)
        # Pass 2: narrow equalization
        _apply_frame_eq_region(stable_lo, stable_hi, apply_lo, apply_hi,
                                smooth_sz=3, clip_lo=0.92, clip_hi=1.08,
                                label=label)

    log.info("Frame equalization: %d frames, %d die regions (two-pass)",
             num_frames, len(die_regions))

    # DEBUG: save after frame equalization
    _dbg = ((img_f - img_f.min()) / max(img_f.max() - img_f.min(), 1) * 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage04_frame_eq.png")
    log.info("DEBUG saved: debug_stage04_frame_eq.png")

    # ── Per-column flat-field (residual, per-die) ──────────────────────
    #   After frame equalization, remove any remaining per-column gain
    #   variation.  Compute and apply independently per die to avoid
    #   cross-die gain contamination.
    for label, stable_lo, stable_hi, apply_lo, apply_hi in die_regions:
        meas_rows = [r for r in range(stable_lo, stable_hi)
                     if not (telem_row_lo <= r < telem_row_hi)]
        if len(meas_rows) < 20:
            continue
        col_meds = np.median(img_f[meas_rows, :], axis=0)
        col_meds[col_meds == 0] = 1
        col_trend = uniform_filter1d(col_meds, size=101)
        correction = col_trend / col_meds
        img_f[apply_lo:apply_hi, :] *= correction[np.newaxis, :]

    # ── Linear-domain dead zone interpolation ────────────────────────
    #   Interpolate across the low-signal dead zone around the telemetry
    #   block.  Use linear interpolation between the last healthy row
    #   above and the first healthy row below — no blend zones (they
    #   create an artificial brightness arch that MUSICA amplifies).
    active_col_range = slice(width // 4, width * 3 // 4)
    row_signal_lin = np.mean(img_f[:, active_col_range], axis=1)
    lin_peak = np.max(row_signal_lin[height // 4:height * 3 // 4])
    dead_thresh = lin_peak * 0.20

    dead_zone_top = telem_row_lo
    while dead_zone_top > 1 and row_signal_lin[dead_zone_top - 1] < dead_thresh:
        dead_zone_top -= 1
    dead_zone_bot = telem_row_hi
    while dead_zone_bot < height - 2 and row_signal_lin[dead_zone_bot + 1] < dead_thresh:
        dead_zone_bot += 1

    anchor_above = max(0, dead_zone_top - 1)
    anchor_below = min(height - 1, dead_zone_bot + 1)
    dead_zone_h = anchor_below - anchor_above

    if dead_zone_h > 2:
        for r in range(anchor_above + 1, anchor_below):
            t = (r - anchor_above) / dead_zone_h
            img_f[r] = img_f[anchor_above] * (1 - t) + img_f[anchor_below] * t
        log.info("Dead zone interpolation: rows %d-%d (%d rows)",
                 dead_zone_top, dead_zone_bot, dead_zone_bot - dead_zone_top + 1)

    # DEBUG: save after telemetry row repair (pre-tone mapping)
    _dbg = ((img_f - img_f.min()) / max(img_f.max() - img_f.min(), 1) * 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage05_telem_repair.png")
    log.info("DEBUG saved: debug_stage05_telem_repair.png")

    # ── Column profile correction (linear domain) ───────────────────
    #   Corrects mid-frequency gain drift across groups of TCP frames
    #   (~25-500 column regions) caused by kV ramp, detector drift,
    #   and per-frame equalization residuals.
    #
    #   Uses a RATIO approach: for each column, compute
    #       ratio = col_mean / smooth(col_mean, sigma=200)
    #   This ratio captures only deviations from the slowly-varying
    #   beam profile (bell curve). Dividing by the ratio flattens
    #   frame-group steps without altering the natural gradient.
    from scipy.ndimage import gaussian_filter1d as _gf1d

    # Use rows that avoid dead zone and telemetry for clean measurement
    _meas_rows_upper = [r for r in range(50, min(anchor_above, height))
                        if not (telem_row_lo <= r < telem_row_hi)]
    _meas_rows_lower = [r for r in range(min(anchor_below + 1, height),
                                         max(height - 30, 0))
                        if not (telem_row_lo <= r < telem_row_hi)]
    _meas_rows = _meas_rows_upper + _meas_rows_lower
    if len(_meas_rows) > 100:
        _col_means = np.mean(img_f[_meas_rows, :], axis=0)
    else:
        _col_means = np.mean(img_f, axis=0)

    # Detect the active content range in the LINEAR domain.
    #   _exposure_left only marks dark vs signal — when the scan starts
    #   with the X-ray already on (no dark pre-scan), _exposure_left ≈ 0
    #   and the first ~200 columns are flat direct beam (no anatomy).
    #   Including these in the Gaussian baseline corrupts the correction.
    #
    #   Detect per-column variance: anatomy has high row-to-row variation,
    #   flat direct beam has near-zero variance.
    _COL_STD_THRESH = 0.10  # fraction of column mean — below = flat beam
    _col_stds = np.std(img_f[_meas_rows, :], axis=0) if len(_meas_rows) > 100 \
        else np.std(img_f, axis=0)
    _col_rel_std = np.where(_col_means > 1.0, _col_stds / _col_means, 0.0)

    # Scan from left: find first column with relative std > threshold
    _active_start = min(_exposure_left + 30, width - 1)
    for c in range(_exposure_left, min(_exposure_left + width // 4, width)):
        if _col_rel_std[c] > _COL_STD_THRESH:
            _active_start = c + 10  # inset slightly past the transition
            break

    # Scan from right: find last column with relative std > threshold
    _active_end = max(_exposure_right - 30, _active_start + 1)
    for c in range(_exposure_right, max(_exposure_right - width // 4, -1), -1):
        if _col_rel_std[c] > _COL_STD_THRESH:
            _active_end = c - 10
            break

    _active_end = max(_active_end, _active_start + 1)
    log.info("Column correction active range: [%d, %d] "
             "(exposure=[%d,%d], content-std threshold=%.2f)",
             _active_start, _active_end, _exposure_left, _exposure_right,
             _COL_STD_THRESH)

    # Compute median signal in the active region.  If too low (phantom
    # or empty scan), skip the correction — there's no frame-group
    # banding to fix when there's no X-ray signal.
    _active_means = _col_means[_active_start:_active_end].astype(np.float64)
    _active_median = float(np.median(_active_means))
    _COL_CORRECT_MIN_SIGNAL = 50.0  # linear-domain minimum (well above noise)

    _correction = np.ones(width, dtype=np.float32)
    if _active_median >= _COL_CORRECT_MIN_SIGNAL and len(_active_means) > 100:
        # Smooth the column profile with a wide Gaussian to get the "expected"
        # beam shape.  sigma=200 cols spans ~400 cols (8+ frame groups) — this
        # preserves the natural jaw-arch gradient while averaging out frame-group
        # steps (which are 25-300 cols wide).
        COL_SMOOTH_SIGMA = 200
        _smooth = _gf1d(_active_means, sigma=COL_SMOOTH_SIGMA).astype(np.float32)

        # Ratio: how each column deviates from the smooth beam profile
        # Values >1 = column is brighter than expected, <1 = dimmer
        _safe_smooth = np.where(_smooth > 1.0, _smooth, 1.0)
        _ratio = (_active_means / _safe_smooth).astype(np.float32)

        # The correction is 1/ratio — divides out the deviation
        _safe_ratio = np.where(np.abs(_ratio) > 0.01, _ratio, 1.0)
        _correction[_active_start:_active_end] = 1.0 / _safe_ratio
        # Clip: max ±15% correction per column (safety limit)
        _correction = np.clip(_correction, 0.85, 1.15)
        log.info("Column profile correction APPLIED: sigma=%d  "
                 "active=[%d,%d] (%d cols)  median_signal=%.0f",
                 COL_SMOOTH_SIGMA, _active_start, _active_end,
                 _active_end - _active_start, _active_median)
    else:
        log.info("Column profile correction SKIPPED: median signal=%.1f "
                 "(min=%.1f)", _active_median, _COL_CORRECT_MIN_SIGNAL)

    # Store content boundary for later use by display-domain masking
    _linear_content_left = _active_start
    _linear_content_right = _active_end

    # Save debug: before correction (percentile stretch for visibility)
    _p2, _p98 = np.percentile(img_f[img_f > 0], [2, 98]) if np.any(img_f > 0) else (0, 1)
    _dbg = np.clip((img_f - _p2) / max(_p98 - _p2, 1) * 255, 0, 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_before_colcorrect.png")

    # Apply correction to every row
    img_f *= _correction[np.newaxis, :]

    # Save debug: after correction
    _dbg = np.clip((img_f - _p2) / max(_p98 - _p2, 1) * 255, 0, 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_after_colcorrect.png")

    # Log correction summary
    _corr_active = _correction[_active_start:_active_end]
    _n_clipped = int(np.sum((_corr_active <= 0.851) | (_corr_active >= 1.149)))
    _corr_std = float(np.std(_corr_active))
    log.info("Column profile correction: active=[%d,%d]  median_signal=%.0f  "
             "correction_std=%.4f  range=[%.4f, %.4f]  clipped=%d/%d",
             _active_start, _active_end, _active_median,
             _corr_std, float(_corr_active.min()), float(_corr_active.max()),
             _n_clipped, len(_corr_active))

    # DEBUG: save pre-MUSICA (after gamma, before MUSICA)
    # (inserted below after img_norm is computed)

    # ── WWE tone mapping + MUSICA contrast enhancement ─────────────
    #   1. Percentile-normalise to [0,1] and apply gamma (0.4) for
    #      dental display convention (bone = bright, air = dark).
    #   2. Horizontal deband: gentle column-axis Gaussian blur to soften
    #      frame-boundary step edges without blurring vertical anatomy.
    #   3. MUSICA: Laplacian pyramid multi-scale contrast amplification.
    #      Fine/medium detail boosted; coarse scale (where banding lives)
    #      suppressed. Non-linear tanh compression prevents halos.
    #   4. Gentle CLAHE for final local adaptation.
    from scipy.ndimage import gaussian_filter, gaussian_filter1d

    WWE_GAMMA = 0.4
    p_lo, p_hi = np.percentile(img_f, [0.5, 99.5])
    if p_hi <= p_lo:
        p_hi = p_lo + 1.0
    img_norm = np.clip((img_f - p_lo) / (p_hi - p_lo), 0, 1)
    if invert:
        img_norm = 1.0 - np.power(img_norm, WWE_GAMMA)
    else:
        img_norm = np.power(img_norm, WWE_GAMMA)

    # DEBUG: save after WWE gamma (before deband/MUSICA)
    _dbg = (np.clip(img_norm, 0, 1) * 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage06_wwe_gamma.png")
    log.info("DEBUG saved: debug_stage06_wwe_gamma.png")

    # Horizontal deband: soften frame-boundary gain steps (sigma=4 cols).
    # BUG 5 FIX: Use protected smoothing to preserve telemetry hole boundaries
    # and tooth/bone contrast near repaired zones.
    detected_hole_cols = []
    if repair_mask is not None:
        detected_hole_cols = sorted(list(set(np.where(np.any(repair_mask == 255, axis=0))[0])))
    
    img_norm = _protected_row_smooth(img_norm, hole_columns=detected_hole_cols, smooth_kernel=5, protection_radius=2)

    # Save glow region diagnostic diff (Bug 2 Validation)
    try:
        if repair_mask is not None:
            # We use img_f (linear domain) for the raw vs repaired diff before gamma/MUSICA
            # We simulate "raw" by restoring the 0x20 telemetry noise where the mask is 255
            # Actually, to be truly diagnostic, we want the ORIGINAL raw data, but img_f 
            # at this point is already repaired. We can mock the hole by zeroing repaired pixels.
            raw_mock = img_f.copy()
            raw_mock[repair_mask == 255] = 0
            _save_glow_region_diff(raw_mock, img_f, detected_hole_cols)
    except Exception as exc:
        log.debug("Glow region diff diagnostic failed: %s", exc)

    # ── Display-domain deband (VFilter + column equalization) ──────
    #   Sidexis applies "VFilter Correction" to remove per-row detector
    #   gain banding and per-column frame gain steps.  Work in the
    #   gamma-corrected domain so corrections match visual perception.

    # Per-row normalization (VFilter): removes fine horizontal banding
    # from per-row detector gain variations.  Use a tight sigma (3) to
    # catch individual row-level brightness variations (1-2 px lines).
    stable_cols = slice(width // 4, width * 3 // 4)
    row_means_d = np.mean(img_norm[:, stable_cols], axis=1)
    row_means_d = np.maximum(row_means_d, 0.01)
    row_trend_d = gaussian_filter1d(row_means_d.astype(np.float64),
                                     sigma=3).astype(np.float32)
    row_corr = np.clip(row_trend_d / row_means_d, 0.82, 1.22)
    img_norm *= row_corr[:, np.newaxis]

    # Per-column normalization: removes vertical banding (frame gain)
    stable_rows = slice(height // 6, height * 5 // 8)
    col_means_d = np.mean(img_norm[stable_rows, :], axis=0)
    col_means_d = np.maximum(col_means_d, 0.01)
    col_trend_d = uniform_filter1d(col_means_d.astype(np.float64),
                                    size=51).astype(np.float32)
    col_corr = np.clip(col_trend_d / col_means_d, 0.92, 1.08)
    img_norm *= col_corr[np.newaxis, :]
    img_norm = np.clip(img_norm, 0, 1)

    # DEBUG: save after VFilter deband (before MUSICA)
    _dbg = (np.clip(img_norm, 0, 1) * 255).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage07_vfilter_deband.png")
    log.info("DEBUG saved: debug_stage07_vfilter_deband.png")

    # ── Pre-MUSICA row median filter ────────────────────────────────
    #   Median filter in the row direction (size=3) to remove single-row
    #   brightness outliers that VFilter couldn't correct (clip limits).
    #   Unlike Gaussian blur, median preserves edges while eliminating
    #   the isolated bright/dark rows that MUSICA would amplify into
    #   visible horizontal stripes.
    from scipy.ndimage import median_filter as _medfilt
    img_norm = _medfilt(img_norm, size=(3, 1))

    # Save pre-MUSICA image for spatial blending below
    pre_musica_16 = (img_norm * 65535).astype(np.uint16)

    # MUSICA Laplacian pyramid (4 detail scales + residual)
    MUSICA_SIGMAS = [2, 8, 32, 128]
    MUSICA_GAINS = [0.5, 1.8, 1.2, 0.15]

    levels = [img_norm]
    for sigma in MUSICA_SIGMAS:
        levels.append(gaussian_filter(img_norm, sigma=sigma))

    laplacian = [levels[i] - levels[i + 1] for i in range(len(levels) - 1)]
    residual = levels[-1]

    # Non-linear boost: tanh compression prevents halos at strong edges
    for i in range(len(laplacian)):
        laplacian[i] = np.tanh(laplacian[i] * MUSICA_GAINS[i] * 3) / 3

    # Reconstruct: flatten residual toward global mean (reduces banding)
    global_mean = np.median(residual)
    reconstructed = residual * 0.7 + global_mean * 0.3
    for lap in laplacian:
        reconstructed += lap
    reconstructed = np.clip(reconstructed, 0, 1)

    img_16 = (reconstructed * 65535).astype(np.uint16)

    try:
        import cv2
        clahe = cv2.createCLAHE(clipLimit=1.0, tileGridSize=(8, 16))
        img_16 = clahe.apply(img_16)
    except ImportError:
        pass

    # ── Spatial MUSICA blending ──────────────────────────────────────
    #   MUSICA amplifies per-row detector gain banding in the bottom
    #   region where there's little anatomical content to mask it.
    #   Blend the MUSICA output with the pre-MUSICA image: full MUSICA
    #   in the top (anatomy-rich), tapering to zero MUSICA in the bottom
    #   (detector-structure-dominated).  The taper starts at the dead zone.
    #   In the original detector coords:
    #     dead_zone_top ~ row 982  (cropped ~964)
    #   We taper from 100% MUSICA above the dead zone to 0% at the bottom.
    MUSICA_TAPER_START = dead_zone_top if 'dead_zone_top' in dir() else height * 3 // 4
    MUSICA_TAPER_END = height  # 0% MUSICA at the bottom
    taper_len = max(MUSICA_TAPER_END - MUSICA_TAPER_START, 1)

    img_16f_blend = img_16.astype(np.float32)
    pre_16f = pre_musica_16.astype(np.float32)
    for r in range(MUSICA_TAPER_START, min(MUSICA_TAPER_END, height)):
        alpha = 1.0 - (r - MUSICA_TAPER_START) / taper_len
        alpha = max(0.0, min(1.0, alpha))
        img_16f_blend[r] = img_16f_blend[r] * alpha + pre_16f[r] * (1.0 - alpha)
    img_16 = np.clip(img_16f_blend, 0, 65535).astype(np.uint16)
    log.info("MUSICA spatial blend: taper rows %d-%d (100%%->0%%)",
             MUSICA_TAPER_START, MUSICA_TAPER_END)

    log.info("Applied WWE gamma=%.1f + MUSICA multi-scale enhancement", WWE_GAMMA)

    # DEBUG: save after MUSICA + CLAHE (before post-MUSICA telem repair)
    _dbg = (img_16 >> 8).astype(np.uint8)
    Image.fromarray(_dbg).save("debug_stage08_musica_clahe.png")
    log.info("DEBUG saved: debug_stage08_musica_clahe.png")

    # Post-MUSICA telemetry repair DISABLED: the dead zone was already
    # interpolated in linear domain.  Mirror-blending after MUSICA
    # reintroduces noisy detector rows into the smooth interpolated zone.

    # ── Post-MUSICA per-row deband (two-pass) ──────────────────────
    #   MUSICA amplifies per-row detector gain variations, especially in
    #   the lower die region where image content is sparse.  Two passes:
    #   Pass 1 (sigma=2): catches single-row brightness spikes
    #   Pass 2 (sigma=8): catches multi-row oscillations from MUSICA halos
    img_16f2 = img_16.astype(np.float32)
    stable_cols_pm = slice(width // 4, width * 3 // 4)

    for pm_pass, pm_sigma, pm_clip_lo, pm_clip_hi in [
        (1, 2, 0.80, 1.25),  # tight: single-row spikes
        (2, 8, 0.85, 1.18),  # broad: multi-row oscillations
    ]:
        row_means_pm = np.mean(img_16f2[:, stable_cols_pm], axis=1)
        row_means_pm = np.maximum(row_means_pm, 1.0)
        row_trend_pm = gaussian_filter1d(row_means_pm.astype(np.float64),
                                          sigma=pm_sigma).astype(np.float32)
        row_corr_pm = np.clip(row_trend_pm / row_means_pm, pm_clip_lo, pm_clip_hi)
        img_16f2 *= row_corr_pm[:, np.newaxis]
        n_corr = np.sum(np.abs(row_corr_pm - 1.0) > 0.01)
        log.info("Post-MUSICA deband pass %d (σ=%d): %d rows (range %.3f-%.3f)",
                 pm_pass, pm_sigma, n_corr, row_corr_pm.min(), row_corr_pm.max())

    img_16 = np.clip(img_16f2, 0, 65535).astype(np.uint16)

    img_8bit = (img_16 >> 8).astype(np.uint8)

    # ── Tone mapping: percentile stretch + gamma ────────────────────
    #   Stretch active pixel range to [0, 255], then apply a mild gamma
    #   to expand highlights (Sidexis convention: bone=medium gray, soft
    #   tissue=light gray, bite block=bright, background=dark with texture).
    #   Gamma < 1 lifts midtones and spreads highlights.
    TONE_GAMMA = 0.90
    img_f8 = img_8bit.astype(np.float32)
    active_mask = img_f8 > 0
    if np.any(active_mask):
        p_lo, p_hi = np.percentile(img_f8[active_mask], [1, 99])
        if p_hi > p_lo:
            stretched = np.clip((img_f8 - p_lo) / (p_hi - p_lo), 0, 1)
            stretched = np.power(stretched, TONE_GAMMA)
            img_f8 = np.where(active_mask, stretched * 250 + 5, 0)
            img_8bit = np.clip(img_f8, 0, 255).astype(np.uint8)
            log.info("Tone stretch: [%.0f, %.0f] -> [5, 255] gamma=%.2f",
                     p_lo, p_hi, TONE_GAMMA)

    # DEBUG: save after tone LUT (before collimator edges)
    Image.fromarray(img_8bit).save("debug_stage09_tone_lut.png")
    log.info("DEBUG saved: debug_stage09_tone_lut.png")

    # ── Per-die row correction (display domain) ────────────────────────
    #   Smooths per-row brightness variation from frame-group banding.
    #   Runs independently on each die half (sigma=20).
    _die_boundary_disp = 580
    _prc_left = (_linear_content_left + 50) if '_linear_content_left' in dir() else 150
    _prc_right = (_linear_content_right - 50) if '_linear_content_right' in dir() else width - 150
    _img_f_prc = img_8bit.astype(np.float32)

    for _prc_label, _prc_r_lo, _prc_r_hi in [
        ("upper", 80, max(80, _die_boundary_disp - 20)),
        ("lower", min(height - 80, _die_boundary_disp + 20), min(height - 80, 1200)),
    ]:
        if _prc_r_hi <= _prc_r_lo + 50:
            continue
        _prc_row_means = np.array([
            float(np.mean(_img_f_prc[r, _prc_left:_prc_right]))
            for r in range(_prc_r_lo, _prc_r_hi)
        ], dtype=np.float64)
        _prc_row_means = np.maximum(_prc_row_means, 1.0)
        _prc_row_smooth = gaussian_filter1d(_prc_row_means, sigma=20).astype(np.float32)
        _prc_row_corr = np.clip(_prc_row_smooth / _prc_row_means, 0.97, 1.03)
        _prc_std = float(np.std(_prc_row_corr))
        if _prc_std > 0.003:
            for _i, _r in enumerate(range(_prc_r_lo, _prc_r_hi)):
                _img_f_prc[_r, :] *= _prc_row_corr[_i]
            log.info("Per-die row corr (%s): rows [%d,%d]  correction_std=%.4f",
                     _prc_label, _prc_r_lo, _prc_r_hi, _prc_std)

    img_8bit = np.clip(_img_f_prc, 0, 255).astype(np.uint8)

    # ── Post-MUSICA column correction (display domain) ────────────────
    #   The linear-domain column correction (stage 1, sigma=200) removes
    #   slow beam-shape variation.  But the gamma inversion + MUSICA
    #   pyramid re-introduces column banding in the display domain.
    #   This stage 2 catches the residual frame-group banding (period
    #   ~30-80 cols) that MUSICA amplified.
    _img_f_cc2 = img_8bit.astype(np.float32)
    _cc2_meas_rows = slice(80, min(height - 80, 1200))
    _cc2_left = _linear_content_left if '_linear_content_left' in dir() else 100
    _cc2_right = _linear_content_right if '_linear_content_right' in dir() else width - 100

    _cc2_col_means = np.mean(_img_f_cc2[_cc2_meas_rows, :], axis=0).astype(np.float64)
    _cc2_active = _cc2_col_means[_cc2_left:_cc2_right]

    CC2_SIGMA = 40  # catches ~30-80 col frame-group banding
    _cc2_smooth = _gf1d(_cc2_active, sigma=CC2_SIGMA).astype(np.float32)
    _cc2_safe = np.where(_cc2_smooth > 1.0, _cc2_smooth, 1.0)
    _cc2_ratio = (_cc2_active / _cc2_safe).astype(np.float32)
    _cc2_corr = np.clip(1.0 / np.where(np.abs(_cc2_ratio) > 0.01, _cc2_ratio, 1.0),
                        0.85, 1.15)
    _cc2_std = float(np.std(_cc2_corr))

    if _cc2_std > 0.005:  # meaningful banding to correct
        _cc2_full = np.ones(width, dtype=np.float32)
        _cc2_full[_cc2_left:_cc2_right] = _cc2_corr
        _img_f_cc2 *= _cc2_full[np.newaxis, :]
        img_8bit = np.clip(_img_f_cc2, 0, 255).astype(np.uint8)
        log.info("Post-MUSICA column correction (stage 2): sigma=%d  "
                 "active=[%d,%d]  correction_std=%.4f  range=[%.4f, %.4f]",
                 CC2_SIGMA, _cc2_left, _cc2_right, _cc2_std,
                 float(_cc2_corr.min()), float(_cc2_corr.max()))
    else:
        log.info("Post-MUSICA column correction SKIPPED: correction_std=%.4f < 0.005",
                 _cc2_std)

    # ── Left/right collimator masking ─────────────────────────────────
    #   Two-stage detection:
    #   1. Dark-column boundaries (_exposure_left/_exposure_right) from
    #      dark correction — catches pre/post exposure dead columns.
    #   2. Content boundary detection — catches direct-beam columns that
    #      have signal but no anatomy (flat, high brightness, low variance).
    #      This handles scans where X-ray starts before capture begins
    #      (no dark pre-scan period), leaving _exposure_left near 0.
    FADE_WIDTH = 25

    # Stage 1: dark-column boundaries
    lin_left_edge = _exposure_left
    lin_right_edge = _exposure_right

    # Stage 2: content boundary detection
    #   Scan from each edge inward looking for where per-column variance
    #   rises (anatomy) vs flat direct beam (bright, uniform).
    _meas_slice = slice(height // 4, height * 3 // 4)
    _content_left = lin_left_edge
    _content_right = lin_right_edge
    _CONTENT_STD_THRESH = 12.0  # per-column std below this = no anatomy
    _CONTENT_SCAN_MAX = width // 4  # don't scan more than 25% of width

    # Left: scan rightward from lin_left_edge
    for c in range(lin_left_edge, min(lin_left_edge + _CONTENT_SCAN_MAX, width)):
        col_std = float(np.std(img_8bit[_meas_slice, c].astype(np.float32)))
        if col_std > _CONTENT_STD_THRESH:
            _content_left = c
            break
    else:
        _content_left = lin_left_edge

    # Right: scan leftward from lin_right_edge
    for c in range(lin_right_edge, max(lin_right_edge - _CONTENT_SCAN_MAX, -1), -1):
        col_std = float(np.std(img_8bit[_meas_slice, c].astype(np.float32)))
        if col_std > _CONTENT_STD_THRESH:
            _content_right = c
            break
    else:
        _content_right = lin_right_edge

    # Use the further-inward of all detections (dark, display-std, linear-std)
    lin_left_edge = max(lin_left_edge, _content_left,
                        _linear_content_left if '_linear_content_left' in dir() else 0)
    lin_right_edge = min(lin_right_edge, _content_right,
                         _linear_content_right if '_linear_content_right' in dir() else width)

    log.info("Content boundaries: left=%d (dark=%d, content=%d)  "
             "right=%d (dark=%d, content=%d)",
             lin_left_edge, _exposure_left, _content_left,
             lin_right_edge, _exposure_right, _content_right)

    # Fade left edge
    for c in range(min(width, lin_left_edge + FADE_WIDTH)):
        if c < lin_left_edge:
            img_8bit[:, c] = 0
        else:
            t = (c - lin_left_edge) / FADE_WIDTH
            img_8bit[:, c] = (img_8bit[:, c].astype(np.float32) * t).astype(np.uint8)

    # Fade right edge
    for c in range(max(0, lin_right_edge - FADE_WIDTH), width):
        if c > lin_right_edge:
            img_8bit[:, c] = 0
        else:
            t = (lin_right_edge - c) / FADE_WIDTH
            img_8bit[:, c] = (img_8bit[:, c].astype(np.float32) * t).astype(np.uint8)

    log.info("Collimator L/R edges: left=%d, right=%d (fade=%d)",
             lin_left_edge, lin_right_edge, FADE_WIDTH)

    # ── Top/bottom collimator fade (display domain) ────────────────
    #   Detect collimator edges in the display domain by scanning for
    #   brightness drop.  Only fades the actual image edges where the
    #   collimator physically blocks the beam (top/bottom few rows).
    row_brightness = np.mean(img_8bit[:, width//4:width*3//4], axis=1).astype(np.float32)
    row_smooth_c = uniform_filter1d(row_brightness, size=11)
    upper_peak = np.max(row_smooth_c[height//4:height*3//4])
    VFADE = 20

    # Bottom: scan from the very bottom upward for the first row with signal
    bot_edge = None
    bot_thresh = upper_peak * 0.15
    for r in range(height - 1, height * 3 // 4, -1):
        if row_smooth_c[r] > bot_thresh:
            bot_edge = r + 1  # first dark row below active content
            break

    if bot_edge is not None and bot_edge < height - 5:
        fade_start = max(0, bot_edge - VFADE)
        for r in range(fade_start, min(height, bot_edge)):
            t = max(0.0, (bot_edge - r) / VFADE)
            img_8bit[r, :] = (img_8bit[r, :].astype(np.float32) * t).astype(np.uint8)
        img_8bit[bot_edge:, :] = 0
        log.info("Bottom collimator fade: row %d (VFADE=%d)", bot_edge, VFADE)

    # Top: scan from the very top downward for the first row with signal
    top_edge = None
    for r in range(0, height // 4):
        if row_smooth_c[r] > bot_thresh:
            top_edge = r  # first active row
            break

    if top_edge is not None and top_edge > 5:
        fade_end = min(height, top_edge + VFADE)
        for r in range(top_edge, fade_end):
            t = max(0.0, (r - top_edge) / VFADE)
            img_8bit[r, :] = (img_8bit[r, :].astype(np.float32) * t).astype(np.uint8)
        img_8bit[:top_edge, :] = 0
        log.info("Top collimator fade: row %d (VFADE=%d)", top_edge, VFADE)

    # DEBUG: save after collimator edges (before corner mask)
    Image.fromarray(img_8bit).save("debug_stage10_collimator.png")
    log.info("DEBUG saved: debug_stage10_collimator.png")

    # ── Bottom/top brightness spike suppression ──────────────────────
    #   The detector bottom (and sometimes top) rows exhibit a brightness
    #   spike from scatter radiation and detector edge effects.  This
    #   creates bright bands, worst in the corners where L/R fade
    #   doesn't reach.  The global top/bottom fade misses it because
    #   it looks for signal DROP — these rows have MORE signal.
    #
    #   Approach: compare each row's per-column brightness to a
    #   "reference" band (the interior rows 30-60px above/below).
    #   Where a row is significantly brighter than its reference,
    #   clamp it down.
    _img_fc = img_8bit.astype(np.float32)

    # Measure before
    _bl_before = _img_fc[height - 180:, :150]
    _br_before = _img_fc[height - 180:, -150:]
    _bl_pct_before = float(np.sum(_bl_before > 240) / max(_bl_before.size, 1) * 100)
    _br_pct_before = float(np.sum(_br_before > 240) / max(_br_before.size, 1) * 100)

    # --- Bottom spike suppression ---
    # Reference: rows at 70%-85% height (interior, above any bottom spike)
    _ref_lo = int(height * 0.70)
    _ref_hi = int(height * 0.85)
    _ref_band_bot = np.mean(_img_fc[_ref_lo:_ref_hi, :], axis=0)  # per-col reference
    _ref_band_bot = np.maximum(_ref_band_bot, 1.0)
    # Smooth the reference to avoid amplifying column noise
    _ref_band_bot = gaussian_filter1d(_ref_band_bot.astype(np.float64),
                                      sigma=30).astype(np.float32)

    # Scan from bottom: for each row in the bottom 15%, check per-column
    # brightness ratio against the reference band.
    SPIKE_ZONE_BOT = int(height * 0.15)  # bottom 15% of image
    SPIKE_THRESH = 1.20   # 20% brighter than reference = spike
    SPIKE_FADE = 25       # fade width for the suppression

    _spike_start_bot = height  # will be lowered to first spiking row
    for r in range(height - 1, height - SPIKE_ZONE_BOT - 1, -1):
        row_data = _img_fc[r, :]
        # Ratio vs reference for columns with actual signal
        _signal_cols = _ref_band_bot > 10
        if not np.any(_signal_cols):
            continue
        ratio = np.median(row_data[_signal_cols] / _ref_band_bot[_signal_cols])
        if ratio > SPIKE_THRESH:
            _spike_start_bot = r
        else:
            break  # found a non-spiking row — stop scanning upward

    if _spike_start_bot < height - 2:
        # Apply per-column clamping with a smooth fade-in zone above the
        # spike boundary.  Without the fade, the hard clamp creates a
        # bright horizontal line at _spike_start_bot.
        SPIKE_BLEND = 30  # rows of gradual transition above spike start
        cap = _ref_band_bot * 1.05
        blend_start = max(0, _spike_start_bot - SPIKE_BLEND)
        for r in range(blend_start, height):
            row_data = _img_fc[r, :]
            clamped = np.minimum(row_data, cap)
            if r < _spike_start_bot:
                # Fade-in zone: blend from 0% clamping to 100%
                alpha = (r - blend_start) / SPIKE_BLEND  # 0→1
                _img_fc[r, :] = row_data * (1 - alpha) + clamped * alpha
            else:
                _img_fc[r, :] = clamped
        # Fade the last few rows to black (detector edge)
        _edge_fade = min(8, height - _spike_start_bot)
        for r in range(height - _edge_fade, height):
            t = (height - r) / _edge_fade
            _img_fc[r, :] *= t
        log.info("Bottom spike suppression: rows %d-%d clamped, blend=%d (ratio>%.2f)",
                 _spike_start_bot, height - 1, SPIKE_BLEND, SPIKE_THRESH)

    # --- Top spike suppression ---
    _ref_lo_t = int(height * 0.15)
    _ref_hi_t = int(height * 0.30)
    _ref_band_top = np.mean(_img_fc[_ref_lo_t:_ref_hi_t, :], axis=0)
    _ref_band_top = np.maximum(_ref_band_top, 1.0)
    _ref_band_top = gaussian_filter1d(_ref_band_top.astype(np.float64),
                                      sigma=30).astype(np.float32)

    SPIKE_ZONE_TOP = int(height * 0.15)
    _spike_end_top = -1
    for r in range(0, SPIKE_ZONE_TOP):
        row_data = _img_fc[r, :]
        _signal_cols = _ref_band_top > 10
        if not np.any(_signal_cols):
            continue
        ratio = np.median(row_data[_signal_cols] / _ref_band_top[_signal_cols])
        if ratio > SPIKE_THRESH:
            _spike_end_top = r
        else:
            break

    if _spike_end_top > 0:
        cap_t = _ref_band_top * 1.05
        SPIKE_BLEND_T = 30  # fade-out zone below spike end
        blend_end_t = min(height, _spike_end_top + 1 + SPIKE_BLEND_T)
        for r in range(0, blend_end_t):
            row_data = _img_fc[r, :]
            clamped = np.minimum(row_data, cap_t)
            if r > _spike_end_top:
                # Fade-out zone: blend from 100% clamping back to 0%
                alpha = 1.0 - (r - _spike_end_top - 1) / SPIKE_BLEND_T  # 1→0
                _img_fc[r, :] = row_data * (1 - alpha) + clamped * alpha
            else:
                _img_fc[r, :] = clamped
        _edge_fade_t = min(8, _spike_end_top + 1)
        for r in range(0, _edge_fade_t):
            t = r / _edge_fade_t
            _img_fc[r, :] *= t
        log.info("Top spike suppression: rows 0-%d clamped, blend=%d",
                 _spike_end_top, SPIKE_BLEND_T)

    img_8bit = np.clip(_img_fc, 0, 255).astype(np.uint8)

    # Measure after
    _bl_after = img_8bit[height - 180:, :150].astype(np.float32)
    _br_after = img_8bit[height - 180:, -150:].astype(np.float32)
    _bl_pct_after = float(np.sum(_bl_after > 240) / max(_bl_after.size, 1) * 100)
    _br_pct_after = float(np.sum(_br_after > 240) / max(_br_after.size, 1) * 100)
    log.info("Edge spike fix: BL>240: %.1f%%->%.1f%%  BR>240: %.1f%%->%.1f%%",
             _bl_pct_before, _bl_pct_after, _br_pct_before, _br_pct_after)

    # DEBUG: save result
    Image.fromarray(img_8bit).save("debug_stage11_edge_spike.png")
    log.info("DEBUG saved: debug_stage11_edge_spike.png")

    # ── Die junction equalization (content-aware) ───────────────────
    #   Only apply if background margins show a consistent gain step.
    DIE_BOUNDARY = 580
    _die_img_f = img_8bit.astype(np.float32)
    _die_steps = {}
    for _name, _c_lo, _c_hi in [("left_bg", 50, min(200, width)),
                                  ("right_bg", max(0, width - 200), width - 50)]:
        _above = float(np.mean(_die_img_f[max(0, DIE_BOUNDARY - 60):max(0, DIE_BOUNDARY - 10),
                                           _c_lo:_c_hi]))
        _below = float(np.mean(_die_img_f[min(height, DIE_BOUNDARY + 10):min(height, DIE_BOUNDARY + 60),
                                           _c_lo:_c_hi]))
        _die_steps[_name] = _above / max(_below, 1.0)
    _bg_avg_step = (abs(_die_steps.get("left_bg", 1.0) - 1.0) +
                    abs(_die_steps.get("right_bg", 1.0) - 1.0)) / 2
    if _bg_avg_step > 0.03:
        _die_scale = np.clip((_die_steps["left_bg"] + _die_steps["right_bg"]) / 2,
                             0.85, 1.15)
        if abs(_die_scale - 1.0) > 0.02:
            _die_img_f[DIE_BOUNDARY:, :] *= _die_scale
            for r in range(max(0, DIE_BOUNDARY - 60), DIE_BOUNDARY):
                t = (r - (DIE_BOUNDARY - 60)) / 60
                _die_img_f[r, :] *= 1.0 + (_die_scale - 1.0) * 0.5 * (1.0 - np.cos(np.pi * t))
            img_8bit = np.clip(_die_img_f, 0, 255).astype(np.uint8)
            log.info("Die junction eq APPLIED: scale=%.4f (bg_step=%.1f%%)",
                     _die_scale, _bg_avg_step * 100)
    else:
        log.info("Die junction eq SKIPPED: bg_step=%.1f%% (anatomy, not die)",
                 _bg_avg_step * 100)

    # ── Anatomy-only tone match ──────────────────────────────────────
    TONE_ANAT_THRESH = 60
    TONE_TARGET_P10, TONE_TARGET_P50, TONE_TARGET_P90 = 82.0, 110.0, 138.0
    _tone_int = img_8bit[200:min(height - 200, 1000),
                         width // 5:width * 4 // 5].astype(np.float32)
    _tone_anat = _tone_int[_tone_int > TONE_ANAT_THRESH]
    if len(_tone_anat) > 1000:
        _cur_p10 = float(np.percentile(_tone_anat, 10))
        _cur_p90 = float(np.percentile(_tone_anat, 90))
        if _cur_p90 > _cur_p10 + 5:
            _img_tone = img_8bit.astype(np.float32)
            _active_tone = _img_tone > 5
            _stretched = ((_img_tone - _cur_p10) / (_cur_p90 - _cur_p10)
                          * (TONE_TARGET_P90 - TONE_TARGET_P10) + TONE_TARGET_P10)
            _s_int = _stretched[200:min(height - 200, 1000),
                                width // 5:width * 4 // 5]
            _s_anat = _s_int[_s_int > TONE_ANAT_THRESH]
            _gamma_t = 1.0
            if len(_s_anat) > 100:
                _cur_p50_s = float(np.percentile(_s_anat, 50))
                _cur_norm = (_cur_p50_s - TONE_TARGET_P10) / (TONE_TARGET_P90 - TONE_TARGET_P10)
                _tw_norm = (TONE_TARGET_P50 - TONE_TARGET_P10) / (TONE_TARGET_P90 - TONE_TARGET_P10)
                if 0.05 < _cur_norm < 0.95 and 0.05 < _tw_norm < 0.95:
                    _gamma_t = np.clip(np.log(_tw_norm) / np.log(_cur_norm), 0.5, 2.0)
                    _norm = np.clip((_stretched - TONE_TARGET_P10)
                                    / (TONE_TARGET_P90 - TONE_TARGET_P10), 0, 1)
                    _norm = np.power(_norm, _gamma_t)
                    _stretched = _norm * (TONE_TARGET_P90 - TONE_TARGET_P10) + TONE_TARGET_P10
            img_8bit = np.where(_active_tone, _stretched, 0)
            img_8bit = np.clip(img_8bit, 0, 255).astype(np.uint8)
            log.info("Anatomy tone match: [%.0f,%.0f] -> [%.0f,%.0f] gamma=%.3f",
                     _cur_p10, _cur_p90, TONE_TARGET_P10, TONE_TARGET_P90, _gamma_t)

    # ── Second edge deband pass (after tone match) ────────────────────
    _meas_s2 = slice(width // 5, width * 4 // 5)
    _img_f_ed2 = img_8bit.astype(np.float32)
    for r in range(min(150, height) - 1, 0, -1):
        _cm_e = float(np.mean(_img_f_ed2[r, _meas_s2]))
        _nm_e = float(np.mean(_img_f_ed2[r + 1, _meas_s2]))
        if _cm_e > _nm_e and _nm_e > 0.1:
            _img_f_ed2[r, :] *= _nm_e / max(_cm_e, 0.1)
    for r in range(max(height - 150, 0), height):
        _cm_e = float(np.mean(_img_f_ed2[r, _meas_s2]))
        _pm_e = float(np.mean(_img_f_ed2[r - 1, _meas_s2]))
        if _cm_e > _pm_e and _pm_e > 0.1:
            _img_f_ed2[r, :] *= _pm_e / max(_cm_e, 0.1)
    _ed_rm2 = np.mean(_img_f_ed2[:, _meas_s2], axis=1).astype(np.float64)
    _ed_trend2 = gaussian_filter1d(_ed_rm2, sigma=15).astype(np.float32)
    for r in list(range(0, min(150, height))) + \
             list(range(max(height - 150, 0), height)):
        if _ed_rm2[r] > 0.1:
            _corr_e = np.clip(float(_ed_trend2[r]) / float(_ed_rm2[r]), 0.80, 1.25)
            _img_f_ed2[r, :] *= _corr_e
    img_8bit = np.clip(_img_f_ed2, 0, 255).astype(np.uint8)

    # ── Crop to standard output size ───────────────────────────────
    #   Sidexis outputs 2440×1280 from the raw 2706×1316.
    CROP_H, CROP_W = 1280, 2440
    if height > CROP_H:
        row_top = min(18, (height - CROP_H) // 2)
        row_bot = row_top + CROP_H
        img_8bit = img_8bit[row_top:row_bot, :]
    if width > CROP_W:
        # Center crop on the active exposure region
        center = (lin_left_edge + lin_right_edge) // 2
        col_left = max(0, center - CROP_W // 2)
        col_right = col_left + CROP_W
        if col_right > width:
            col_right = width
            col_left = max(0, col_right - CROP_W)
        img_8bit = img_8bit[:, col_left:col_right]
    crop_h, crop_w = img_8bit.shape
    log.info("Cropped: %dx%d -> %dx%d", width, height, crop_w, crop_h)

    # ── Sharpen ──────────────────────────────────────────────────────
    img_pil = Image.fromarray(img_8bit, mode="L")
    try:
        from PIL import ImageFilter
        img_pil = img_pil.filter(
            ImageFilter.UnsharpMask(radius=2, percent=80, threshold=3)
        )
    except Exception:
        pass

    log.info(
        "Panoramic stitched: %dx%d%s",
        crop_w, crop_h, " (inverted)" if invert else "",
    )

    return img_pil


def save_scanline_pngs(
    scanlines: list[Scanline], outdir: Path
) -> list[Path]:
    """Save each scanline as an individual PNG strip."""
    outdir.mkdir(parents=True, exist_ok=True)
    paths = []

    for idx, sl in enumerate(scanlines):
        # Create a 1-pixel-wide vertical strip image
        arr = sl.pixels_8bit.reshape(-1, 1)  # Nx1 column
        img = Image.fromarray(arr, mode="L")

        filename = f"HB_{idx + 1:04d}_sl{sl.scanline_id:02X}.png"
        path = outdir / filename
        img.save(path)
        paths.append(path)

    return paths


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Live TCP Client
# ╚══════════════════════════════════════════════════════════════════════════════

class SironaLiveClient:
    """Live TCP client for Sirona Orthophos direct connection.

    Implements the P2K session handshake, heartbeat loop, and scan
    data capture as observed in the ff.txt Wireshark dump.
    """

    def __init__(
        self,
        host: str = "192.168.139.170",
        port: int = 12837,
        hb_interval: float = 0.4,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.hb_interval = hb_interval
        self.timeout = timeout

        self._sock: socket.socket | None = None
        self._hb_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._hb_seq = 0
        self._connected = False
        self._device_status_code: int = -1  # last polled device status
        self._armed = False          # patient data sent, waiting for button
        self._exposing_active = False  # device actively exposing (got 0x1005)

        # Diagnostic ring buffer — last N HB/status entries for failure dumps
        self._diag_ring: list[str] = []
        self._diag_ring_max: int = 20
        self._last_recv_frame: bytes = b""  # last raw frame for disconnect diagnosis

        # Callbacks
        self.on_hb: list = []           # (seq, rtt_ms) → None
        self.on_status: list = []       # (status_str) → None
        self.on_device_status: list = []  # (status_code: int) → None
        self.on_kv_sample: list = []    # (KVSample) → None
        self.on_scanline: list = []     # (Scanline) → None
        self.on_event: list = []        # (str) → None
        self.on_error: list = []        # (Exception) → None

    # ── Connection lifecycle ─────────────────────────────────────────────

    def connect(self) -> None:
        """Open TCP connection and perform P2K session handshake.

        The handshake sends SESSION_OPEN_REQ (0x205C) and waits up to 1 s
        for SESSION_OPEN_ACK (0x205D).  Some firmware variants (notably on
        Windows-attached units) silently ignore the OPEN request but do
        respond to SESSION_INIT (0x2001) and HB_REQUEST (0x200B).  When
        no ACK arrives within 1 s the OPEN step is skipped and the method
        proceeds directly to INIT — this is not an error.
        """
        log.info("Connecting to %s:%d ...", self.host, self.port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        self._sock = sock
        log.info("TCP connected")

        # ── 1. SESSION_OPEN  (optional — may be ignored by some firmware) ─
        self._send_session_frame(FC_SESSION_OPEN_REQ, flags=0x000F)

        saved_timeout = sock.gettimeout()
        sock.settimeout(1.0)                  # 1 s window for ACK
        try:
            resp = self._recv_frame()
            fc = (resp[0] << 8) | resp[1] if len(resp) >= 2 else 0
            if fc == FC_SESSION_OPEN_ACK:
                log.info("Session opened (0x205D ACK)")
            else:
                # Got *something* but not the ACK — log and carry on.
                log.info(
                    "SESSION_OPEN response was 0x%04X (not ACK) "
                    "\u2014 proceeding to INIT",
                    fc,
                )
        except socket.timeout:
            log.info(
                "SESSION_OPEN ACK skipped (device silent) "
                "\u2014 proceeding to INIT"
            )
        finally:
            sock.settimeout(saved_timeout)    # restore original timeout

        # ── 2. SESSION_INIT  (always sent) ────────────────────────────────
        self._send_session_frame(FC_SESSION_INIT)
        resp = self._recv_frame()
        fc = (resp[0] << 8) | resp[1] if len(resp) >= 2 else 0
        log.info("Session init response: 0x%04X (%d bytes)", fc, len(resp))

        self._connected = True
        self._session_start = time.perf_counter()
        self._hb_responses_received = 0
        self._fire(self.on_status, "CONNECTED")

    def disconnect(self) -> None:
        """Stop HB thread and close the TCP socket."""
        self._stop.set()
        if self._hb_thread:
            self._hb_thread.join(timeout=3.0)
            self._hb_thread = None
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._connected = False
        self._armed = False
        self._exposing_active = False
        log.info("Disconnected")

    # ── Heartbeat loop ───────────────────────────────────────────────────

    def start_hb_loop(self) -> None:
        """Start the background heartbeat thread."""
        self._stop.clear()
        self._hb_thread = threading.Thread(
            target=self._hb_loop, name="sirona-hb", daemon=True
        )
        self._hb_thread.start()
        log.info("HB loop started (interval=%.1fs)", self.hb_interval)

    # Maximum session age before proactive refresh (device hard limit ~2 s)
    SESSION_REFRESH_S = 1.5

    def _hb_loop(self) -> None:
        """Send HB_REQUEST, wait for HB_RESPONSE, repeat.

        Operates in three modes:
          NORMAL:   Session refresh every 1.5s, send HB, recv response.
          ARMED:    No session refresh (session must survive until scan).
                    Send HB, recv — watch for EXPOSE_NOTIFY (0x1005).
          EXPOSING: Device is flooding data.  Recv in tight loop (no HB
                    needed).  Detect end-of-data → send IMAGE_ACK.
        """
        while not self._stop.is_set():
            try:
                # ── EXPOSING mode: tight recv loop ────────────────────
                if self._exposing_active:
                    self._recv_scan_data()
                    continue

                # ── Session refresh (only in NORMAL mode) ─────────────
                if not self._armed:
                    session_age = time.perf_counter() - self._session_start
                    if session_age >= self.SESSION_REFRESH_S:
                        self._session_refresh()
                        continue

                # ── Send HB (NORMAL and ARMED modes) ──────────────────
                self._hb_seq += 1
                t0 = time.perf_counter()

                with self._lock:
                    self._send_session_frame(FC_HB_REQUEST)
                    resp = self._recv_frame()

                rtt_ms = (time.perf_counter() - t0) * 1000
                fc = (resp[0] << 8) | resp[1] if len(resp) >= 2 else 0

                if fc == FC_HB_RESPONSE:
                    self._hb_responses_received += 1
                    self._diag_push(
                        f"HB seq={self._hb_seq} rtt={rtt_ms:.0f}ms "
                        f"armed={self._armed}"
                    )
                    self._fire(self.on_hb, self._hb_seq, rtt_ms)

                elif fc == FC_EXPOSE_NOTIFY:
                    # Physical button pressed — device starting exposure.
                    # The 0x1005 frame often carries a large payload that
                    # includes the first scan data (embedded 0x1002 header
                    # + kV ramp / patient echo).  Stash it so _recv_scan_data
                    # can prepend it to the scan buffer.
                    self._exposing_active = True
                    payload = resp[SESSION_HEADER_SIZE:] if len(resp) > SESSION_HEADER_SIZE else b""
                    self._expose_initial_data = payload
                    self._diag_push(
                        f"EXPOSE_NOTIFY (0x1005) {len(payload)}B payload"
                    )
                    log.info(
                        "EXPOSE_NOTIFY received — exposure starting! "
                        "%d bytes initial data", len(payload),
                    )
                    self._fire(self.on_event, "EXPOSE_STARTED")
                    self._fire(self.on_status, "EXPOSING")
                    continue  # switch to recv loop immediately

                elif fc == FC_SESSION_OPEN_ACK:
                    # Unsolicited device session refresh — just log it
                    self._diag_push("Device SESSION_REFRESH (0x205D)")

                elif fc == FC_SESSION_CONFIRM:
                    # Unsolicited confirm — device cycling session
                    self._diag_push("Device SESSION_CONFIRM (0x2002)")

                else:
                    # Might be scan data or status — process it
                    self._diag_push(
                        f"DATA fc=0x{fc:04X} len={len(resp)}"
                    )
                    self._process_live_data(resp)

            except socket.timeout:
                self._diag_push("HB_TIMEOUT (no response)")
                self._fire(self.on_status, "HB_TIMEOUT")
            except OSError as exc:
                # Log the LAST frame received before the connection dropped
                last = self._last_recv_frame
                if last:
                    last_fc = (last[0] << 8 | last[1]) if len(last) >= 2 else 0
                    last_payload = last[SESSION_HEADER_SIZE:] if len(last) > SESSION_HEADER_SIZE else b""
                    log.warning(
                        "LAST FRAME before drop: fc=0x%04X len=%d first20=%s",
                        last_fc, len(last),
                        last_payload[:20].hex() if last_payload else "(empty)",
                    )

                session_age = time.perf_counter() - self._session_start
                early_reject = (
                    session_age < 2.0
                    and self._hb_responses_received == 0
                )

                if early_reject:
                    msg = (
                        "Device rejected session \u2014 another client "
                        "may be connected (close Sidexis)"
                    )
                    self._diag_push(f"SESSION_REJECTED: {exc} "
                                    f"(age={session_age:.1f}s, 0 HB)")
                    log.warning("%s  (%s)", msg, exc)
                    self._fire(self.on_event, msg)
                    self._fire(self.on_status, "SESSION_REJECTED")
                    self._attempt_reconnect(backoff_s=10.0)
                else:
                    self._diag_push(f"HB_ERROR: {exc}")
                    log.error("HB loop error: %s", exc)
                    self._fire(self.on_error, exc)
                    self._fire(self.on_status, "RECONNECTING")
                    self._attempt_reconnect(backoff_s=2.0)
                break

            self._stop.wait(self.hb_interval)

    def _recv_scan_data(self) -> None:
        """Receive scan data in a tight loop during active exposure.

        The device sends data as a continuous TCP byte stream:
          1. EXPOSE_NOTIFY (0x1005) with embedded 0x1002 header + data
          2. Raw data chunks (no per-chunk session headers)
          3. Stream ends when no data arrives for 2s

        We accumulate all bytes into a single buffer, then parse kV
        samples and scanlines from the complete buffer.
        """
        if self._sock is None:
            return

        saved_timeout = self._sock.gettimeout()
        self._sock.settimeout(2.0)

        scan_buffer = bytearray()
        chunk_count = 0

        # Seed buffer with data from the EXPOSE_NOTIFY payload
        initial = getattr(self, '_expose_initial_data', b'')
        if initial:
            scan_buffer.extend(initial)
            self._expose_initial_data = b''
            log.info("Seeded scan buffer with %d bytes from EXPOSE_NOTIFY", len(initial))

        try:
            while not self._stop.is_set() and self._exposing_active:
                try:
                    with self._lock:
                        data = self._sock.recv(65536)

                    if not data:
                        raise ConnectionError("Connection closed during scan")

                    chunk_count += 1
                    self._last_recv_frame = data

                    # The first chunk after EXPOSE_NOTIFY may contain an
                    # embedded 0x1002 session header.  Find and skip it so
                    # the buffer contains only raw scan data.
                    if chunk_count <= 2:
                        # Look for 0x1002 header signature in first chunks.
                        # This frame contains calibration data (SGFHeader,
                        # DieWidthPixel, DarkCurrentRows, etc.) — save it
                        # before stripping.
                        sig_1002 = b'\x10\x02\x07\x2d\x07\xd0'
                        pos = data.find(sig_1002)
                        if pos >= 0:
                            # Save the full 0x1002 frame for calibration
                            calib_data = data[pos:]
                            try:
                                calib_path = LOG_DIR / "last_scan_calibration.bin"
                                with open(calib_path, "wb") as cf:
                                    cf.write(calib_data)
                                log.info(
                                    "Saved 0x1002 calibration frame: %s (%d bytes)",
                                    calib_path, len(calib_data),
                                )
                            except Exception as exc:
                                log.warning("Failed to save calibration: %s", exc)

                            # Strip the 20-byte session header for pixel stream
                            data = data[pos + SESSION_HEADER_SIZE:]
                            log.info(
                                "Scan chunk %d: stripped 0x1002 header at "
                                "offset %d, %d bytes remain",
                                chunk_count, pos, len(data),
                            )

                    scan_buffer.extend(data)

                    if chunk_count % 50 == 0:
                        log.info(
                            "Scan progress: %d chunks, %.1f KB buffered",
                            chunk_count, len(scan_buffer) / 1024,
                        )

                except socket.timeout:
                    log.info(
                        "Scan data stream ended (timeout) — "
                        "%d chunks, %.1f KB total",
                        chunk_count, len(scan_buffer) / 1024,
                    )
                    break

        finally:
            self._sock.settimeout(saved_timeout)

        # ── Save raw buffer for offline analysis ──────────────────────
        log.info(
            "Parsing scan buffer: %d bytes from %d chunks",
            len(scan_buffer), chunk_count,
        )
        try:
            raw_path = LOG_DIR / "last_scan_raw.bin"
            with open(raw_path, "wb") as f:
                f.write(scan_buffer)
            log.info("Raw scan buffer saved: %s (%d bytes)", raw_path, len(scan_buffer))
        except Exception as exc:
            log.warning("Failed to save raw buffer: %s", exc)

        raw = bytes(scan_buffer)

        # Extract kV ramp samples
        kv_samples = _extract_kv_samples(raw)
        kv_peak = 0
        if kv_samples:
            kv_peak = max(s.kv_raw for s in kv_samples)
            log.info(
                "kV ramp: %d samples, peak raw=0x%04X (%.1f kV)",
                len(kv_samples), kv_peak, kv_peak / 10.0,
            )
            peak_sample = max(kv_samples, key=lambda s: s.kv_raw)
            self._fire(self.on_kv_sample, peak_sample)
        # Store peak kV for direct retrieval by the GUI (avoids
        # race with after(0,...) callback ordering).
        self._scan_kv_peak = kv_peak / 10.0

        # Extract full panoramic image from continuous pixel stream
        # Try advanced panoramic extraction (with telemetry repair etc.)
        try:
            _pano_result = _extract_panoramic(raw)
            if isinstance(_pano_result, tuple):
                scanlines, self._repair_mask = _pano_result
            else:
                scanlines, self._repair_mask = _pano_result, None
        except Exception as exc:
            log.error("Advanced panoramic extraction failed: %s", exc)
            scanlines = []
            self._repair_mask = None

        # Fallback 1: simple panoramic extraction (no telemetry repair)
        if not scanlines:
            try:
                scanlines = _extract_panoramic_simple(raw)
                self._repair_mask = None
                if scanlines:
                    log.info("Simple panoramic: %d columns", len(scanlines))
            except Exception as exc:
                log.error("Simple panoramic extraction failed: %s", exc)
                scanlines = []

        # Fallback 2: marker-based extraction (minimal, always works)
        if not scanlines:
            scanlines = _extract_scanlines(raw)
            if scanlines:
                log.info(
                    "Marker scanlines: %d (IDs 0x%02X-0x%02X)",
                    len(scanlines),
                    scanlines[0].scanline_id,
                    scanlines[-1].scanline_id,
                )

        if scanlines:
            log.info(
                "Image: %d columns x %d px = %dx%d panoramic",
                len(scanlines), scanlines[0].pixel_count,
                len(scanlines), scanlines[0].pixel_count,
            )
            # Store scanlines for batch retrieval by the GUI.
            self._scan_scanlines = scanlines
            # Fire first and last to notify GUI without flooding Tk.
            self._fire(self.on_scanline, scanlines[0])
            if len(scanlines) > 1:
                self._fire(self.on_scanline, scanlines[-1])

        # Extract ASCII events (only fire unique event types)
        seen_types = set()
        for ev in _extract_events(raw):
            if ev.event_type not in seen_types:
                seen_types.add(ev.event_type)
                self._fire(self.on_event, f"{ev.event_type}: {ev.detail}")

        # ── Scan complete — send IMAGE_ACK ────────────────────────────
        self._exposing_active = False
        self._armed = False
        log.info("Scan data reception complete — sending IMAGE_ACK")
        self._diag_push(
            f"SCAN_COMPLETE — {len(scanlines)} scanlines, "
            f"{len(kv_samples)} kV samples"
        )

        try:
            self.send_image_ack()
        except Exception as exc:
            log.warning("IMAGE_ACK failed: %s (non-fatal)", exc)

        self._fire(self.on_event, "SCAN_COMPLETE")
        self._fire(self.on_status, "SCAN_COMPLETE")

    def _session_refresh(self) -> None:
        """Silently close and reopen the TCP session.

        The device enforces a hard ~2 s session limit.  This method
        cycles the connection without triggering error callbacks or
        backoff — the GUI stays CONNECTED throughout.

        MUST NOT be called when armed — the session must stay alive
        for the physical button press and subsequent data flood.
        """
        if self._armed or self._exposing_active:
            return  # never refresh during armed/exposing state
        log.debug("Session refresh (device 2s limit)")
        self._diag_push("SESSION_REFRESH")

        # Close the old socket
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        # Reconnect: new TCP + SESSION_OPEN + SESSION_INIT
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        self._sock = sock

        # SESSION_OPEN (optional ACK)
        self._send_session_frame(FC_SESSION_OPEN_REQ, flags=0x000F)
        saved_timeout = sock.gettimeout()
        sock.settimeout(1.0)
        try:
            self._recv_frame()
        except socket.timeout:
            pass
        finally:
            sock.settimeout(saved_timeout)

        # SESSION_INIT
        self._send_session_frame(FC_SESSION_INIT)
        self._recv_frame()

        self._session_start = time.perf_counter()

    def _attempt_reconnect(self, backoff_s: float = 2.0) -> None:
        """Reconnect after connection loss.

        Args:
            backoff_s: Seconds to wait between retry attempts.  Use 10.0
                       for session-rejected (another client) scenarios,
                       2.0 (default) for normal post-scan E7 recovery.
        """
        log.info("Attempting reconnect (backoff=%.0fs)...", backoff_s)
        self._fire(self.on_event,
                   f"Reconnecting (backoff={backoff_s:.0f}s)")

        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        for attempt in range(1, 6):
            if self._stop.is_set():
                return
            time.sleep(backoff_s)
            try:
                self.connect()
                self.start_hb_loop()
                self._fire(self.on_event, f"Reconnected after {attempt} attempt(s)")
                return
            except Exception as exc:
                log.warning("Reconnect attempt %d failed: %s", attempt, exc)

        self._fire(self.on_error, ConnectionError("Reconnect failed after 5 attempts"))

    # ── Device status query ─────────────────────────────────────────────

    def query_status(self) -> int:
        """Return the last known device status code.

        NOTE: Active status polling via FC 0x1005 is not supported —
        that function code is EXPOSE_NOTIFY (device → host only).
        Status is inferred from HB responses and device events.
        Returns -1 if unknown.
        """
        return self._device_status_code

    @property
    def device_status_code(self) -> int:
        """Last known device status code, or -1 if unknown."""
        return self._device_status_code

    # ── Diagnostic ring buffer ────────────────────────────────────────

    def _diag_push(self, entry: str) -> None:
        """Append a timestamped diagnostic entry to the ring buffer."""
        ts = time.strftime("%H:%M:%S")
        self._diag_ring.append(f"[{ts}] {entry}")
        if len(self._diag_ring) > self._diag_ring_max:
            self._diag_ring = self._diag_ring[-self._diag_ring_max:]

    def dump_diagnostics(self, last_n: int = 10) -> list[str]:
        """Return the most recent *last_n* HB/status diagnostic entries."""
        return list(self._diag_ring[-last_n:])

    # ── Expose: arm + wait-for-button protocol ───────────────────────

    # Continuation data sent immediately after DATA_SEND (102 bytes).
    # This is the program/parameter table from ff.txt Sidexis capture.
    _DATA_CONTINUATION = bytes([
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x2c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x2c, 0x00, 0x03, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c,
        0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x08, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff,
        0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05,
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0xff, 0xff, 0x00, 0x05, 0xff, 0xff,
    ])

    @staticmethod
    def _encode_utf16le_field(text: str) -> bytes:
        """Encode a string as [LE-uint16 length][UTF-16LE data]."""
        encoded = text.encode("utf-16-le")
        length = len(text)  # char count, not byte count
        return struct.pack("<H", length) + encoded

    # Exact 156-byte payload from ff.txt frame 750 DATA_SEND.
    # Packet bytes 0x14-0xAF (everything after the 20-byte session header).
    # Patient "test test", Doctor "Dr. Demo", Station "DESKTOP-NK6UFML".
    # Confirmed working against live device 2026-03-23.
    _DATA_SEND_TEMPLATE = bytes([
        0xfc,0x30,0x00,0x00,0x1f,0x00,0x05,0x00,0xe6,0x07,0x11,0x00,
        0x0f,0x00,0x29,0x00,0xfa,0x00,0xdb,0x04,0x9b,0x08,0x00,0x04,
        0x00,0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x04,0x00,0x74,
        0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x01,0x00,0x01,0x07,0xd1,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x08,0x00,0x44,0x00,0x72,0x00,0x2e,0x00,0x20,0x00,0x44,
        0x00,0x65,0x00,0x6d,0x00,0x6f,0x00,0x00,0x00,0x14,0x00,0x30,
        0x00,0x30,0x00,0x33,0x00,0x31,0x00,0x30,0x00,0x35,0x00,0x32,
        0x00,0x30,0x00,0x32,0x00,0x32,0x00,0x31,0x00,0x37,0x00,0x31,
        0x00,0x35,0x00,0x34,0x00,0x31,0x00,0x30,0x00,0x32,0x00,0x35,
        0x00,0x30,0x00,0x0f,0x00,0x44,0x00,0x45,0x00,0x53,0x00,0x4b,
        0x00,0x54,0x00,0x4f,0x00,0x50,0x00,0x2d,0x00,0x4e,0x00,0x4b,
        0x00,0x36,0x00,0x55,0x00,0x46,0x00,0x4d,0x00,0x4c,0x00,0x05,
    ])

    def _build_patient_payload(
        self,
        last_name: str = "test",
        first_name: str = "test",
        doctor: str = "Dr. Demo",
        study_id: str = "",
        workstation: str = "PUREXS",
    ) -> bytes:
        """Return the DATA_SEND payload for arming the device.

        Uses the exact 156-byte payload captured from ff.txt which is
        known to be accepted by the Orthophos XG.  Patient name fields
        in the payload are "test test" — the device does not validate
        these for exposure (they are for DICOM metadata only).
        """
        return self._DATA_SEND_TEMPLATE

    def arm_for_expose(
        self,
        last_name: str = "test",
        first_name: str = "test",
        doctor: str = "Dr. Demo",
        study_id: str = "",
        workstation: str = "PUREXS",
    ) -> None:
        """Arm the device for exposure: CAPS exchange + patient DATA_SEND.

        After this call the device is armed and waiting for the physical
        expose button to be pressed.  The HB loop continues but session
        refresh is disabled (the session must stay alive until the scan
        completes).

        The device will send FC_EXPOSE_NOTIFY (0x1005) when the operator
        presses the button, followed by kV ramp data and scanline images.

        Raises:
            ConnectionError: Socket not connected.
            RuntimeError: Unexpected device response.
        """
        if self._sock is None:
            raise ConnectionError("Not connected — cannot arm")

        # Force a fresh session so that CAPS_REQ is the FIRST command
        # after SESSION_INIT (no prior HB).  This matches the Sidexis
        # sequence and prevents the device from embedding extra kV
        # telemetry in the scan data echo payloads.
        if not self._armed:
            try:
                self._session_refresh()
                log.info("Fresh session for arm (no prior HB)")
            except Exception as exc:
                log.warning("Pre-arm session refresh failed: %s", exc)

        with self._lock:
            # 1. Capabilities exchange
            self._send_session_frame(FC_CAPS_REQ)
            caps_resp = self._recv_frame()
            caps_fc = (caps_resp[0] << 8) | caps_resp[1] if len(caps_resp) >= 2 else 0
            if caps_fc != FC_CAPS_RESP:
                log.warning(
                    "Expected CAPS_RESP (0x2111), got 0x%04X — continuing",
                    caps_fc,
                )
            else:
                log.info(
                    "CAPS_RESP received (%d bytes payload)",
                    len(caps_resp) - SESSION_HEADER_SIZE,
                )

            # 2. DATA_SEND (patient + exam info)
            payload = self._build_patient_payload(
                last_name, first_name, doctor, study_id, workstation,
            )
            # Header payload_length must cover BOTH the payload AND the
            # continuation data that follows in a separate TCP segment.
            total_len = len(payload) + len(self._DATA_CONTINUATION)
            self._send_data_frame(
                FC_DATA_SEND, payload, total_payload_length=total_len,
            )
            log.info(
                "DATA_SEND: %d bytes payload (total_len=%d incl continuation)",
                len(payload), total_len,
            )

            # 3. Continuation data (program parameters)
            self._sock.sendall(self._DATA_CONTINUATION)
            log.info("DATA continuation: %d bytes", len(self._DATA_CONTINUATION))

            # 4. Wait for DATA_ACK (0x1001)
            ack_resp = self._recv_frame()
            ack_fc = (ack_resp[0] << 8) | ack_resp[1] if len(ack_resp) >= 2 else 0
            if ack_fc != FC_DATA_ACK:
                log.warning(
                    "Expected DATA_ACK (0x1001), got 0x%04X", ack_fc,
                )
            else:
                log.info("DATA_ACK received — device armed")

        self._armed = True
        self._exposing_active = False
        self._diag_push("ARMED — waiting for physical expose button")
        self._fire(self.on_event, "ARMED")
        self._fire(self.on_status, "ARMED")
        log.info("Device armed — press the physical expose button on the unit")

    def send_expose(self) -> None:
        """DEPRECATED: Use arm_for_expose() instead.

        The old approach of sending raw kV ramp bytes as a 'trigger' was
        incorrect — those bytes are device telemetry, not a command.
        The Orthophos expose is triggered by the physical button on the
        unit.  arm_for_expose() sets up the device to accept exposure.
        """
        log.warning(
            "send_expose() is DEPRECATED — the Orthophos expose is "
            "triggered by the physical button. Calling arm_for_expose() "
            "with defaults instead."
        )
        self.arm_for_expose()

    def send_image_ack(self) -> None:
        """Send IMAGE_ACK (0x1008) after receiving all scan data.

        This tells the device we received the image data.  The device
        responds with IMAGE_ACK_RESP (0x1009) and the session can then
        be closed cleanly.
        """
        if self._sock is None:
            raise ConnectionError("Not connected")
        with self._lock:
            self._send_session_frame(FC_IMAGE_ACK)
            log.info("IMAGE_ACK (0x1008) sent")
            try:
                resp = self._recv_frame()
                fc = (resp[0] << 8) | resp[1] if len(resp) >= 2 else 0
                if fc == FC_IMAGE_ACK_RESP:
                    log.info("IMAGE_ACK_RESP (0x1009) received — scan complete")
                else:
                    log.info("Post-IMAGE_ACK response: 0x%04X", fc)
            except socket.timeout:
                log.info("No response to IMAGE_ACK (timeout) — OK")

    def send_raw(self, data: bytes) -> None:
        """Send arbitrary bytes on the session socket (for protocol research)."""
        if self._sock is None:
            raise ConnectionError("Not connected")
        with self._lock:
            self._sock.sendall(data)

    # ── Wire I/O ─────────────────────────────────────────────────────────

    def _build_session_header(
        self, func_code: int, flags: int = 0x000E,
        payload_length: int = 0,
    ) -> bytearray:
        """Build a 20-byte P2K session header (no send).

        Header layout (confirmed from ff.txt):
          +0x00  WORD   func_code      command family + sub-command
          +0x02  WORD   magic          0x072D
          +0x04  WORD   port           0x07D0
          +0x06  WORD   version        0x0001
          +0x08  WORD   flags          0x000E or 0x000F
          +0x0A  8B     reserved       zeros
          +0x12  WORD   payload_len    total bytes following this header (BE)
        """
        header = bytearray(SESSION_HEADER_SIZE)
        header[0] = (func_code >> 8) & 0xFF    # func_hi
        header[1] = func_code & 0xFF            # func_lo
        struct.pack_into(">H", header, 2, MAGIC)
        struct.pack_into(">H", header, 4, PORT_MARKER)
        struct.pack_into(">H", header, 6, 0x0001)  # version (always 1)
        struct.pack_into(">H", header, 8, flags)
        # bytes 10-17 are zeros (reserved)
        struct.pack_into(">H", header, 18, payload_length)
        return header

    def _send_session_frame(self, func_code: int, flags: int = 0x000E) -> None:
        """Build and send a 20-byte P2K session frame."""
        header = self._build_session_header(func_code, flags)
        if self._sock is None:
            raise ConnectionError("Not connected")
        self._sock.sendall(header)

    def _send_data_frame(
        self, func_code: int, payload: bytes, flags: int = 0x000E,
        total_payload_length: int | None = None,
    ) -> None:
        """Build session header + payload and send as one frame.

        Args:
            total_payload_length: If set, overrides the auto-computed
                payload_length in the header.  Use this when additional
                data (e.g. continuation bytes) will follow in a separate
                TCP segment — the header length field must cover ALL data.
        """
        plen = total_payload_length if total_payload_length is not None else len(payload)
        header = self._build_session_header(func_code, flags, payload_length=plen)
        if self._sock is None:
            raise ConnectionError("Not connected")
        self._sock.sendall(header + payload)

    def _recv_frame(self) -> bytes:
        """Receive data from the device. Returns at least the header."""
        if self._sock is None:
            raise ConnectionError("Not connected")
        # Read whatever is available (device sends variable-length frames)
        data = self._sock.recv(4096)
        if not data:
            raise ConnectionError("Connection closed by device")
        # Raw frame logging: func_code (hex) + payload len + first 20 bytes
        fc = (data[0] << 8 | data[1]) if len(data) >= 2 else 0
        payload = data[SESSION_HEADER_SIZE:] if len(data) > SESSION_HEADER_SIZE else b""
        preview = payload[:20].hex() if payload else "(empty)"
        log.info(
            "RECV fc=0x%04X payload_len=%d first20=%s",
            fc, len(payload), preview,
        )
        self._last_recv_frame = data
        return data

    def _process_live_data(self, data: bytes) -> None:
        """Process non-HB data received during the live loop."""
        # Check for kV ramp data
        if _contains_kv_records(data):
            for sample in _extract_kv_samples(data):
                self._fire(self.on_kv_sample, sample)
                if sample.is_expose_trigger:
                    self._fire(self.on_event, "EXPOSE TRIGGER DETECTED")

        # Check for scanlines
        for sl in _extract_scanlines(data):
            self._fire(self.on_scanline, sl)

        # Check for ASCII events
        for ev in _extract_events(data):
            self._fire(self.on_event, f"{ev.event_type}: {ev.detail}")

    def _fire(self, callbacks: list, *args) -> None:
        for cb in callbacks:
            try:
                cb(*args)
            except Exception as exc:
                log.debug("Callback error: %s", exc)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Output / Reporting
# ╚══════════════════════════════════════════════════════════════════════════════

def print_summary(capture: DecodedCapture) -> None:
    """Print a human-readable summary of a decoded capture."""
    print("=" * 70)
    print("PureXS HB Decoder — Capture Summary")
    print("=" * 70)

    print(f"\n  Session frames:     {len(capture.frames)}")
    print(f"  Heartbeat pairs:    {len(capture.hb_pairs)}")
    print(f"  kV ramp samples:    {len(capture.kv_samples)}")
    print(f"  Image scanlines:    {len(capture.scanlines)}")
    print(f"  Log events:         {len(capture.events)}")

    if capture.hb_pairs:
        print("\n  HB Pairs:")
        for i, (req, resp) in enumerate(capture.hb_pairs):
            rtt = (resp.timestamp - req.timestamp) * 1000
            print(f"    [{i+1}] t={req.timestamp:.3f}  RTT={rtt:.1f}ms")

    if capture.kv_samples:
        print(f"\n  kV Ramp: {len(capture.kv_samples)} samples")
        trigger = [s for s in capture.kv_samples if s.is_expose_trigger]
        print(f"  Expose triggers:    {len(trigger)}")
        if trigger:
            t = trigger[0]
            print(
                f"  First trigger:      pos={t.position} "
                f"kV=0x{t.kv_raw:04X} ramp=0x{t.field3:04X}"
            )

    if capture.scanlines:
        ids = [sl.scanline_id for sl in capture.scanlines]
        print(f"\n  Scanlines: {len(capture.scanlines)}")
        print(f"  ID range:           0x{min(ids):02X} — 0x{max(ids):02X}")
        pixels = capture.scanlines[0].pixel_count
        print(f"  Pixels per line:    {pixels}")

    if capture.events:
        print("\n  Events:")
        rec_starts = [e for e in capture.events if e.event_type == "recording_start"]
        rec_stops = [e for e in capture.events if e.event_type == "recording_stop"]
        releases = [e for e in capture.events if e.event_type == "state_released"]
        e7_errors = [e for e in capture.events if e.event_type == "e7_error"]

        print(f"    Recording start:  {len(rec_starts)}")
        print(f"    Recording stop:   {len(rec_stops)}")
        print(f"    Released:         {len(releases)}")
        print(f"    E7 14 02 errors:  {len(e7_errors)}")

        for ev in rec_starts[:5]:
            print(f"      {ev.timestamp_str}  {ev.detail}")

    print("\n" + "=" * 70)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  CLI
# ╚══════════════════════════════════════════════════════════════════════════════

def cmd_parse(args: argparse.Namespace) -> int:
    """Parse a Wireshark dump and extract all protocol elements."""
    capture = parse_wireshark_dump(args.dump_file)
    print_summary(capture)

    outdir = Path(args.outdir)

    # Save kV ramp as CSV
    if capture.kv_samples:
        csv_path = outdir / "kv_ramp.csv"
        outdir.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "w") as f:
            f.write("position,kv_raw,field2,field3,is_trigger\n")
            for s in capture.kv_samples:
                f.write(
                    f"{s.position},{s.kv_raw},{s.field2},"
                    f"{s.field3},{int(s.is_expose_trigger)}\n"
                )
        log.info("kV ramp saved: %s (%d samples)", csv_path, len(capture.kv_samples))

    # Save scanline PNGs
    if capture.scanlines:
        sl_dir = outdir / "scanlines"
        paths = save_scanline_pngs(capture.scanlines, sl_dir)
        log.info("Scanline PNGs saved: %s (%d files)", sl_dir, len(paths))

        # Reconstruct composite image
        img = reconstruct_image(capture.scanlines, repair_mask=capture.repair_mask)
        if img:
            composite_path = outdir / "panoramic_reconstructed.png"
            img.save(composite_path)
            log.info("Composite image: %s (%dx%d)", composite_path, img.width, img.height)

    # Save event log
    if capture.events:
        log_path = outdir / "events.log"
        outdir.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w") as f:
            for ev in capture.events:
                f.write(f"{ev.timestamp_str}  {ev.event_type}  {ev.detail}\n")
        log.info("Event log: %s (%d events)", log_path, len(capture.events))

    # Save session frame summary
    if capture.frames:
        frames_path = outdir / "frames.log"
        outdir.mkdir(parents=True, exist_ok=True)
        with open(frames_path, "w") as f:
            f.write(f"{'#':>5}  {'Time':>12}  {'Dir':>3}  {'FuncCode':>10}  "
                    f"{'Name':<20}  {'PayloadLen':>10}\n")
            f.write("-" * 70 + "\n")
            for fr in capture.frames:
                f.write(
                    f"{fr.frame_no:>5}  {fr.timestamp:>12.3f}  {fr.direction:>3}  "
                    f"0x{fr.func_code:04X}      {fr.func_name:<20}  "
                    f"{fr.payload_len:>10}\n"
                )
        log.info("Frame log: %s (%d frames)", frames_path, len(capture.frames))

    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    """Print a quick summary without writing output files."""
    capture = parse_wireshark_dump(args.dump_file)
    print_summary(capture)
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    """Connect to device and run live HB monitor."""
    client = SironaLiveClient(
        host=args.host,
        port=args.port,
        hb_interval=args.interval,
    )

    # Wire up console output
    client.on_hb.append(
        lambda seq, rtt: print(f"  HB seq={seq:>4}  RTT={rtt:.1f}ms")
    )
    client.on_status.append(lambda s: print(f"  STATUS: {s}"))
    client.on_event.append(lambda e: print(f"  EVENT: {e}"))
    client.on_kv_sample.append(
        lambda s: print(
            f"  kV pos={s.position} raw=0x{s.kv_raw:04X} "
            f"ramp=0x{s.field3:04X}"
            f"{'  ** TRIGGER **' if s.is_expose_trigger else ''}"
        )
    )
    client.on_error.append(lambda e: print(f"  ERROR: {e}"))

    try:
        client.connect()
        client.start_hb_loop()
        print(f"\nLive monitoring {args.host}:{args.port}")
        print("Press Ctrl+C to stop.\n")

        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping...")
    except Exception as exc:
        log.error("Live monitor failed: %s", exc)
        print(f"ERROR: {exc}")
        return 1
    finally:
        client.disconnect()

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hb_decoder",
        description="PureXS HB Decoder — Sirona Orthophos protocol decoder",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # parse
    p_parse = sub.add_parser(
        "parse", help="Parse a Wireshark text dump",
    )
    p_parse.add_argument("dump_file", help="Path to Wireshark text export")
    p_parse.add_argument(
        "--outdir", "-o", default="./decoded",
        help="Output directory (default: ./decoded)",
    )
    p_parse.set_defaults(func=cmd_parse)

    # summary
    p_sum = sub.add_parser(
        "summary", help="Quick summary of a dump (no file output)",
    )
    p_sum.add_argument("dump_file", help="Path to Wireshark text export")
    p_sum.set_defaults(func=cmd_summary)

    # live
    p_live = sub.add_parser(
        "live", help="Live TCP monitor (connects to device)",
    )
    p_live.add_argument(
        "--host", default="192.168.139.170", help="Device IP",
    )
    p_live.add_argument(
        "--port", "-p", type=int, default=12837, help="TCP port",
    )
    p_live.add_argument(
        "--interval", "-i", type=float, default=0.1,
        help="HB poll interval in seconds (default: 0.1)",
    )
    p_live.set_defaults(func=cmd_live)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
