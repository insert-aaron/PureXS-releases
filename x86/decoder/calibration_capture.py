#!/usr/bin/env python3
"""
PureXS Calibration Data Capture

Connects to the Orthophos XG on the SERVICE port (12836) and requests
calibration data:

  1. Connects and performs session handshake
  2. Requests panoramic adjustment data (TCP_ReqGetPanAdjustDataAll)
  3. Requests the SGF gain file (TCP_ReqFile)
  4. Saves everything to disk for use by hb_decoder.py

Run this when the XG is powered on and accessible on the network.

Usage:
    python calibration_capture.py --host 192.168.139.170
    python calibration_capture.py --host 192.168.139.170 --port 12836

Protocol reference: Netapi_1_15.xml from Sidexis installation.
"""

import argparse
import json
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path

log = logging.getLogger("calibration")

# ── Protocol constants ───────────────────────────────────────────────────

MAGIC = 0x072D
PORT_MARKER = 0x07D0
SESSION_HDR_SIZE = 20

# Function codes (from Netapi_1_15.xml)
FC_SESSION_OPEN_REQ   = 0x205C
FC_SESSION_OPEN_ACK   = 0x205D
FC_SESSION_INIT       = 0x2001
FC_HB_REQUEST         = 0x200B

# Service port commands
FC_REQ_INFO           = 0x2013  # TCP_ReqInfo
FC_INFO               = 0x2014  # TCP_Info
FC_REQ_DEV_CAPS       = 0x2003  # TCP_ReqDevCaps
FC_DEV_CAPS           = 0x2004  # TCP_DevCaps
FC_REQ_GET_PAN_ADJUST = 0x20B6  # TCP_ReqGetPanAdjustDataAll (request)
FC_GET_PAN_ADJUST     = 0x20B7  # TCP_GetPanAdjustDataAll (response)
FC_REQ_FILE           = 0x204A  # TCP_ReqFile
FC_FILE               = 0x204B  # TCP_File
FC_REQ_EXT_INFO_DX41  = 0x2019  # TCP_ReqExtInfoDX41 (request)
FC_EXT_INFO_DX41      = 0x201A  # TCP_ExtInfoDX41 (response)
FC_REQ_SERVICE_TABLE  = 0x210A  # TCP_ReqServiceFunctionTable
FC_SERVICE_TABLE      = 0x210B  # TCP_ServiceFunctionTable

# Service port
SERVICE_PORT = 12836
MAIN_PORT = 12837


def build_header(func_code: int, flags: int = 0x000E,
                 payload_length: int = 0) -> bytearray:
    """Build a 20-byte P2K session header."""
    hdr = bytearray(SESSION_HDR_SIZE)
    hdr[0] = (func_code >> 8) & 0xFF
    hdr[1] = func_code & 0xFF
    struct.pack_into(">H", hdr, 2, MAGIC)
    struct.pack_into(">H", hdr, 4, PORT_MARKER)
    struct.pack_into(">H", hdr, 6, 0x0001)
    struct.pack_into(">H", hdr, 8, flags)
    struct.pack_into(">H", hdr, 18, payload_length)
    return hdr


def send_frame(sock: socket.socket, func_code: int,
               payload: bytes = b"", flags: int = 0x000E) -> None:
    """Send a P2K frame (header + optional payload)."""
    hdr = build_header(func_code, flags, len(payload))
    sock.sendall(hdr + payload)
    log.debug("SEND fc=0x%04x payload=%d bytes", func_code, len(payload))


def recv_all(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Receive all available data (may be multi-segment)."""
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            # Short timeout for continuation data
            sock.settimeout(0.5)
    except socket.timeout:
        pass
    data = b"".join(chunks)
    if data:
        fc = (data[0] << 8 | data[1]) if len(data) >= 2 else 0
        log.debug("RECV fc=0x%04x total=%d bytes", fc, len(data))
    return data


def destuff(data: bytes) -> bytearray:
    """Remove 0x20 byte-stuffing from protocol data."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x20 and i + 1 < len(data):
            out.append(data[i + 1])
            i += 2
        else:
            out.append(data[i])
            i += 1
    return out


def connect_and_handshake(host: str, port: int,
                          timeout: float = 10.0) -> socket.socket:
    """Connect to the XG and perform session handshake."""
    log.info("Connecting to %s:%d ...", host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    log.info("TCP connected")

    # Session open (may be ignored)
    send_frame(sock, FC_SESSION_OPEN_REQ, flags=0x000F)
    try:
        resp = recv_all(sock, timeout=1.0)
        fc = (resp[0] << 8 | resp[1]) if len(resp) >= 2 else 0
        log.info("Session open response: 0x%04x (%d bytes)", fc, len(resp))
    except socket.timeout:
        log.info("Session open: no ACK (proceeding)")

    # Session init
    send_frame(sock, FC_SESSION_INIT)
    resp = recv_all(sock, timeout=3.0)
    fc = (resp[0] << 8 | resp[1]) if len(resp) >= 2 else 0
    log.info("Session init response: 0x%04x (%d bytes)", fc, len(resp))

    return sock


def request_device_info(sock: socket.socket) -> dict:
    """Request basic device info (TCP_ReqInfo -> TCP_Info)."""
    log.info("Requesting device info (0x2013)...")
    send_frame(sock, FC_REQ_INFO)
    resp = recv_all(sock, timeout=5.0)

    info = {"raw_hex": resp.hex(), "raw_length": len(resp)}
    if len(resp) > SESSION_HDR_SIZE:
        payload = resp[SESSION_HDR_SIZE:]
        ds = destuff(payload)
        info["destuffed_hex"] = ds.hex()
        info["destuffed_length"] = len(ds)
        # Try to extract readable strings
        strings = []
        for s in ds.split(b"\x00"):
            try:
                t = s.decode("ascii")
                if len(t) > 2 and t.isprintable():
                    strings.append(t)
            except (UnicodeDecodeError, ValueError):
                pass
        info["strings"] = strings
    log.info("Device info: %d bytes, strings: %s", len(resp), info.get("strings", []))
    return info


def request_ext_info_dx41(sock: socket.socket) -> dict:
    """Request extended info for DX41 (Orthophos XG)."""
    log.info("Requesting ExtInfo DX41 (0x2019)...")
    send_frame(sock, FC_REQ_EXT_INFO_DX41)
    resp = recv_all(sock, timeout=5.0)

    info = {"raw_hex": resp.hex(), "raw_length": len(resp)}
    if len(resp) > SESSION_HDR_SIZE:
        payload = destuff(resp[SESSION_HDR_SIZE:])
        info["destuffed_hex"] = payload.hex()
        info["destuffed_length"] = len(payload)
    log.info("ExtInfo DX41: %d bytes", len(resp))
    return info


def request_pan_adjust_data(sock: socket.socket) -> dict:
    """Request panoramic adjustment/calibration data.

    Sends TCP_ReqGetPanAdjustDataAll and parses the response
    (TCP_GetPanAdjustDataAll = 0x20B7) which contains geometric
    offsets and calibration parameters.
    """
    log.info("Requesting PanAdjustDataAll...")

    # The request might need an AdjustID parameter.
    # Try sending with empty payload first (some commands don't need params).
    send_frame(sock, FC_REQ_GET_PAN_ADJUST)
    resp = recv_all(sock, timeout=10.0)

    result = {"raw_hex": resp.hex(), "raw_length": len(resp)}

    if len(resp) > SESSION_HDR_SIZE:
        payload = destuff(resp[SESSION_HDR_SIZE:])
        result["destuffed_hex"] = payload.hex()
        result["destuffed_length"] = len(payload)

        # Parse known fields from TCP_GetPanAdjustDataAll (0x20B7):
        # W #State, DW #TpDx, DW #TpDy, DW #TpDAlpha,
        # DW #OffsetA1, DW #OffsetA2, DW #OffsetC1,
        # DW #OffsetBx, DW #OffsetBy, DW #OffsetBf,
        # DW #TsaOffsetBx, DW #TsaOffsetBy, DW #TsaOffsetBf,
        # DW #TsaOffsetBs, DW #OffsetTu
        if len(payload) >= 58:
            fields = {}
            off = 0
            fields["State"] = struct.unpack_from(">H", payload, off)[0]; off += 2
            for name in ["TpDx", "TpDy", "TpDAlpha",
                         "OffsetA1", "OffsetA2", "OffsetC1",
                         "OffsetBx", "OffsetBy", "OffsetBf",
                         "TsaOffsetBx", "TsaOffsetBy", "TsaOffsetBf",
                         "TsaOffsetBs", "OffsetTu"]:
                fields[name] = struct.unpack_from(">I", payload, off)[0]
                off += 4
            result["fields"] = fields
            log.info("PanAdjust fields: %s", fields)

    fc = (resp[0] << 8 | resp[1]) if len(resp) >= 2 else 0
    log.info("PanAdjustData response: fc=0x%04x, %d bytes", fc, len(resp))
    return result


def request_file(sock: socket.socket, filename: str,
                 device_id: int = 0, file_id: int = 0) -> bytes | None:
    """Request a file from the device (TCP_ReqFile -> TCP_File).

    Can be used to download SGF gain correction files.
    """
    log.info("Requesting file: '%s' (device=%d, file=%d)...", filename, device_id, file_id)

    # Build payload: W #DeviceId, W #FileId, BA8 #Filename
    fname_bytes = filename.encode("ascii")[:8].ljust(8, b"\x00")
    payload = struct.pack(">HH", device_id, file_id) + fname_bytes
    send_frame(sock, FC_REQ_FILE, payload)

    # Response may be large (SGF files up to 1MB)
    resp = recv_all(sock, timeout=30.0)

    fc = (resp[0] << 8 | resp[1]) if len(resp) >= 2 else 0
    log.info("File response: fc=0x%04x, %d bytes", fc, len(resp))

    if len(resp) > SESSION_HDR_SIZE:
        payload_raw = resp[SESSION_HDR_SIZE:]
        ds = destuff(payload_raw)
        # TCP_File: W #State, W #DeviceId, W #FileId, BA8 #Filename, BLOB #Data
        if len(ds) > 14:
            state = struct.unpack_from(">H", ds, 0)[0]
            ret_dev = struct.unpack_from(">H", ds, 2)[0]
            ret_fid = struct.unpack_from(">H", ds, 4)[0]
            ret_name = ds[6:14].rstrip(b"\x00").decode("ascii", errors="replace")
            file_data = bytes(ds[14:])
            log.info("File '%s': state=%d, %d bytes of data", ret_name, state, len(file_data))
            return file_data

    return None


def request_service_function_table(sock: socket.socket) -> dict:
    """Request the service function table to see what commands are available."""
    log.info("Requesting ServiceFunctionTable (0x210A)...")
    send_frame(sock, FC_REQ_SERVICE_TABLE)
    resp = recv_all(sock, timeout=5.0)
    result = {"raw_hex": resp[:200].hex(), "raw_length": len(resp)}
    fc = (resp[0] << 8 | resp[1]) if len(resp) >= 2 else 0
    log.info("ServiceFunctionTable response: fc=0x%04x, %d bytes", fc, len(resp))
    return result


def capture_full_scan_session(host: str, port: int = MAIN_PORT,
                              timeout: float = 120.0) -> bytes:
    """Connect to the MAIN port and capture the full session including
    the 0x1002 XRayImgBegin frame with SGFHeader.

    This captures everything from connection until the scan completes.
    The user must trigger the scan on the device while this is running.
    """
    log.info("Connecting to main port %s:%d for full session capture...", host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))

    # Handshake
    send_frame(sock, FC_SESSION_OPEN_REQ, flags=0x000F)
    try:
        recv_all(sock, timeout=1.0)
    except socket.timeout:
        pass
    send_frame(sock, FC_SESSION_INIT)
    recv_all(sock, timeout=3.0)

    log.info("Connected. Waiting for scan data (trigger exposure on device)...")
    log.info("Will capture for up to %.0f seconds...", timeout)

    # Capture everything
    all_data = bytearray()
    sock.settimeout(2.0)
    deadline = time.time() + timeout
    got_1003 = False
    got_1004 = False

    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            all_data.extend(chunk)

            # Check for frame types in the chunk
            sig = bytes([0x07, 0x2d, 0x07, 0xd0])
            pos = 0
            while True:
                idx = chunk.find(sig, pos)
                if idx < 0:
                    break
                h = idx - 2
                if h >= 0:
                    fc = (chunk[h] << 8) | chunk[h + 1]
                    if fc == 0x1002:
                        log.info("Got 0x1002 (XRayImgBegin) — SGF header inside!")
                    elif fc == 0x1003 and not got_1003:
                        log.info("Got first 0x1003 (pixel data)")
                        got_1003 = True
                    elif fc == 0x1004:
                        log.info("Got 0x1004 (XRayImgEnd) — scan complete")
                        got_1004 = True
                pos = idx + 4

            if got_1004:
                # Give a moment for trailing data
                time.sleep(0.5)
                try:
                    chunk = sock.recv(65536)
                    if chunk:
                        all_data.extend(chunk)
                except socket.timeout:
                    pass
                break

            # Send heartbeat periodically to keep session alive
            if not got_1003:
                send_frame(sock, FC_HB_REQUEST)

        except socket.timeout:
            if not got_1003:
                send_frame(sock, FC_HB_REQUEST)
            continue

    sock.close()
    log.info("Captured %d bytes total", len(all_data))
    return bytes(all_data)


def main():
    parser = argparse.ArgumentParser(
        description="PureXS Calibration Data Capture"
    )
    parser.add_argument("--host", default="192.168.139.170",
                        help="XG device IP address")
    parser.add_argument("--port", type=int, default=None,
                        help="TCP port (default: tries service 12836 then main 12837)")
    parser.add_argument("--output", "-o", default="calibration_data",
                        help="Output directory")
    parser.add_argument("--mode", choices=["service", "scan", "both"],
                        default="both",
                        help="'service' = query service port, "
                             "'scan' = capture full scan with 0x1002, "
                             "'both' = do both")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    results = {}

    # ── Service port queries ─────────────────────────────────────────
    if args.mode in ("service", "both"):
        port = args.port or SERVICE_PORT
        try:
            sock = connect_and_handshake(args.host, port)

            # 1. Device info
            info = request_device_info(sock)
            results["device_info"] = info

            # 2. Extended info (DX41 specific)
            ext = request_ext_info_dx41(sock)
            results["ext_info_dx41"] = ext

            # 3. Pan adjustment data (geometric calibration)
            adjust = request_pan_adjust_data(sock)
            results["pan_adjust_data"] = adjust

            # 4. Service function table
            sft = request_service_function_table(sock)
            results["service_function_table"] = sft

            # 5. Try to download SGF file
            # The SGF filename from our pre-scan data was "SGFP4_4sgf"
            for sgf_name in ["SGFP4_4s", "0000000", "DEFAULT"]:
                sgf_data = request_file(sock, sgf_name)
                if sgf_data and len(sgf_data) > 128:
                    sgf_path = outdir / f"sgf_{sgf_name}.bin"
                    sgf_path.write_bytes(sgf_data)
                    log.info("Saved SGF data: %s (%d bytes)", sgf_path, len(sgf_data))
                    results[f"sgf_{sgf_name}"] = {
                        "size": len(sgf_data),
                        "path": str(sgf_path),
                    }

            sock.close()
        except Exception as e:
            log.error("Service port connection failed: %s", e)
            log.info("The device may not support service port connections, "
                     "or it may be busy. Try --mode scan instead.")

    # ── Full scan capture (includes 0x1002 with SGFHeader) ───────────
    if args.mode in ("scan", "both"):
        port = args.port or MAIN_PORT
        log.info("\n" + "=" * 60)
        log.info("FULL SCAN CAPTURE MODE")
        log.info("Connect to the device and trigger an X-ray exposure.")
        log.info("The capture will include the 0x1002 frame with calibration data.")
        log.info("=" * 60)

        try:
            scan_data = capture_full_scan_session(args.host, port)
            if scan_data:
                scan_path = outdir / "full_scan_session.bin"
                scan_path.write_bytes(scan_data)
                log.info("Saved full scan: %s (%d bytes)", scan_path, len(scan_data))
                results["full_scan"] = {
                    "size": len(scan_data),
                    "path": str(scan_path),
                }

                # Check if we got the 0x1002 frame
                sig = bytes([0x07, 0x2d, 0x07, 0xd0])
                pos = 0
                frame_types = {}
                while pos < len(scan_data) - 6:
                    idx = scan_data.find(sig, pos)
                    if idx < 0:
                        break
                    h = idx - 2
                    if h >= 0:
                        fc = (scan_data[h] << 8) | scan_data[h + 1]
                        frame_types[fc] = frame_types.get(fc, 0) + 1
                    pos = idx + 4
                log.info("Frame types captured: %s",
                         {f"0x{k:04x}": v for k, v in sorted(frame_types.items())})
                results["frame_types"] = {f"0x{k:04x}": v for k, v in frame_types.items()}
        except Exception as e:
            log.error("Scan capture failed: %s", e)

    # ── Save results ─────────────────────────────────────────────────
    results_path = outdir / "calibration_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log.info("Results saved to %s", results_path)

    print("\n" + "=" * 60)
    print("CALIBRATION CAPTURE COMPLETE")
    print("=" * 60)
    print(f"Output directory: {outdir}")
    for key, val in results.items():
        if isinstance(val, dict) and "size" in val:
            print(f"  {key}: {val['size']} bytes -> {val.get('path', 'N/A')}")
        elif isinstance(val, dict) and "raw_length" in val:
            print(f"  {key}: {val['raw_length']} bytes")
    print()
    print("Next steps:")
    print("  1. Check calibration_results.json for captured data")
    print("  2. If SGF files were downloaded, they contain flat-field correction data")
    print("  3. If full_scan_session.bin was captured, it includes the 0x1002 frame")
    print("     with SGFHeader and DieWidthPixel calibration parameters")


if __name__ == "__main__":
    main()
