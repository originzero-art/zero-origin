# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

"""Pure-Python Apache-2.0 verifier for zero-origin C2PA/JUMBF containers & HTTP TDM headers."""

import hashlib
import json
import struct
import zlib
from typing import Dict, Optional, Tuple

C2PA_JUMBF_UUID = bytes.fromhex("6332706100110010800000aa00389b71")
ISOBMFF_C2PA_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")


def detect_format(data: bytes) -> str:
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WebP"
    if len(data) >= 12 and data[4:8] == b"ftyp" and data[8:12] in (b"avif", b"avis", b"mif1", b"heic"):
        return "AVIF"
    raise ValueError("Unsupported or unrecognized media format")


def _sha256_excluded(data: bytes, start: int, end: int) -> str:
    h = hashlib.sha256()
    h.update(data[:start])
    h.update(data[end:])
    return h.hexdigest()


def extract_jumbf(data: bytes) -> Tuple[str, bytes, str]:
    fmt = detect_format(data)

    if fmt == "JPEG":
        pos = 2
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                raise ValueError(f"Malformed JPEG at {pos}")
            while pos < len(data) and data[pos] == 0xFF:
                pos += 1
            if pos >= len(data):
                break
            marker = data[pos]
            seg_start = pos - 1
            pos += 1
            if marker in (0xD9, 0xDA):
                break
            if (0xD0 <= marker <= 0xD7) or marker == 0x01:
                continue
            seg_len = struct.unpack(">H", data[pos : pos + 2])[0]
            seg_end = pos + seg_len
            if seg_len < 2 or seg_end > len(data):
                raise ValueError(f"Malformed JPEG segment at {pos}")
            payload = data[pos + 2 : seg_end]
            if marker == 0xEB and len(payload) >= 8 and payload[:2] == b"JP":
                return ("JPEG", payload[8:], _sha256_excluded(data, seg_start, seg_end))
            pos = seg_end
        raise ValueError("JUMBF APP11 manifest not found in JPEG")

    if fmt == "PNG":
        pos = 8
        while pos + 12 <= len(data):
            chunk_len = struct.unpack(">I", data[pos : pos + 4])[0]
            ctype = data[pos + 4 : pos + 8]
            data_start = pos + 8
            data_end = data_start + chunk_len
            chunk_end = data_end + 4
            if chunk_end > len(data):
                raise ValueError(f"Malformed PNG chunk at {pos}")
            if ctype == b"caBX":
                expected_crc = struct.unpack(">I", data[data_end:chunk_end])[0]
                if (zlib.crc32(data[pos + 4 : data_end]) & 0xFFFFFFFF) != expected_crc:
                    raise ValueError("Invalid PNG CRC-32 checksum in caBX chunk")
                return ("PNG", data[data_start:data_end], _sha256_excluded(data, pos, chunk_end))
            if ctype == b"IEND":
                break
            pos = chunk_end
        raise ValueError("caBX manifest chunk not found in PNG")

    if fmt == "WebP":
        current_riff = struct.unpack("<I", data[4:8])[0]
        pos = 12
        while pos + 8 <= len(data):
            fourcc = data[pos : pos + 4]
            chunk_len = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
            data_start = pos + 8
            data_end = data_start + chunk_len
            chunk_end = data_end + (chunk_len % 2)
            if chunk_end > len(data):
                raise ValueError(f"Malformed WebP chunk at {pos}")
            if fourcc == b"C2PA":
                orig_riff = struct.pack("<I", max(0, current_riff - (chunk_end - pos)))
                h = hashlib.sha256()
                h.update(data[:4])
                h.update(orig_riff)
                h.update(data[8:pos])
                h.update(data[chunk_end:])
                return ("WebP", data[data_start:data_end], h.hexdigest())
            pos = chunk_end
        raise ValueError("C2PA chunk not found in WebP")

    # AVIF
    pos = 0
    while pos + 8 <= len(data):
        box_size = struct.unpack(">I", data[pos : pos + 4])[0]
        box_type = data[pos + 4 : pos + 8]
        hdr_len = 8
        if box_size == 1 and pos + 16 <= len(data):
            box_size = struct.unpack(">Q", data[pos + 8 : pos + 16])[0]
            hdr_len = 16
        elif box_size == 0:
            box_size = len(data) - pos
        if box_size < hdr_len or pos + box_size > len(data):
            raise ValueError(f"Malformed ISOBMFF box at {pos}")
        if box_type == b"uuid" and box_size >= hdr_len + 16:
            if data[pos + hdr_len : pos + hdr_len + 16] == ISOBMFF_C2PA_UUID:
                return ("AVIF", data[pos + hdr_len + 16 : pos + box_size], _sha256_excluded(data, pos, pos + box_size))
        pos += box_size
    raise ValueError("C2PA UUID box not found in AVIF")


def decode_jumbf_envelope(jumb: bytes) -> dict:
    if len(jumb) < 8 or jumb[4:8] != b"jumb":
        raise ValueError("Invalid JUMBF superbox")
    declared_len = struct.unpack(">I", jumb[:4])[0]
    if declared_len > len(jumb):
        raise ValueError("Truncated JUMBF superbox")
    pos = 8
    uuid_ok = False
    payload_json: Optional[bytes] = None
    while pos + 8 <= declared_len:
        blen = struct.unpack(">I", jumb[pos : pos + 4])[0]
        btype = jumb[pos + 4 : pos + 8]
        if blen < 8 or pos + blen > declared_len:
            raise ValueError("Malformed child JUMBF box")
        body = jumb[pos + 8 : pos + blen]
        if btype == b"jumd" and body[:16] == C2PA_JUMBF_UUID:
            uuid_ok = True
        elif btype == b"json":
            payload_json = body
        pos += blen
    if not uuid_ok or payload_json is None:
        raise ValueError("Missing C2PA UUID or JSON claim box")
    return json.loads(payload_json.decode("utf-8"))


def audit_http_rights_headers(headers: Dict[str, str]) -> dict:
    norm = {k.lower(): v.strip() for k, v in headers.items()}
    tdm_res = norm.get("tdm-reservation")
    link = norm.get("link")
    valid_link = link if link and ('rel="license"' in link or "rel='license'" in link) else None
    return {
        "tdm_reservation": tdm_res,
        "tdm_policy": norm.get("tdm-policy"),
        "content_usage": norm.get("content-usage"),
        "rfc8288_license_link": valid_link,
        "x_robots_tag": norm.get("x-robots-tag"),
        "rights_enforced": tdm_res == "1" and valid_link is not None,
    }
