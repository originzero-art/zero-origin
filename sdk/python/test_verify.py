# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

import hashlib
import json
import struct
import zlib
from zero_origin_verify import (
    C2PA_JUMBF_UUID,
    audit_http_rights_headers,
    decode_jumbf_envelope,
    extract_jumbf,
)


def main():
    # 1. Verify HTTP TDM headers audit
    audit = audit_http_rights_headers({
        "TDM-Reservation": "1",
        "Content-Usage": "train-ai=n, search=y",
        "Link": '<https://originzero.art/license/tdm-reservation>; rel="license"',
        "X-Robots-Tag": "noai, noimageai",
    })
    assert audit["rights_enforced"] is True
    assert audit["content_usage"] == "train-ai=n, search=y"

    # 2. Construct PNG with valid CRC32 caBX JUMBF box and verify hash extraction
    png_header = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">I", 13) + b"IHDR" + b"\x00" * 13 + struct.pack(">I", 0)
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)
    orig_png = png_header + ihdr + iend
    orig_hash = hashlib.sha256(orig_png).hexdigest()

    claim = json.dumps({"creator_name": "757", "asset_sha256": orig_hash})
    envelope_bytes = json.dumps({"alg": "ed25519", "claim_json": claim}).encode("utf-8")

    jumd = struct.pack(">I", 30) + b"jumd" + C2PA_JUMBF_UUID + b"\x03c2pa\x00"
    json_box = struct.pack(">I", 8 + len(envelope_bytes)) + b"json" + envelope_bytes
    jumb = struct.pack(">I", 8 + len(jumd) + len(json_box)) + b"jumb" + jumd + json_box

    crc = zlib.crc32(b"caBX" + jumb) & 0xFFFFFFFF
    cabx = struct.pack(">I", len(jumb)) + b"caBX" + jumb + struct.pack(">I", crc)
    signed_png = png_header + ihdr + cabx + iend

    fmt, extracted_jumb, computed_sha = extract_jumbf(signed_png)
    assert fmt == "PNG"
    assert computed_sha == orig_hash
    env = decode_jumbf_envelope(extracted_jumb)
    assert json.loads(env["claim_json"])["creator_name"] == "757"
    print("[PASS] zero_origin_verify Python SDK tests succeeded.")


if __name__ == "__main__":
    main()
