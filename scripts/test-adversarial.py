#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

"""Adversarial container & cross-SDK verification harness (Node TypeScript SDK + Python SDK)."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "sdk", "python"))

from zero_origin_verify import detect_format, extract_jumbf  # noqa: E402


def run_adversarial_container_checks():
    # 1. Malformed truncated JPEG header must raise ValueError cleanly (no panic/hang)
    try:
        extract_jumbf(b"\xff\xd8\xff\xeb\x00\xff")
        raise AssertionError("Expected truncated JPEG to fail")
    except ValueError:
        pass

    # 2. PNG with corrupted CRC32 inside caBX chunk must fail validation cleanly
    import struct
    bad_cabx = struct.pack(">I", 4) + b"caBX" + b"test" + struct.pack(">I", 0xDEADBEEF)
    bad_png = b"\x89PNG\r\n\x1a\n" + bad_cabx
    try:
        extract_jumbf(bad_png)
        raise AssertionError("Expected invalid PNG CRC32 to be caught")
    except ValueError as err:
        assert "CRC" in str(err)

    # 3. Unrecognized file payload rejected cleanly
    try:
        detect_format(b"MALICIOUS_EXE_HEADER")
        raise AssertionError("Expected unknown format to fail")
    except ValueError:
        pass


def main():
    run_adversarial_container_checks()
    print("[PASS] Adversarial malformed container & PNG CRC tamper checks passed.")

    # Execute Python SDK suite
    subprocess.run([sys.executable, os.path.join(ROOT, "sdk", "python", "test_verify.py")], check=True)

    # Execute Node/TypeScript SDK suite
    subprocess.run(["node", os.path.join(ROOT, "sdk", "typescript", "test.js")], check=True)

    print("[PASS] Cross-SDK & adversarial verification complete.")


if __name__ == "__main__":
    main()
