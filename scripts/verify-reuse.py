#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

"""REUSE 3.0 SPDX, Dual-License DAG Isolation & originZero.Art Invariant Auditor."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APACHE_DIRS = (
    "crates/zero-origin-common",
    "crates/zero-origin-verify",
    "crates/zero-origin-scanner",
    "specs",
    "schemas",
    "sdk",
    "config",
    "scripts",
    "docs",
    ".agents",
    ".github",
)

AGPL_DIRS = (
    "crates/zero-origin-ja4",
    "crates/zero-origin-c2pa",
    "crates/zero-origin-proxy",
    "crates/zero-origin-cli",
    "benches",
)

AGPL_CRATES = {
    "zero-origin-ja4",
    "zero-origin-c2pa",
    "zero-origin-proxy",
    "zero-origin-cli",
}

TEXT_CODE_EXTS = {
    ".rs",
    ".py",
    ".js",
    ".ts",
    ".go",
    ".toml",
    ".service",
    ".timer",
    ".yml",
    ".yaml",
    ".html",
    ".css",
    ".sh",
    ".conf",
}
BANNED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".avif", ".gif", ".ico"}


def expected_license_for(rel_path: str) -> str:
    for prefix in AGPL_DIRS:
        if rel_path.startswith(prefix + "/") or rel_path == prefix:
            return "AGPL-3.0-or-later"
    return "Apache-2.0"


def check_repo():
    errors = []
    checked_files = 0

    for dirpath, _, filenames in os.walk(ROOT):
        if "/target" in dirpath or "/.git/" in dirpath or dirpath.endswith("/.git"):
            continue
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, ROOT).replace(os.sep, "/")
            _, ext = os.path.splitext(fname)

            # 1. Zero AI-generated raster visual assets rule
            if ext.lower() in BANNED_IMAGE_EXTS and not rel.startswith("tests/fixtures"):
                errors.append(f"[IMAGE-BAN] Raster asset not permitted in public source repo: {rel}")

            # 2. Explicit SPDX header check across code, config, CI workflows, and packaging files
            if ext in TEXT_CODE_EXTS or fname == "Containerfile":
                checked_files += 1
                with open(full, "r", encoding="utf-8") as fh:
                    head = "".join(fh.readline() for _ in range(6))
                expected = expected_license_for(rel)
                if f"SPDX-License-Identifier: {expected}" not in head:
                    errors.append(
                        f"[SPDX-MISSING] {rel} missing 'SPDX-License-Identifier: {expected}'"
                    )
                if "SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>" not in head:
                    errors.append(f"[COPYRIGHT-MISSING] {rel} missing canonical SPDX-FileCopyrightText")

            # 3. Open-Core DAG check: Apache-2.0 crates MUST NEVER link AGPL crates
            if fname == "Cargo.toml" and rel.startswith("crates/"):
                crate_dir = rel.split("/")[1]
                if crate_dir in ("zero-origin-common", "zero-origin-verify", "zero-origin-scanner"):
                    with open(full, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    for agpl_dep in AGPL_CRATES:
                        if agpl_dep in content:
                            errors.append(
                                f"[LICENSE-LEAK] Apache-2.0 crate {crate_dir} MUST NOT depend on AGPL crate {agpl_dep}"
                            )

            # 4. Zero em-dash / en-dash check across Romanian scanner & academy UI files
            if rel.startswith("crates/zero-origin-scanner/web/") and ext in (".html", ".js"):
                with open(full, "r", encoding="utf-8") as fh:
                    ui_text = fh.read()
                if "—" in ui_text or "–" in ui_text:
                    errors.append(f"[PUNCTUATION-BAN] Forbidden em/en-dash found in {rel}")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)

    print(
        f"[PASS] REUSE 3.0 & Dual-License DAG audit succeeded ({checked_files} code/config/CI files verified; 0 boundary leaks; 0 raster images)."
    )


if __name__ == "__main__":
    check_repo()
