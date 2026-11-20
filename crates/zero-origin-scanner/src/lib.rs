// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! `zero-origin-scanner` (Apache-2.0): Sovereign Split-Screen Telemetry Comparator
//! (`unsafe.originzero.art` vs. `originzero.art`) and "99% -> 1%" DNS/IP Academy.
//! Strictly enforces a closed enumerated target allowlist (Zero-SSRF) and read-only
//! SQLite WAL audit telemetry inspection.

pub mod audit_reader;
pub mod config;
pub mod probe;
pub mod server;
