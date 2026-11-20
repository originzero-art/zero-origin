// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! `zero-origin-proxy` (AGPL-3.0-or-later): Deterministic Layer-7 Edge Shield.

pub mod classifier;
pub mod config;
pub mod fcrdns;
pub mod proxy_protocol;
pub mod server;
pub mod telemetry;
