// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Read-Only SQLite WAL Telemetry Reader for `scanner.originzero.art`.
//! Opens `zero-origin-audit.db` strictly with `SQLITE_OPEN_READ_ONLY` + `PRAGMA query_only=ON`
//! to display live zero-PII crawler drop proofs without write capability.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventRow {
    pub id: i64,
    pub timestamp_utc: String,
    pub action: String,
    pub rule_id: String,
    pub client_prefix: String,
    pub ja4_hash: Option<String>,
    pub method: String,
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFeedReport {
    pub available: bool,
    pub wal_mode: String,
    pub total_blocked_403: i64,
    pub total_rate_limited_429: i64,
    pub total_rejected_400: i64,
    pub recent_events: Vec<AuditEventRow>,
}

impl AuditFeedReport {
    pub fn empty_unavailable() -> Self {
        Self {
            available: false,
            wal_mode: "unavailable".to_string(),
            total_blocked_403: 0,
            total_rate_limited_429: 0,
            total_rejected_400: 0,
            recent_events: Vec::new(),
        }
    }
}

/// Reads the latest zero-PII blocked events from `zero-origin-audit.db` in strictly read-only mode.
pub fn read_audit_wal_feed(db_path: &str, limit: usize) -> AuditFeedReport {
    let capped_limit = limit.clamp(1, 25);
    if !Path::new(db_path).exists() {
        return AuditFeedReport::empty_unavailable();
    }

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = match Connection::open_with_flags(db_path, flags) {
        Ok(c) => c,
        Err(_) => return AuditFeedReport::empty_unavailable(),
    };

    let _ = conn.execute_batch("PRAGMA busy_timeout = 2000; PRAGMA query_only = ON;");

    let wal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
        .unwrap_or_else(|_| "unknown".to_string());

    let total_blocked_403: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM edge_audit WHERE action = 'BLOCK_403'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let total_rate_limited_429: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM edge_audit WHERE action = 'RATE_429'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let total_rejected_400: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM edge_audit WHERE action = 'REJECT_400'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let mut recent_events = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, timestamp_utc, action, rule_id, client_prefix, ja4_hash, method, path_prefix
         FROM edge_audit
         ORDER BY id DESC
         LIMIT ?1",
    ) {
        if let Ok(rows) = stmt.query_map([capped_limit as i64], |r| {
            Ok(AuditEventRow {
                id: r.get(0)?,
                timestamp_utc: r.get(1)?,
                action: r.get(2)?,
                rule_id: r.get(3)?,
                client_prefix: r.get(4)?,
                ja4_hash: r.get(5)?,
                method: r.get(6)?,
                path_prefix: r.get(7)?,
            })
        }) {
            for item in rows.flatten() {
                recent_events.push(item);
            }
        }
    }

    AuditFeedReport {
        available: true,
        wal_mode,
        total_blocked_403,
        total_rate_limited_429,
        total_rejected_400,
        recent_events,
    }
}
