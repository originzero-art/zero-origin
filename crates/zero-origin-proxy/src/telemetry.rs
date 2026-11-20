// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Embedded SQLite (WAL mode) Zero-PII Audit Telemetry.
//! Logs crawler drops, matched rule IDs, and anonymized network prefixes
//! without storing full visitor IP addresses or personal data.

use std::net::IpAddr;
use std::sync::Mutex;

use chrono::Utc;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, Clone)]
pub struct AuditSummary {
    pub total_blocked: i64,
    pub total_rate_limited: i64,
    pub recent_rules: Vec<(String, i64)>,
}

pub struct AuditStore {
    conn: Mutex<Connection>,
}

/// Anonymizes client IPs to `/24` (IPv4) or `/48` (IPv6) + short salted hash prefix
/// to preserve telemetry utility while guaranteeing zero PII retention.
pub fn anonymize_ip(ip: IpAddr) -> String {
    let prefix = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(ip.to_string().as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{}#{}", prefix, &digest[..8])
}

impl AuditStore {
    pub fn open(path: &str) -> Result<Self, TelemetryError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
             CREATE TABLE IF NOT EXISTS edge_audit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp_utc TEXT NOT NULL,
                 action TEXT NOT NULL,
                 rule_id TEXT NOT NULL,
                 client_prefix TEXT NOT NULL,
                 ja4_hash TEXT,
                 method TEXT NOT NULL,
                 path_prefix TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_edge_audit_ts ON edge_audit(timestamp_utc);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn record_event(
        &self,
        action: &str,
        rule_id: &str,
        client_ip: IpAddr,
        ja4_hash: Option<&str>,
        method: &str,
        raw_path: &str,
    ) {
        let ts = Utc::now().to_rfc3339();
        let client_prefix = anonymize_ip(client_ip);
        // Truncate path at query boundary to avoid accidental query-token leakage
        let clean_path: String = raw_path
            .split('?')
            .next()
            .unwrap_or("/")
            .chars()
            .take(128)
            .collect();

        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO edge_audit (timestamp_utc, action, rule_id, client_prefix, ja4_hash, method, path_prefix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![ts, action, rule_id, client_prefix, ja4_hash, method, clean_path],
            );
        }
    }

    pub fn summary(&self) -> Result<AuditSummary, TelemetryError> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(p) => p.into_inner(),
        };

        let total_blocked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM edge_audit WHERE action = 'BLOCK_403'",
            [],
            |r| r.get(0),
        )?;
        let total_rate_limited: i64 = conn.query_row(
            "SELECT COUNT(*) FROM edge_audit WHERE action = 'RATE_429'",
            [],
            |r| r.get(0),
        )?;

        let mut stmt = conn.prepare(
            "SELECT rule_id, COUNT(*) as cnt FROM edge_audit GROUP BY rule_id ORDER BY cnt DESC LIMIT 10",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut recent_rules = Vec::new();
        for r in rows {
            recent_rules.push(r?);
        }

        Ok(AuditSummary {
            total_blocked,
            total_rate_limited,
            recent_rules,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_zero_pii_anonymization() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 145));
        let anon_v4 = anonymize_ip(v4);
        assert!(anon_v4.starts_with("192.0.2.0/24#"));
        assert!(!anon_v4.contains(".145"));

        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x1234, 0, 0, 0, 1));
        let anon_v6 = anonymize_ip(v6);
        assert!(anon_v6.starts_with("2001:db8:85a3::/48#"));
        assert!(!anon_v6.contains("1234"));
    }

    #[test]
    fn test_in_memory_sqlite_audit_summary() {
        let store = AuditStore::open(":memory:").expect("sqlite memory DB opens");
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12));
        store.record_event("BLOCK_403", "RULE-UA-BOT:gptbot", ip, None, "GET", "/painting.jpg?token=secret");
        store.record_event("RATE_429", "RULE-RATE-LIMIT-RPM", ip, None, "GET", "/gallery");

        let sum = store.summary().unwrap();
        assert_eq!(sum.total_blocked, 1);
        assert_eq!(sum.total_rate_limited, 1);
        assert_eq!(sum.recent_rules.len(), 2);
    }
}
