// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Runtime configuration schema (TOML) for `zero-origin` L7 edge proxy.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zero_origin_common::rights::OriginRightsPolicy;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed reading config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SniCertConfig {
    pub server_name: String,
    pub cert_path: String,
    pub key_path: String,
}

fn default_max_concurrent_connections() -> usize {
    10_240
}
fn default_header_read_timeout_secs() -> u64 {
    10
}
fn default_tls_handshake_timeout_secs() -> u64 {
    5
}
fn default_upstream_timeout_secs() -> u64 {
    30
}
fn default_http2_keepalive_interval_secs() -> u64 {
    15
}
fn default_http2_keepalive_timeout_secs() -> u64 {
    20
}
fn default_true() -> bool {
    true
}
fn default_fcrdns_cache_ttl_secs() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Local address to bind incoming HTTP/TLS traffic (e.g. "127.0.0.1:8088")
    pub listen_addr: String,
    /// Downstream private origin upstream URL (e.g. "http://127.0.0.1:8080")
    pub upstream_origin: String,
    /// Optional per-host upstream routing map (lowercase Host/SNI -> upstream origin URL)
    #[serde(default)]
    pub upstream_routes: HashMap<String, String>,
    /// Optional default TLS certificate chain PEM path (enables HTTPS + raw JA4 peek)
    pub tls_cert_path: Option<String>,
    /// Optional default TLS private key PEM path
    pub tls_key_path: Option<String>,
    /// Optional per-SNI TLS certificates (`ResolvesServerCertUsingSni`)
    #[serde(default)]
    pub tls_sni_certs: Vec<SniCertConfig>,
    /// Path to embedded SQLite WAL audit telemetry database
    pub sqlite_path: String,
    /// Requests per minute allowed per client IP before deterministic 429 limit
    pub rate_limit_rpm: u32,
    /// Maximum active concurrent client sockets capped via Semaphore
    #[serde(default = "default_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
    /// Slowloris HTTP/1 header read deadline in seconds (enforced via TokioTimer)
    #[serde(default = "default_header_read_timeout_secs")]
    pub header_read_timeout_secs: u64,
    /// Pre-HTTP socket peek + PROXY protocol + TLS handshake timeout in seconds
    #[serde(default = "default_tls_handshake_timeout_secs")]
    pub tls_handshake_timeout_secs: u64,
    /// Upstream reverse-proxy request timeout in seconds (504 Gateway Timeout on expiry)
    #[serde(default = "default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,
    /// HTTP/2 PING keepalive interval in seconds
    #[serde(default = "default_http2_keepalive_interval_secs")]
    pub http2_keepalive_interval_secs: u64,
    /// HTTP/2 PING keepalive acknowledgement timeout in seconds
    #[serde(default = "default_http2_keepalive_timeout_secs")]
    pub http2_keepalive_timeout_secs: u64,
    /// Accept HAProxy PROXY protocol v1/v2 ONLY from `trusted_proxy_cidrs`
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    /// Verify claimed search indexers (`Googlebot`, `Bingbot`, etc.) via async FCrDNS
    #[serde(default = "default_true")]
    pub verify_search_bots_fcrdns: bool,
    /// Optional explicit UDP DNS resolver (`host:port`) for FCrDNS PTR queries
    #[serde(default)]
    pub fcrdns_resolver: Option<String>,
    /// Cached FCrDNS entry TTL in seconds
    #[serde(default = "default_fcrdns_cache_ttl_secs")]
    pub fcrdns_cache_ttl_secs: u64,
    /// Trusted upstream load-balancer CIDRs allowed to assert X-Forwarded-For / PROXY protocol
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    /// Additional blocked datacenter/botnet CIDRs
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,
    /// Explicitly blocked JA4 TLS fingerprints
    #[serde(default)]
    pub blocked_ja4: Vec<String>,
    /// Additional blocked User-Agent substring signatures
    #[serde(default)]
    pub extra_blocked_user_agents: Vec<String>,
    /// Rights declaration injected on responses and /ai.txt + tdmrep.json
    #[serde(default)]
    pub rights: OriginRightsPolicy,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8088".to_string(),
            upstream_origin: "http://127.0.0.1:8080".to_string(),
            upstream_routes: HashMap::new(),
            tls_cert_path: None,
            tls_key_path: None,
            tls_sni_certs: vec![],
            sqlite_path: "./zero-origin-audit.db".to_string(),
            rate_limit_rpm: 120,
            max_concurrent_connections: default_max_concurrent_connections(),
            header_read_timeout_secs: default_header_read_timeout_secs(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout_secs(),
            upstream_timeout_secs: default_upstream_timeout_secs(),
            http2_keepalive_interval_secs: default_http2_keepalive_interval_secs(),
            http2_keepalive_timeout_secs: default_http2_keepalive_timeout_secs(),
            accept_proxy_protocol: false,
            verify_search_bots_fcrdns: true,
            fcrdns_resolver: None,
            fcrdns_cache_ttl_secs: default_fcrdns_cache_ttl_secs(),
            trusted_proxy_cidrs: vec![],
            blocked_cidrs: vec![],
            blocked_ja4: vec![],
            extra_blocked_user_agents: vec![],
            rights: OriginRightsPolicy::default(),
        }
    }
}

impl ProxyConfig {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)?;
        let parsed: Self = toml::from_str(&raw)?;
        Ok(parsed)
    }

    pub fn resolve_upstream_for_host(&self, host_or_sni: Option<&str>) -> &str {
        if let Some(raw_host) = host_or_sni {
            let host_only = raw_host
                .split(':')
                .next()
                .unwrap_or(raw_host)
                .trim()
                .to_ascii_lowercase();
            if let Some(mapped) = self.upstream_routes.get(&host_only) {
                return mapped.as_str();
            }
        }
        self.upstream_origin.as_str()
    }
}
