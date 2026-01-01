// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Zero-SSRF Configuration & Closed Target Enumerations for `scanner.originzero.art`.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerConfigError {
    #[error("failed reading scanner config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid scanner TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("configuration invariant violation: {0}")]
    Validation(String),
}

/// Strictly enumerated target IDs permitted by the scanner backend.
/// Arbitrary user-supplied URLs, IPs, ports, or schemes are mathematically unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AllowedTargetId {
    #[serde(rename = "unsafe.originzero.art")]
    UnsafeOriginZero,
    #[serde(rename = "originzero.art")]
    OriginZero,
    #[serde(rename = "757.originzero.art")]
    Artist757,
    #[serde(rename = "spartan.originzero.art")]
    ArtistSpartan,
    #[serde(rename = "crimadezignz.originzero.art")]
    ArtistCrimaDezignz,
}

impl AllowedTargetId {
    pub fn as_hostname(&self) -> &'static str {
        match self {
            Self::UnsafeOriginZero => "unsafe.originzero.art",
            Self::OriginZero => "originzero.art",
            Self::Artist757 => "757.originzero.art",
            Self::ArtistSpartan => "spartan.originzero.art",
            Self::ArtistCrimaDezignz => "crimadezignz.originzero.art",
        }
    }

    pub fn parse_strict(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "unsafe.originzero.art" => Ok(Self::UnsafeOriginZero),
            "originzero.art" => Ok(Self::OriginZero),
            "757.originzero.art" => Ok(Self::Artist757),
            "spartan.originzero.art" => Ok(Self::ArtistSpartan),
            "crimadezignz.originzero.art" => Ok(Self::ArtistCrimaDezignz),
            other => Err(format!(
                "Target '{}' rejected by Zero-SSRF allowlist guard. Permitted IDs: unsafe.originzero.art, originzero.art, 757.originzero.art, spartan.originzero.art, crimadezignz.originzero.art",
                other.chars().take(64).collect::<String>()
            )),
        }
    }
}

/// Enumerated visitor / scraper personas for deterministic wire comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeProfile {
    #[serde(rename = "human")]
    HumanCollector,
    #[serde(rename = "gptbot")]
    GptBot,
    #[serde(rename = "ccbot")]
    CcBot,
    #[serde(rename = "claudebot")]
    ClaudeBot,
    #[serde(rename = "bytespider")]
    Bytespider,
    #[serde(rename = "spoofed_googlebot")]
    SpoofedGooglebot,
}

impl ProbeProfile {
    pub fn parse_strict(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "human" => Ok(Self::HumanCollector),
            "gptbot" => Ok(Self::GptBot),
            "ccbot" => Ok(Self::CcBot),
            "claudebot" => Ok(Self::ClaudeBot),
            "bytespider" => Ok(Self::Bytespider),
            "spoofed_googlebot" => Ok(Self::SpoofedGooglebot),
            other => Err(format!(
                "Unknown probe profile '{}'. Allowed: human, gptbot, ccbot, claudebot, bytespider, spoofed_googlebot",
                other.chars().take(48).collect::<String>()
            )),
        }
    }

    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::HumanCollector => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
            }
            Self::GptBot => {
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"
            }
            Self::CcBot => "CCBot/2.0 (https://commoncrawl.org/faq/)",
            Self::ClaudeBot => {
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
            }
            Self::Bytespider => {
                "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)"
            }
            Self::SpoofedGooglebot => {
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            }
        }
    }

    pub fn display_label_ro(&self) -> &'static str {
        match self {
            Self::HumanCollector => "Vizitator Uman / Colecționar (Browser Standard)",
            Self::GptBot => "Crawler Automat: OpenAI GPTBot/1.2",
            Self::CcBot => "Crawler Automat: CommonCrawl CCBot/2.0",
            Self::ClaudeBot => "Crawler Automat: Anthropic ClaudeBot/1.0",
            Self::Bytespider => "Crawler Automat: ByteDance Bytespider",
            Self::SpoofedGooglebot => "Bot Falsificat: Googlebot Fără FCrDNS Valid",
        }
    }

    pub fn is_scraper_or_spoof(&self) -> bool {
        !matches!(self, Self::HumanCollector)
    }
}

fn default_ns() -> Vec<String> {
    vec![
        "ns1.example.net.".to_string(),
        "ns2.example.net.".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub id: AllowedTargetId,
    pub label: String,
    pub shielded: bool,
    pub probe_page_url: String,
    pub probe_asset_url: String,
    /// Server-side socket override for pre-cutover loopback TLS verification ONLY
    #[serde(default)]
    pub connect_override: Option<String>,
    #[serde(default = "default_ns")]
    pub authoritative_ns: Vec<String>,
}

fn default_rate_limit_rpm() -> u32 {
    30
}
fn default_probe_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub listen_addr: String,
    pub audit_sqlite_path: String,
    #[serde(default = "default_rate_limit_rpm")]
    pub rate_limit_rpm: u32,
    #[serde(default = "default_probe_timeout_secs")]
    pub probe_timeout_secs: u64,
    /// Optional static web root directory
    #[serde(default)]
    pub web_root: Option<String>,
    /// Optional local test root certificate PEM path for pre-cutover Triad TLS verification
    #[serde(default)]
    pub extra_root_cert_pem: Option<String>,
    pub targets: Vec<TargetSpec>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8082".to_string(),
            audit_sqlite_path: "./zero-origin-audit.db".to_string(),
            rate_limit_rpm: default_rate_limit_rpm(),
            probe_timeout_secs: default_probe_timeout_secs(),
            web_root: None,
            extra_root_cert_pem: None,
            targets: vec![
                TargetSpec {
                    id: AllowedTargetId::UnsafeOriginZero,
                    label: "unsafe.originzero.art (Control Fără Scut)".to_string(),
                    shielded: false,
                    probe_page_url: "https://unsafe.originzero.art/".to_string(),
                    probe_asset_url: "https://unsafe.originzero.art/canary/benchmark-origin-00.png".to_string(),
                    connect_override: None,
                    authoritative_ns: default_ns(),
                },
                TargetSpec {
                    id: AllowedTargetId::OriginZero,
                    label: "originZero.Art (Sub Scutul zero-origin)".to_string(),
                    shielded: true,
                    probe_page_url: "https://originzero.art/".to_string(),
                    probe_asset_url: "https://originzero.art/canary/benchmark-origin-00.png".to_string(),
                    connect_override: None,
                    authoritative_ns: default_ns(),
                },
                TargetSpec {
                    id: AllowedTargetId::Artist757,
                    label: "757.originZero.Art (Portofoliu Creator)".to_string(),
                    shielded: true,
                    probe_page_url: "https://757.originzero.art/".to_string(),
                    probe_asset_url: "https://originzero.art/canary/benchmark-origin-00.png".to_string(),
                    connect_override: None,
                    authoritative_ns: default_ns(),
                },
                TargetSpec {
                    id: AllowedTargetId::ArtistSpartan,
                    label: "spartan.originZero.Art (Portofoliu Creator)".to_string(),
                    shielded: true,
                    probe_page_url: "https://spartan.originzero.art/".to_string(),
                    probe_asset_url: "https://originzero.art/canary/benchmark-origin-00.png".to_string(),
                    connect_override: None,
                    authoritative_ns: default_ns(),
                },
                TargetSpec {
                    id: AllowedTargetId::ArtistCrimaDezignz,
                    label: "crimadezignz.originZero.Art (Portofoliu Creator)".to_string(),
                    shielded: true,
                    probe_page_url: "https://crimadezignz.originzero.art/".to_string(),
                    probe_asset_url: "https://originzero.art/canary/benchmark-origin-00.png".to_string(),
                    connect_override: None,
                    authoritative_ns: default_ns(),
                },
            ],
        }
    }
}

impl ScannerConfig {
    pub fn from_file(path: &Path) -> Result<Self, ScannerConfigError> {
        let raw = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        if self.targets.is_empty() {
            return Err(ScannerConfigError::Validation(
                "scanner targets allowlist must not be empty".to_string(),
            ));
        }
        for t in &self.targets {
            for u in [&t.probe_page_url, &t.probe_asset_url] {
                if !u.starts_with("https://") && !u.starts_with("http://") {
                    return Err(ScannerConfigError::Validation(format!(
                        "invalid URL scheme in target {:?}: {}",
                        t.id, u
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn find_target(&self, id: AllowedTargetId) -> Option<&TargetSpec> {
        self.targets.iter().find(|t| t.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_guard_rejects_arbitrary_urls_and_internal_ips() {
        let hostile_inputs = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22",
            "127.0.0.1",
            "localhost",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "https://evil.example.com",
            "originzero.art@127.0.0.1",
            "originzero.art:8080",
        ];
        for input in hostile_inputs {
            assert!(
                AllowedTargetId::parse_strict(input).is_err(),
                "SSRF guard MUST reject hostile target: {}",
                input
            );
        }
        assert_eq!(
            AllowedTargetId::parse_strict("originzero.art").unwrap(),
            AllowedTargetId::OriginZero
        );
        assert_eq!(
            AllowedTargetId::parse_strict("unsafe.originzero.art").unwrap(),
            AllowedTargetId::UnsafeOriginZero
        );
    }
}
