// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Deterministic Layer-7 AI Crawler Classification & Rate-Limiting Engine.
//! Evaluates requests in microseconds with bounded memory and zero external network calls.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use zero_origin_ja4::Ja4Fingerprint;

use crate::config::ProxyConfig;
use crate::fcrdns::SearchBotFamily;

/// Known commercial AI training crawlers and unconsented harvesting bot tokens (lowercase).
pub const DEFAULT_AI_CRAWLER_SIGNATURES: &[&str] = &[
    "gptbot",
    "chatgpt-user",
    "oai-searchbot",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "bytespider",
    "ccbot",
    "diffbot",
    "meta-externalagent",
    "meta-externalfetcher",
    "facebookbot",
    "perplexitybot",
    "google-extended",
    "applebot-extended",
    "cohere-ai",
    "amazonbot",
    "imagesiftbot",
    "omgili",
    "omgilibot",
    "scrapy",
    "headlesschrome",
    "phantomjs",
    "bingbot-ai",
    "youbot",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    RejectBadRequest { rule_id: &'static str },
    BlockForbidden { rule_id: String },
    RateLimited { rule_id: &'static str },
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct EdgeClassifier {
    ai_signatures: Vec<String>,
    blocked_ja4: Vec<String>,
    trusted_proxies: Vec<IpNet>,
    blocked_cidrs: Vec<IpNet>,
    rate_limit_rpm: f64,
    allow_search_indexing: bool,
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
}

/// Identifies if a User-Agent claims a recognized traditional search indexer
/// eligible for FCrDNS verification when `allow_search_indexing = true`.
pub fn claimed_search_bot_family(user_agent: Option<&str>) -> Option<SearchBotFamily> {
    let ua = user_agent?.to_ascii_lowercase();
    if ua.contains("googlebot") || ua.contains("google-inspectiontool") {
        Some(SearchBotFamily::Google)
    } else if ua.contains("bingbot") || ua.contains("msnbot") {
        Some(SearchBotFamily::Bing)
    } else if ua.contains("duckduckbot") {
        Some(SearchBotFamily::DuckDuckGo)
    } else if ua.contains("applebot") {
        Some(SearchBotFamily::Apple)
    } else {
        None
    }
}

impl EdgeClassifier {
    pub fn from_config(cfg: &ProxyConfig) -> Self {
        let mut ai_signatures: Vec<String> = DEFAULT_AI_CRAWLER_SIGNATURES
            .iter()
            .map(|s| s.to_string())
            .collect();
        for extra in &cfg.extra_blocked_user_agents {
            let norm = extra.trim().to_ascii_lowercase();
            if !norm.is_empty() {
                ai_signatures.push(norm);
            }
        }

        let trusted_proxies = cfg
            .trusted_proxy_cidrs
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();
        let blocked_cidrs = cfg
            .blocked_cidrs
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();

        let blocked_ja4 = cfg
            .blocked_ja4
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .collect();

        Self {
            ai_signatures,
            blocked_ja4,
            trusted_proxies,
            blocked_cidrs,
            rate_limit_rpm: cfg.rate_limit_rpm.max(1) as f64,
            allow_search_indexing: cfg.rights.allow_search_indexing,
            buckets: Mutex::new(HashMap::with_capacity(1024)),
        }
    }

    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|net| net.contains(&ip))
    }

    /// Resolves effective client IP safely using right-most untrusted hop traversal:
    /// ignores `X-Forwarded-For` unless `peer_ip` originates inside `trusted_proxy_cidrs`,
    /// then walks right-to-left skipping trusted proxies so spoofed client-prepended
    /// addresses cannot bypass CIDR bans or rate limits.
    pub fn resolve_client_ip(&self, peer_ip: IpAddr, xff_header: Option<&str>) -> IpAddr {
        if self.is_trusted_proxy(peer_ip) {
            if let Some(xff) = xff_header {
                for raw_hop in xff.rsplit(',') {
                    if let Ok(parsed) = raw_hop.trim().parse::<IpAddr>() {
                        if !self.is_trusted_proxy(parsed) {
                            return parsed;
                        }
                    }
                }
            }
        }
        peer_ip
    }

    /// Classifies an incoming request before contacting upstream origin storage.
    pub fn classify(
        &self,
        peer_ip: IpAddr,
        xff_header: Option<&str>,
        user_agent: Option<&str>,
        ja4: Option<&Ja4Fingerprint>,
        has_content_length: bool,
        has_transfer_encoding: bool,
    ) -> (IpAddr, Verdict) {
        let client_ip = self.resolve_client_ip(peer_ip, xff_header);

        // 0. Strict HTTP Request Smuggling Defense (RFC 9112 CL+TE ambiguity)
        if has_content_length && has_transfer_encoding {
            return (
                client_ip,
                Verdict::RejectBadRequest {
                    rule_id: "RULE-RFC9112-SMUGGLING-CL-TE",
                },
            );
        }

        // 1. Layer C: Explicit Datacenter / Abusive CIDR Blocklist
        if self.blocked_cidrs.iter().any(|net| net.contains(&client_ip)) {
            return (
                client_ip,
                Verdict::BlockForbidden {
                    rule_id: "RULE-CIDR-BLOCKLIST".to_string(),
                },
            );
        }

        // 2. Layer B: Explicit JA4 TLS Fingerprint Blocklist
        if let Some(fp) = ja4 {
            let ja4_lower = fp.ja4.to_ascii_lowercase();
            if self.blocked_ja4.iter().any(|b| b == &ja4_lower) {
                return (
                    client_ip,
                    Verdict::BlockForbidden {
                        rule_id: format!("RULE-JA4-BLOCK:{}", fp.ja4),
                    },
                );
            }
        }

        // 3. Layer A: Deterministic AI Training Bot User-Agent Signatures
        if let Some(ua) = user_agent {
            let ua_lower = ua.to_ascii_lowercase();
            for sig in &self.ai_signatures {
                if ua_lower.contains(sig) {
                    return (
                        client_ip,
                        Verdict::BlockForbidden {
                            rule_id: format!("RULE-UA-BOT:{}", sig),
                        },
                    );
                }
            }

            // 3b. If search engine indexing is explicitly forbidden, drop search indexers too
            if !self.allow_search_indexing && claimed_search_bot_family(Some(ua)).is_some() {
                return (
                    client_ip,
                    Verdict::BlockForbidden {
                        rule_id: "RULE-SEARCH-INDEX-DISABLED".to_string(),
                    },
                );
            }

            // 4. Cross-Layer Spoof Detection:
            // Claims modern Chrome/Firefox (`Mozilla/5.0 ... Chrome/`) over TLS yet JA4 exhibits
            // zero GREASE and zero ALPN negotiation (hallmark of basic automated TLS bots spoofing UA).
            if let Some(fp) = ja4 {
                let claims_modern_browser = ua_lower.contains("mozilla/5.0")
                    && (ua_lower.contains("chrome/") || ua_lower.contains("safari/"))
                    && !ua_lower.contains("googlebot")
                    && !ua_lower.contains("bingbot");
                if claims_modern_browser && !fp.observed_grease && fp.first_alpn.is_none() {
                    return (
                        client_ip,
                        Verdict::BlockForbidden {
                            rule_id: "RULE-JA4-UA-SPOOF-MISMATCH".to_string(),
                        },
                    );
                }
            }
        }

        // 5. Bounded Per-IP Token-Bucket Rate Limiter
        if !self.consume_token(client_ip) {
            return (
                client_ip,
                Verdict::RateLimited {
                    rule_id: "RULE-RATE-LIMIT-RPM",
                },
            );
        }

        (client_ip, Verdict::Allow)
    }

    fn consume_token(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let refill_per_sec = self.rate_limit_rpm / 60.0;
        let capacity = self.rate_limit_rpm;

        let mut map = match self.buckets.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Bound map size to prevent memory exhaustion under distributed floods
        if map.len() >= 65_536 && !map.contains_key(&ip) {
            let stale_cutoff = Duration::from_secs(120);
            map.retain(|_, b| now.duration_since(b.last_refill) < stale_cutoff);
            if map.len() >= 65_536 {
                map.clear();
            }
        }

        let bucket = map.entry(ip).or_insert_with(|| TokenBucket {
            tokens: capacity,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_blocks_gptbot_claudebot_bytespider() {
        let classifier = EdgeClassifier::from_config(&ProxyConfig::default());
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));

        for bot_ua in [
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "ClaudeBot/1.0; +claudebot@anthropic.com",
            "Mozilla/5.0 (Linux; Android 5.0) Bytespider; spider-feedback@bytedance.com",
            "CCBot/2.0 (https://commoncrawl.org/faq/)",
        ] {
            let (_, verdict) = classifier.classify(peer, None, Some(bot_ua), None, false, false);
            assert!(
                matches!(verdict, Verdict::BlockForbidden { .. }),
                "expected {} to be blocked",
                bot_ua
            );
        }
    }

    #[test]
    fn test_allows_human_visitor_and_prevents_xff_spoof() {
        let mut cfg = ProxyConfig::default();
        cfg.trusted_proxy_cidrs = vec!["10.0.0.0/8".to_string()];
        let classifier = EdgeClassifier::from_config(&cfg);

        // Untrusted public internet peer trying to spoof X-Forwarded-For as 1.1.1.1
        let untrusted_peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        let (resolved, verdict) = classifier.classify(
            untrusted_peer,
            Some("1.1.1.1"),
            Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/126.0"),
            None,
            false,
            false,
        );
        assert_eq!(resolved, untrusted_peer);
        assert_eq!(verdict, Verdict::Allow);

        // Trusted proxy forwarding real IP: right-most untrusted traversal prevents client-prepended spoofing!
        let trusted_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5));
        let (resolved_trusted, _) = classifier.classify(
            trusted_peer,
            Some("1.1.1.1, 198.51.100.42, 10.0.2.9"),
            None,
            None,
            false,
            false,
        );
        assert_eq!(resolved_trusted, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)));
    }

    #[test]
    fn test_rejects_cl_te_smuggling() {
        let classifier = EdgeClassifier::from_config(&ProxyConfig::default());
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let (_, verdict) = classifier.classify(peer, None, None, None, true, true);
        assert_eq!(
            verdict,
            Verdict::RejectBadRequest {
                rule_id: "RULE-RFC9112-SMUGGLING-CL-TE"
            }
        );
    }

    #[test]
    fn test_ja4_ua_spoof_mismatch_caught() {
        let classifier = EdgeClassifier::from_config(&ProxyConfig::default());
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88));
        let bot_fp = Ja4Fingerprint {
            ja4: "t12d040200_aaaaaaaaaaaa_bbbbbbbbbbbb".to_string(),
            ja4_raw: String::new(),
            sni: Some("originzero.art".to_string()),
            first_alpn: None,
            cipher_count: 4,
            extension_count: 2,
            observed_grease: false,
        };
        let (_, verdict) = classifier.classify(
            peer,
            None,
            Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"),
            Some(&bot_fp),
            false,
            false,
        );
        assert_eq!(
            verdict,
            Verdict::BlockForbidden {
                rule_id: "RULE-JA4-UA-SPOOF-MISMATCH".to_string()
            }
        );
    }

    #[test]
    fn test_rate_limiter_enforces_429() {
        let mut cfg = ProxyConfig::default();
        cfg.rate_limit_rpm = 3;
        let classifier = EdgeClassifier::from_config(&cfg);
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));

        for _ in 0..3 {
            let (_, v) = classifier.classify(peer, None, Some("CustomViewer/1.0"), None, false, false);
            assert_eq!(v, Verdict::Allow);
        }
        let (_, over_limit) = classifier.classify(peer, None, Some("CustomViewer/1.0"), None, false, false);
        assert_eq!(
            over_limit,
            Verdict::RateLimited {
                rule_id: "RULE-RATE-LIMIT-RPM"
            }
        );
    }
}
