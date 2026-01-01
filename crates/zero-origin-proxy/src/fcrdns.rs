// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Async Zero-Dependency Forward-Confirmed Reverse DNS (FCrDNS) Search Crawler Verifier.
//! Validates claimed search engine bots (`Googlebot`, `Bingbot`, `DuckDuckBot`, `Applebot`)
//! by executing RFC 1035 UDP PTR lookup + forward DNS confirmation with a bounded TTL cache
//! so scrapers cannot spoof search-crawler User-Agents to bypass edge inspection.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

static DNS_TXID_COUNTER: AtomicU16 = AtomicU16::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchBotFamily {
    Google,
    Bing,
    DuckDuckGo,
    Apple,
}

impl SearchBotFamily {
    /// Strict trailing DNS zone validation against official crawler operator domains.
    pub fn matches_domain(&self, raw_hostname: &str) -> bool {
        let host = raw_hostname.trim_end_matches('.').to_ascii_lowercase();
        let allowed_suffixes: &[&str] = match self {
            SearchBotFamily::Google => &[".googlebot.com", ".google.com"],
            SearchBotFamily::Bing => &[".search.msn.com"],
            SearchBotFamily::DuckDuckGo => &[".duckduckgo.com"],
            SearchBotFamily::Apple => &[".applebot.apple.com"],
        };
        allowed_suffixes.iter().any(|suffix| {
            host.ends_with(suffix) || host == suffix.trim_start_matches('.')
        })
    }
}

struct CachedFcrdns {
    verified: bool,
    expires_at: Instant,
}

pub struct FcrdnsVerifier {
    resolver: SocketAddr,
    positive_ttl: Duration,
    negative_ttl: Duration,
    query_timeout: Duration,
    cache: Mutex<HashMap<IpAddr, CachedFcrdns>>,
}

impl FcrdnsVerifier {
    pub fn new(resolver_override: Option<&str>, cache_ttl_secs: u64) -> Self {
        let resolver = resolver_override
            .and_then(|s| parse_resolver_addr(s))
            .or_else(read_system_resolver)
            .unwrap_or_else(|| "1.1.1.1:53".parse().unwrap());
        let ttl = Duration::from_secs(cache_ttl_secs.max(30));
        Self {
            resolver,
            positive_ttl: ttl,
            negative_ttl: ttl.min(Duration::from_secs(300)),
            query_timeout: Duration::from_millis(1500),
            cache: Mutex::new(HashMap::with_capacity(512)),
        }
    }

    pub async fn verify_search_bot(&self, ip: IpAddr, family: SearchBotFamily) -> bool {
        self.verify_with_forward_lookup(ip, family, system_forward_lookup)
            .await
    }

    pub async fn verify_with_forward_lookup<F, Fut>(
        &self,
        ip: IpAddr,
        family: SearchBotFamily,
        forward_lookup: F,
    ) -> bool
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Vec<IpAddr>>,
    {
        let now = Instant::now();
        {
            let map = match self.cache.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(entry) = map.get(&ip) {
                if now < entry.expires_at {
                    return entry.verified;
                }
            }
        }

        let verified = self.execute_fcrdns(ip, family, forward_lookup).await;
        let ttl = if verified {
            self.positive_ttl
        } else {
            self.negative_ttl
        };

        let mut map = match self.cache.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if map.len() >= 16_384 && !map.contains_key(&ip) {
            map.retain(|_, v| v.expires_at > now);
            if map.len() >= 16_384 {
                map.clear();
            }
        }
        map.insert(
            ip,
            CachedFcrdns {
                verified,
                expires_at: Instant::now() + ttl,
            },
        );
        verified
    }

    async fn execute_fcrdns<F, Fut>(
        &self,
        ip: IpAddr,
        family: SearchBotFamily,
        forward_lookup: F,
    ) -> bool
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Vec<IpAddr>>,
    {
        let qname = to_ptr_qname(ip);
        let ptr_hosts = match tokio::time::timeout(
            self.query_timeout,
            query_ptr_udp(self.resolver, &qname),
        )
        .await
        {
            Ok(Ok(hosts)) => hosts,
            _ => return false,
        };

        for host in ptr_hosts {
            if !family.matches_domain(&host) {
                continue;
            }
            if let Ok(resolved_ips) =
                tokio::time::timeout(self.query_timeout, forward_lookup(host)).await
            {
                if resolved_ips.contains(&ip) {
                    return true;
                }
            }
        }
        false
    }
}

async fn system_forward_lookup(hostname: String) -> Vec<IpAddr> {
    let target = format!("{}:80", hostname.trim_end_matches('.'));
    let res = match tokio::net::lookup_host(target.as_str()).await {
        Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
        Err(_) => Vec::new(),
    };
    res
}

fn parse_resolver_addr(raw: &str) -> Option<SocketAddr> {
    if let Ok(sa) = raw.trim().parse::<SocketAddr>() {
        return Some(sa);
    }
    raw.trim()
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 53))
}

fn read_system_resolver() -> Option<SocketAddr> {
    let content = fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let token = rest.split_whitespace().next()?;
            if let Ok(ip) = token.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, 53));
            }
        }
    }
    None
}

pub fn to_ptr_qname(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut labels = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                labels.push_str(&format!("{:x}.{:x}.", b & 0x0f, (b >> 4) & 0x0f));
            }
            labels.push_str("ip6.arpa");
            labels
        }
    }
}

pub fn build_ptr_query(txid: u16, qname: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Standard query, Recursion Desired
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in qname.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        pkt.push(len as u8);
        pkt.extend_from_slice(&bytes[..len]);
    }
    pkt.push(0x00); // Root label
    pkt.extend_from_slice(&12u16.to_be_bytes()); // QTYPE = PTR (12)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN (1)
    pkt
}

/// Bounds-checked RFC 1035 domain name decoder with compression-pointer cycle guard.
fn decode_dns_name(pkt: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end_after_first = None;
    let mut jumps = 0u8;

    loop {
        let len_byte = *pkt.get(pos)?;
        if (len_byte & 0xc0) == 0xc0 {
            let ptr_lo = *pkt.get(pos + 1)?;
            let offset = (((len_byte & 0x3f) as usize) << 8) | (ptr_lo as usize);
            if end_after_first.is_none() {
                end_after_first = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 || offset >= pkt.len() {
                return None;
            }
            pos = offset;
            continue;
        }
        if (len_byte & 0xc0) != 0 {
            return None;
        }
        let len = len_byte as usize;
        pos += 1;
        if len == 0 {
            let final_end = end_after_first.unwrap_or(pos);
            return Some((labels.join("."), final_end));
        }
        let slice = pkt.get(pos..pos + len)?;
        labels.push(std::str::from_utf8(slice).ok()?.to_string());
        pos += len;
    }
}

pub fn parse_ptr_response(pkt: &[u8], expected_txid: u16) -> Option<Vec<String>> {
    if pkt.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([pkt[0], pkt[1]]);
    if txid != expected_txid {
        return None;
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Some(Vec::new());
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (_, next_pos) = decode_dns_name(pkt, pos)?;
        pos = next_pos + 4; // QTYPE(2) + QCLASS(2)
        if pos > pkt.len() {
            return None;
        }
    }

    let mut results = Vec::new();
    for _ in 0..ancount {
        let (_, next_pos) = decode_dns_name(pkt, pos)?;
        pos = next_pos;
        if pos + 10 > pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rdlength = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > pkt.len() {
            return None;
        }
        if rtype == 12 {
            // PTR record
            if let Some((ptr_host, _)) = decode_dns_name(pkt, pos) {
                results.push(ptr_host);
            }
        }
        pos += rdlength;
    }

    Some(results)
}

async fn query_ptr_udp(resolver: SocketAddr, qname: &str) -> Result<Vec<String>, std::io::Error> {
    let bind_addr = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(resolver).await?;

    let seq = DNS_TXID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x5a5a);
    let txid = seq ^ nanos;
    let query = build_ptr_query(txid, qname);
    sock.send(&query).await?;

    let mut resp = [0u8; 1024];
    let n = sock.recv(&mut resp).await?;
    Ok(parse_ptr_response(&resp[..n], txid).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ptr_qname_v4_and_v6() {
        let v4 = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        assert_eq!(to_ptr_qname(v4), "1.66.249.66.in-addr.arpa");

        let v6: IpAddr = "2001:4860:4801:10::1".parse().unwrap();
        assert!(to_ptr_qname(v6).ends_with(".ip6.arpa"));
        assert!(to_ptr_qname(v6).starts_with("1.0.0.0."));
    }

    #[test]
    fn test_strict_bot_domain_suffix_matching() {
        assert!(SearchBotFamily::Google.matches_domain("crawl-66-249-66-1.googlebot.com."));
        assert!(SearchBotFamily::Google.matches_domain("rate-limited-proxy-66-249-90-77.google.com"));
        assert!(!SearchBotFamily::Google.matches_domain("crawl.evilgooglebot.com"));
        assert!(SearchBotFamily::Bing.matches_domain("msnbot-157-55-39-1.search.msn.com"));
        assert!(!SearchBotFamily::Bing.matches_domain("fake.msn.com"));
        assert!(SearchBotFamily::Apple.matches_domain("17-58-100-1.applebot.apple.com"));
    }

    async fn spawn_mock_ptr_dns(ptr_hostname: &'static str) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if n >= 12 {
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&buf[0..2]); // txid
                    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // standard response, NOERROR
                    resp.extend_from_slice(&buf[4..6]); // QDCOUNT
                    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
                    resp.extend_from_slice(&0u32.to_be_bytes()); // NS + AR
                    // Copy Question section verbatim
                    resp.extend_from_slice(&buf[12..n]);
                    // Answer NAME = pointer 0xC00C
                    resp.extend_from_slice(&[0xc0, 0x0c]);
                    resp.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
                    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
                    let mut rdata = Vec::new();
                    for lbl in ptr_hostname.split('.') {
                        rdata.push(lbl.len() as u8);
                        rdata.extend_from_slice(lbl.as_bytes());
                    }
                    rdata.push(0);
                    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                    resp.extend_from_slice(&rdata);
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_fcrdns_authentic_vs_spoofed_googlebot() {
        let google_ip: IpAddr = "66.249.66.1".parse().unwrap();
        let mock_dns_ok = spawn_mock_ptr_dns("crawl-66-249-66-1.googlebot.com").await;
        let verifier = FcrdnsVerifier::new(Some(&mock_dns_ok.to_string()), 60);

        let verified = verifier
            .verify_with_forward_lookup(google_ip, SearchBotFamily::Google, |_host| async move {
                vec!["66.249.66.1".parse().unwrap()]
            })
            .await;
        assert!(verified, "authentic Googlebot PTR + forward A match must verify");

        // Attacker with fake PTR domain or mismatched forward A lookup
        let attacker_ip: IpAddr = "203.0.113.55".parse().unwrap();
        let mock_dns_spoof = spawn_mock_ptr_dns("vps-203.attacker.example").await;
        let verifier_spoof = FcrdnsVerifier::new(Some(&mock_dns_spoof.to_string()), 60);
        let rejected = verifier_spoof
            .verify_with_forward_lookup(attacker_ip, SearchBotFamily::Google, |_host| async move {
                vec!["203.0.113.55".parse().unwrap()]
            })
            .await;
        assert!(!rejected, "spoofed PTR outside .googlebot.com must fail");
    }
}
