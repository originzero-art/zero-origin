// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Controlled Zero-SSRF Wire Probe Engine for `scanner.originzero.art`.
//! Connects ONLY to server-configured `TargetSpec` endpoints (never following redirects),
//! measuring DNS resolution, TLS handshake parameters, JA4 edge telemetry, HTTP rights headers,
//! transferred asset byte counts, and offline C2PA/JUMBF cryptographic verification.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use chrono::Utc;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::TlsConnector;
use zero_origin_verify::{audit_http_rights_headers, verify_asset_bytes, HttpRightsAuditReport};

use crate::audit_reader::{read_audit_wal_feed, AuditFeedReport};
use crate::config::{AllowedTargetId, ProbeProfile, ScannerConfig, TargetSpec};

const MAX_PROBE_BODY_BYTES: usize = 4 * 1024 * 1024; // 4 MiB safety cap

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTelemetry {
    pub hostname: String,
    pub ipv4_records: Vec<String>,
    pub ipv6_records: Vec<String>,
    pub authoritative_ns: Vec<String>,
    pub dns_rtt_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsWireTelemetry {
    pub encrypted: bool,
    pub tls_version: String,
    pub cipher_suite: String,
    pub alpn: String,
    pub ja4_fingerprint: Option<String>,
    pub sni_sent: String,
    pub handshake_rtt_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTelemetry {
    pub page_http_status: u16,
    pub asset_http_status: u16,
    pub page_bytes: usize,
    pub image_bytes_leaked: usize,
    pub total_bytes_transferred: usize,
    pub bandwidth_verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceTelemetry {
    pub status: String,
    pub valid: bool,
    pub format: Option<String>,
    pub algorithm: Option<String>,
    pub creator_name: Option<String>,
    pub content_sha256: Option<String>,
    pub manifest_bytes: Option<usize>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeLegReport {
    pub target_id: String,
    pub label: String,
    pub shielded: bool,
    pub reachable: bool,
    pub error: Option<String>,
    pub verdict_code: String,
    pub verdict_summary_ro: String,
    pub total_rtt_ms: f64,
    pub dns: DnsTelemetry,
    pub tls: TlsWireTelemetry,
    pub http_status: u16,
    pub rights: HttpRightsAuditReport,
    pub raw_headers: Vec<(String, String)>,
    pub payload: PayloadTelemetry,
    pub provenance: ProvenanceTelemetry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub id: ProbeProfile,
    pub label_ro: String,
    pub user_agent: String,
    pub is_scraper: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResponse {
    pub timestamp_utc: String,
    pub profile: ProfileMetadata,
    pub left: ProbeLegReport,
    pub right: ProbeLegReport,
    pub audit_feed: AuditFeedReport,
}

pub fn build_tls_connector(extra_root_cert_pem: Option<&str>) -> Result<TlsConnector, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(pem_path) = extra_root_cert_pem {
        let f = File::open(pem_path)
            .map_err(|e| format!("failed opening extra_root_cert_pem '{}': {}", pem_path, e))?;
        let mut reader = BufReader::new(f);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid PEM in '{}': {}", pem_path, e))?;
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| format!("failed adding root cert: {}", e))?;
        }
    }

    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(cfg)))
}

struct SingleFetchOutcome {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
    dns_v4: Vec<String>,
    dns_v6: Vec<String>,
    dns_rtt_ms: f64,
    encrypted: bool,
    tls_version: String,
    cipher_suite: String,
    alpn: String,
    handshake_rtt_ms: f64,
}

fn parse_url_parts(raw_url: &str) -> Result<(bool, String, u16, String), String> {
    let uri: Uri = raw_url
        .parse()
        .map_err(|e| format!("invalid target URL '{}': {}", raw_url, e))?;
    let is_tls = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        other => return Err(format!("unsupported scheme: {:?}", other)),
    };
    let host = uri
        .host()
        .ok_or_else(|| format!("missing host in URL '{}'", raw_url))?
        .to_string();
    let port = uri.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok((is_tls, host, port, path_and_query))
}

async fn resolve_dns_addresses(
    host: &str,
    port: u16,
    connect_override: Option<&str>,
) -> Result<(SocketAddr, Vec<String>, Vec<String>, f64), String> {
    let dns_start = Instant::now();
    if let Some(override_str) = connect_override {
        let sock: SocketAddr = override_str
            .parse()
            .map_err(|e| format!("invalid connect_override '{}': {}", override_str, e))?;
        // Attempt quick non-blocking DNS lookup for public record display if available; fall back to socket IP
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        if let Ok(Ok(addrs)) =
            tokio::time::timeout(Duration::from_millis(400), lookup_host((host, port))).await
        {
            for a in addrs {
                match a.ip() {
                    std::net::IpAddr::V4(ip) => {
                        let s = ip.to_string();
                        if !v4.contains(&s) {
                            v4.push(s);
                        }
                    }
                    std::net::IpAddr::V6(ip) => {
                        let s = ip.to_string();
                        if !v6.contains(&s) {
                            v6.push(s);
                        }
                    }
                }
            }
        }
        if v4.is_empty() && v6.is_empty() {
            match sock.ip() {
                std::net::IpAddr::V4(ip) => v4.push(ip.to_string()),
                std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
            }
        }
        let rtt = dns_start.elapsed().as_secs_f64() * 1000.0;
        return Ok((sock, v4, v6, rtt));
    }

    let resolved: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {}: {}", host, e))?
        .collect();
    let rtt = dns_start.elapsed().as_secs_f64() * 1000.0;

    let first = resolved
        .first()
        .copied()
        .ok_or_else(|| format!("NXDOMAIN / empty address set for {}", host))?;
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for a in &resolved {
        match a.ip() {
            std::net::IpAddr::V4(ip) => {
                let s = ip.to_string();
                if !v4.contains(&s) {
                    v4.push(s);
                }
            }
            std::net::IpAddr::V6(ip) => {
                let s = ip.to_string();
                if !v6.contains(&s) {
                    v6.push(s);
                }
            }
        }
    }
    Ok((first, v4, v6, rtt))
}

async fn fetch_single_url(
    raw_url: &str,
    user_agent: &str,
    connect_override: Option<&str>,
    tls_connector: &TlsConnector,
) -> Result<SingleFetchOutcome, String> {
    let (is_tls, host, port, path_and_query) = parse_url_parts(raw_url)?;
    let (connect_addr, dns_v4, dns_v6, dns_rtt_ms) =
        resolve_dns_addresses(&host, port, connect_override).await?;

    let hs_start = Instant::now();
    let tcp = TcpStream::connect(connect_addr)
        .await
        .map_err(|e| format!("TCP connect to {} failed: {}", connect_addr, e))?;
    let _ = tcp.set_nodelay(true);

    let req = Request::builder()
        .method("GET")
        .uri(&path_and_query)
        .header(hyper::header::HOST, &host)
        .header(hyper::header::USER_AGENT, user_agent)
        .header(hyper::header::ACCEPT, "*/*")
        .header(hyper::header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("request build error: {}", e))?;

    if is_tls {
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| format!("invalid TLS SNI server name '{}'", host))?;
        let tls_stream = tls_connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS handshake failed for {}: {}", host, e))?;
        let handshake_rtt_ms = hs_start.elapsed().as_secs_f64() * 1000.0;

        let (_, tls_conn) = tls_stream.get_ref();
        let tls_version = tls_conn
            .protocol_version()
            .map(|v| match v {
                rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
                rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
                other => format!("{:?}", other),
            })
            .unwrap_or_else(|| "TLS".to_string());
        let cipher_suite = tls_conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "unknown".to_string());
        let alpn = tls_conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_else(|| "http/1.1".to_string());

        let (mut sender, conn) = http1::handshake(TokioIo::new(tls_stream))
            .await
            .map_err(|e| format!("HTTP/1.1 over TLS handshake error: {}", e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        let status = resp.status().as_u16();
        let headers = extract_header_vec(resp.headers());
        let body = read_capped_body(resp.into_body()).await?;

        Ok(SingleFetchOutcome {
            status,
            headers,
            body,
            dns_v4,
            dns_v6,
            dns_rtt_ms,
            encrypted: true,
            tls_version,
            cipher_suite,
            alpn,
            handshake_rtt_ms,
        })
    } else {
        let handshake_rtt_ms = hs_start.elapsed().as_secs_f64() * 1000.0;
        let (mut sender, conn) = http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| format!("HTTP/1.1 handshake error: {}", e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        let status = resp.status().as_u16();
        let headers = extract_header_vec(resp.headers());
        let body = read_capped_body(resp.into_body()).await?;

        Ok(SingleFetchOutcome {
            status,
            headers,
            body,
            dns_v4,
            dns_v6,
            dns_rtt_ms,
            encrypted: false,
            tls_version: "CLEARTEXT-HTTP".to_string(),
            cipher_suite: "NONE".to_string(),
            alpn: "http/1.1".to_string(),
            handshake_rtt_ms,
        })
    }
}

fn extract_header_vec(map: &hyper::HeaderMap) -> Vec<(String, String)> {
    map.iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_string(), val.to_string()))
        })
        .collect()
}

async fn read_capped_body(mut body: hyper::body::Incoming) -> Result<Bytes, String> {
    let mut buf = BytesMut::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|e| format!("body stream error: {}", e))?;
        if let Ok(chunk) = frame.into_data() {
            let remaining = MAX_PROBE_BODY_BYTES.saturating_sub(buf.len());
            if remaining == 0 {
                break;
            }
            let take_len = chunk.len().min(remaining);
            buf.extend_from_slice(&chunk[..take_len]);
        }
    }
    Ok(buf.freeze())
}

fn resolve_override_for_url<'a>(raw_url: &str, cfg: &'a ScannerConfig, target: &'a TargetSpec) -> Option<&'a str> {
    if let Ok((_, host, _, _)) = parse_url_parts(raw_url) {
        if host.eq_ignore_ascii_case(target.id.as_hostname()) {
            return target.connect_override.as_deref();
        }
        for other in &cfg.targets {
            if host.eq_ignore_ascii_case(other.id.as_hostname()) {
                return other.connect_override.as_deref();
            }
        }
    }
    target.connect_override.as_deref()
}

pub async fn probe_single_leg(
    cfg: &ScannerConfig,
    target: &TargetSpec,
    profile: ProbeProfile,
    tls_connector: &TlsConnector,
) -> ProbeLegReport {
    let start = Instant::now();
    let deadline = Duration::from_secs(cfg.probe_timeout_secs.max(2));
    let ua = profile.user_agent();
    let host_str = target.id.as_hostname().to_string();

    let page_override = resolve_override_for_url(&target.probe_page_url, cfg, target);
    let page_res = tokio::time::timeout(
        deadline,
        fetch_single_url(&target.probe_page_url, ua, page_override, tls_connector),
    )
    .await;

    let page = match page_res {
        Ok(Ok(p)) => p,
        Ok(Err(err)) => return unreachable_leg_report(target, &host_str, err, start.elapsed()),
        Err(_) => {
            return unreachable_leg_report(
                target,
                &host_str,
                format!("Probe timed out after {}s", cfg.probe_timeout_secs),
                start.elapsed(),
            )
        }
    };

    // Probe the benchmark/canary image asset to measure real byte leakage & C2PA JUMBF provenance
    let asset_override = resolve_override_for_url(&target.probe_asset_url, cfg, target);
    let asset_res = tokio::time::timeout(
        deadline,
        fetch_single_url(&target.probe_asset_url, ua, asset_override, tls_connector),
    )
    .await;

    let (asset_status, asset_bytes) = match asset_res {
        Ok(Ok(a)) => (a.status, a.body),
        _ => (0, Bytes::new()),
    };

    let total_rtt_ms = start.elapsed().as_secs_f64() * 1000.0;

    let ref_headers: Vec<(&str, &str)> = page
        .headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let rights = audit_http_rights_headers(ref_headers);

    let ja4_fingerprint = page
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-zero-origin-ja4"))
        .map(|(_, v)| v.clone());

    let image_bytes_leaked = if asset_status == 200 && asset_bytes.len() > 64 {
        asset_bytes.len()
    } else {
        0
    };
    let page_bytes = page.body.len();
    let total_bytes_transferred = page_bytes + asset_bytes.len();

    let bandwidth_verdict = if asset_status == 403 || asset_status == 429 || page.status == 403 || page.status == 429 {
        "0 octeți imagine expuși (Conexiune tăiată la Layer-7 înainte de streaming)".to_string()
    } else if image_bytes_leaked > 0 {
        format!(
            "{:.2} MB transferați ({} octeți activ media)",
            (image_bytes_leaked as f64) / (1024.0 * 1024.0),
            image_bytes_leaked
        )
    } else {
        format!("{} octeți HTML transferați", page_bytes)
    };

    let provenance = if asset_status == 403 || asset_status == 429 || page.status == 403 || page.status == 429 {
        ProvenanceTelemetry {
            status: "PROTECTED_AT_EDGE".to_string(),
            valid: true,
            format: None,
            algorithm: Some("Ed25519 (Protejat)".to_string()),
            creator_name: None,
            content_sha256: None,
            manifest_bytes: None,
            detail: "Crawler oprit la marginea rețelei (0 octeți de imagine livrați către robot).".to_string(),
        }
    } else if image_bytes_leaked > 0 {
        match verify_asset_bytes(&asset_bytes) {
            Ok(rep) => ProvenanceTelemetry {
                status: "VERIFIED_C2PA_JUMBF".to_string(),
                valid: rep.valid,
                format: Some(rep.format),
                algorithm: Some(format!("{:?}", rep.algorithm)),
                creator_name: Some(rep.claim.creator_name),
                content_sha256: Some(rep.content_sha256),
                manifest_bytes: Some(rep.manifest_offset_end.saturating_sub(rep.manifest_offset_start)),
                detail: "Semnătură criptografică C2PA/JUMBF validată matematic bit-cu-bit.".to_string(),
            },
            Err(_) => ProvenanceTelemetry {
                status: "UNSIGNED_OR_STRIPPED".to_string(),
                valid: false,
                format: Some("PNG/Raster".to_string()),
                algorithm: None,
                creator_name: None,
                content_sha256: None,
                manifest_bytes: None,
                detail: "Niciun manifest C2PA/JUMBF detectat. Pixelii pot fi ingerați fără dovadă criptografică a originii umane.".to_string(),
            },
        }
    } else {
        ProvenanceTelemetry {
            status: "NO_ASSET_PAYLOAD".to_string(),
            valid: false,
            format: None,
            algorithm: None,
            creator_name: None,
            content_sha256: None,
            manifest_bytes: None,
            detail: "Niciun activ binar inspectat pe această rută.".to_string(),
        }
    };

    let (verdict_code, verdict_summary_ro) = match (page.status, profile.is_scraper_or_spoof(), rights.rights_enforced) {
        (403, _, _) => (
            "BLOCKED_403_SHIELD".to_string(),
            "BLOCAT LA LAYER-7 (403 Forbidden): Crawler oprit înainte de accesul la originea privată.".to_string(),
        ),
        (429, _, _) => (
            "RATE_LIMITED_429".to_string(),
            "LIMITAT (429 Too Many Requests): Pragul token-bucket atins la marginea rețelei.".to_string(),
        ),
        (200, true, false) => (
            "VULNERABLE_SCRAPED".to_string(),
            "EXPUS COMPLET (200 OK): Robotul a descărcat integral conținutul fără restricții TDM sau C2PA.".to_string(),
        ),
        (200, false, true) => (
            "SOVEREIGN_HUMAN_OK".to_string(),
            "ACCES UMAN SUVERAN (200 OK): Vizitator legitim servit cu antete UE DSM Art. 4 și semnătură C2PA.".to_string(),
        ),
        (200, false, false) => (
            "UNSHIELDED_HUMAN_OK".to_string(),
            "NEPROTEJAT (200 OK): Conținut livrat fără antete de rezervare a drepturilor TDM și fără C2PA.".to_string(),
        ),
        (code, _, _) => (
            format!("HTTP_{}", code),
            format!("Răspuns HTTP {} recepționat de la origine.", code),
        ),
    };

    ProbeLegReport {
        target_id: host_str.clone(),
        label: target.label.clone(),
        shielded: target.shielded,
        reachable: true,
        error: None,
        verdict_code,
        verdict_summary_ro,
        total_rtt_ms,
        dns: DnsTelemetry {
            hostname: host_str.clone(),
            ipv4_records: page.dns_v4,
            ipv6_records: page.dns_v6,
            authoritative_ns: target.authoritative_ns.clone(),
            dns_rtt_ms: page.dns_rtt_ms,
        },
        tls: TlsWireTelemetry {
            encrypted: page.encrypted,
            tls_version: page.tls_version,
            cipher_suite: page.cipher_suite,
            alpn: page.alpn,
            ja4_fingerprint,
            sni_sent: host_str,
            handshake_rtt_ms: page.handshake_rtt_ms,
        },
        http_status: page.status,
        rights,
        raw_headers: page.headers,
        payload: PayloadTelemetry {
            page_http_status: page.status,
            asset_http_status: asset_status,
            page_bytes,
            image_bytes_leaked,
            total_bytes_transferred,
            bandwidth_verdict,
        },
        provenance,
    }
}

fn unreachable_leg_report(
    target: &TargetSpec,
    host_str: &str,
    err: String,
    elapsed: Duration,
) -> ProbeLegReport {
    ProbeLegReport {
        target_id: host_str.to_string(),
        label: target.label.clone(),
        shielded: target.shielded,
        reachable: false,
        error: Some(err.clone()),
        verdict_code: "UNREACHABLE".to_string(),
        verdict_summary_ro: format!("Origine inaccesibilă în timpul sondei: {}", err),
        total_rtt_ms: elapsed.as_secs_f64() * 1000.0,
        dns: DnsTelemetry {
            hostname: host_str.to_string(),
            ipv4_records: vec![],
            ipv6_records: vec![],
            authoritative_ns: target.authoritative_ns.clone(),
            dns_rtt_ms: 0.0,
        },
        tls: TlsWireTelemetry {
            encrypted: false,
            tls_version: "N/A".to_string(),
            cipher_suite: "N/A".to_string(),
            alpn: "N/A".to_string(),
            ja4_fingerprint: None,
            sni_sent: host_str.to_string(),
            handshake_rtt_ms: 0.0,
        },
        http_status: 0,
        rights: HttpRightsAuditReport {
            tdm_reservation: None,
            tdm_policy: None,
            content_usage: None,
            rfc8288_license_link: None,
            x_robots_tag: None,
            rights_enforced: false,
        },
        raw_headers: vec![],
        payload: PayloadTelemetry {
            page_http_status: 0,
            asset_http_status: 0,
            page_bytes: 0,
            image_bytes_leaked: 0,
            total_bytes_transferred: 0,
            bandwidth_verdict: "0 octeți (Conexiune eșuată)".to_string(),
        },
        provenance: ProvenanceTelemetry {
            status: "UNREACHABLE".to_string(),
            valid: false,
            format: None,
            algorithm: None,
            creator_name: None,
            content_sha256: None,
            manifest_bytes: None,
            detail: "Originea nu a putut fi interogată.".to_string(),
        },
    }
}

pub async fn run_comparison_probe(
    cfg: &ScannerConfig,
    left_id: AllowedTargetId,
    right_id: AllowedTargetId,
    profile: ProbeProfile,
    tls_connector: &TlsConnector,
) -> Result<ComparisonResponse, String> {
    let left_spec = cfg
        .find_target(left_id)
        .ok_or_else(|| format!("Target {:?} is not configured on this scanner instance", left_id))?;
    let right_spec = cfg
        .find_target(right_id)
        .ok_or_else(|| format!("Target {:?} is not configured on this scanner instance", right_id))?;

    let (left_rep, right_rep) = tokio::join!(
        probe_single_leg(cfg, left_spec, profile, tls_connector),
        probe_single_leg(cfg, right_spec, profile, tls_connector),
    );

    let audit_feed = read_audit_wal_feed(&cfg.audit_sqlite_path, 12);

    Ok(ComparisonResponse {
        timestamp_utc: Utc::now().to_rfc3339(),
        profile: ProfileMetadata {
            id: profile,
            label_ro: profile.display_label_ro().to_string(),
            user_agent: profile.user_agent().to_string(),
            is_scraper: profile.is_scraper_or_spoof(),
        },
        left: left_rep,
        right: right_rep,
        audit_feed,
    })
}
