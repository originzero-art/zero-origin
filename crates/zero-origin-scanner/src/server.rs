// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Loopback HTTP Server for `scanner.originzero.art` & Minimal Static Origin Helper.
//! Enforces Zero-SSRF target validation, Fetch Metadata cross-site rejection,
//! strict CSP (zero `'unsafe-inline'`), and per-IP token-bucket rate limiting.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

use crate::audit_reader::read_audit_wal_feed;
use crate::config::{AllowedTargetId, ProbeProfile, ScannerConfig};
use crate::probe::{build_tls_connector, run_comparison_probe};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const INDEX_HTML: &str = include_str!("../web/index.html");
const ACADEMY_HTML: &str = include_str!("../web/academy.html");
const SCANNER_CSS: &str = include_str!("../web/scanner.css");
const COMPARATOR_JS: &str = include_str!("../web/comparator.js");
const ACADEMY_JS: &str = include_str!("../web/academy.js");

const MAX_JSON_REQ_BYTES: usize = 2048;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    rpm: u32,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(rpm: u32) -> Self {
        Self {
            rpm: rpm.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let cap = self.rpm as f64;
        let refill_per_sec = cap / 60.0;
        let now = Instant::now();
        let mut map = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if map.len() > 4096 {
            map.retain(|_, b| now.duration_since(b.last_refill) < Duration::from_secs(120));
        }
        let entry = map.entry(ip).or_insert(Bucket {
            tokens: cap,
            last_refill: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * refill_per_sec).min(cap);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct ScannerAppState {
    pub config: ScannerConfig,
    pub tls_connector: TlsConnector,
    pub limiter: RateLimiter,
}

impl ScannerAppState {
    pub fn new(config: ScannerConfig) -> Result<Arc<Self>, BoxError> {
        config.validate()?;
        let tls_connector = build_tls_connector(config.extra_root_cert_pem.as_deref())?;
        let limiter = RateLimiter::new(config.rate_limit_rpm);
        Ok(Arc::new(Self {
            config,
            tls_connector,
            limiter,
        }))
    }
}

#[derive(Deserialize)]
struct RawProbeRequest {
    left_target: String,
    right_target: String,
    profile: String,
}

fn attach_scanner_security_headers(headers: &mut hyper::HeaderMap) {
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(
        "vary",
        HeaderValue::from_static("Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site"),
    );
}

fn build_response(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(body.into()));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    attach_scanner_security_headers(resp.headers_mut());
    resp
}

fn extract_effective_client_ip(req: &Request<hyper::body::Incoming>, peer_addr: SocketAddr) -> IpAddr {
    // Only trust X-Forwarded-For when scanner is bound behind local loopback zero-origin
    if peer_addr.ip().is_loopback() {
        if let Some(xff) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(right_most) = xff.split(',').next_back() {
                if let Ok(ip) = right_most.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    peer_addr.ip()
}

fn violates_fetch_metadata(req: &Request<hyper::body::Incoming>) -> bool {
    // Reject cross-site and cross-subdomain (same-site) non-navigational fetches so even
    // unshielded sibling subdomains (e.g. unsafe.originzero.art) cannot invoke scanner APIs.
    if let Some(site) = req.headers().get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !matches!(site, "same-origin" | "none") {
            return true;
        }
    }
    false
}

fn load_web_asset(web_root: Option<&str>, rel_file: &str, fallback: &'static str) -> Bytes {
    if let Some(root) = web_root {
        let candidate = Path::new(root).join(rel_file);
        if let Ok(bytes) = fs::read(&candidate) {
            return Bytes::from(bytes);
        }
    }
    Bytes::from_static(fallback.as_bytes())
}

pub async fn handle_scanner_request(
    req: Request<hyper::body::Incoming>,
    peer_addr: SocketAddr,
    state: Arc<ScannerAppState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let client_ip = extract_effective_client_ip(&req, peer_addr);
    let web_root = state.config.web_root.as_deref();

    match (&method, path.as_str()) {
        (&Method::GET, "/") | (&Method::HEAD, "/") => Ok(build_response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            load_web_asset(web_root, "index.html", INDEX_HTML),
        )),
        (&Method::GET, "/cum-functioneaza-internetul")
        | (&Method::GET, "/cum-functioneaza-internetul/")
        | (&Method::GET, "/internet")
        | (&Method::GET, "/internet/")
        | (&Method::HEAD, "/cum-functioneaza-internetul")
        | (&Method::HEAD, "/internet") => Ok(build_response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            load_web_asset(web_root, "academy.html", ACADEMY_HTML),
        )),
        (&Method::GET, "/assets/scanner.css") => Ok(build_response(
            StatusCode::OK,
            "text/css; charset=utf-8",
            load_web_asset(web_root, "assets/scanner.css", SCANNER_CSS),
        )),
        (&Method::GET, "/assets/comparator.js") => Ok(build_response(
            StatusCode::OK,
            "application/javascript; charset=utf-8",
            load_web_asset(web_root, "assets/comparator.js", COMPARATOR_JS),
        )),
        (&Method::GET, "/assets/academy.js") => Ok(build_response(
            StatusCode::OK,
            "application/javascript; charset=utf-8",
            load_web_asset(web_root, "assets/academy.js", ACADEMY_JS),
        )),
        (&Method::GET, "/favicon.svg") => {
            if let Some(root) = web_root {
                if let Ok(bytes) = fs::read(Path::new(root).join("favicon.svg")) {
                    return Ok(build_response(StatusCode::OK, "image/svg+xml", bytes));
                }
            }
            Ok(build_response(StatusCode::NOT_FOUND, "text/plain; charset=utf-8", "Not Found"))
        }
        (&Method::GET, "/robots.txt") => {
            let body = load_web_asset(
                web_root,
                "robots.txt",
                "User-agent: *\nAllow: /\nDisallow: /api/\n",
            );
            Ok(build_response(StatusCode::OK, "text/plain; charset=utf-8", body))
        }
        (&Method::GET, "/sitemap.xml") => {
            if let Some(root) = web_root {
                if let Ok(bytes) = fs::read(Path::new(root).join("sitemap.xml")) {
                    return Ok(build_response(StatusCode::OK, "application/xml; charset=utf-8", bytes));
                }
            }
            Ok(build_response(StatusCode::NOT_FOUND, "text/plain; charset=utf-8", "Not Found"))
        }
        (&Method::GET, "/api/v1/targets") => {
            if violates_fetch_metadata(&req) {
                return Ok(build_response(
                    StatusCode::FORBIDDEN,
                    "application/json; charset=utf-8",
                    r#"{"error":"CROSS_SITE_FETCH_REJECTED"}"#,
                ));
            }
            let summary: Vec<_> = state
                .config
                .targets
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "id": t.id.as_hostname(),
                        "label": t.label,
                        "shielded": t.shielded,
                    })
                })
                .collect();
            let body = serde_json::to_string(&summary).unwrap_or_else(|_| "[]".to_string());
            Ok(build_response(StatusCode::OK, "application/json; charset=utf-8", body))
        }
        (&Method::GET, "/api/v1/audit-feed") => {
            if violates_fetch_metadata(&req) {
                return Ok(build_response(
                    StatusCode::FORBIDDEN,
                    "application/json; charset=utf-8",
                    r#"{"error":"CROSS_SITE_FETCH_REJECTED"}"#,
                ));
            }
            let feed = read_audit_wal_feed(&state.config.audit_sqlite_path, 15);
            let body = serde_json::to_string(&feed).unwrap_or_else(|_| "{}".to_string());
            Ok(build_response(StatusCode::OK, "application/json; charset=utf-8", body))
        }
        (&Method::POST, "/api/v1/probe") => {
            if violates_fetch_metadata(&req) {
                return Ok(build_response(
                    StatusCode::FORBIDDEN,
                    "application/json; charset=utf-8",
                    r#"{"error":"CROSS_SITE_FETCH_REJECTED","message":"Cross-site POST requests are blocked by Fetch Metadata isolation."}"#,
                ));
            }
            if !state.limiter.allow(client_ip) {
                let mut resp = build_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "application/json; charset=utf-8",
                    r#"{"error":"RATE_LIMITED_429","message":"Prea multe interogări pe minut. Reîncearcă peste 60 de secunde."}"#,
                );
                resp.headers_mut()
                    .insert(hyper::header::RETRY_AFTER, HeaderValue::from_static("60"));
                return Ok(resp);
            }

            // Read bounded request payload (max 2048 bytes)
            let mut buf = BytesMut::new();
            let mut body_stream = req.into_body();
            while let Some(frame_res) = body_stream.frame().await {
                match frame_res {
                    Ok(frame) => {
                        if let Ok(chunk) = frame.into_data() {
                            if buf.len() + chunk.len() > MAX_JSON_REQ_BYTES {
                                return Ok(build_response(
                                    StatusCode::PAYLOAD_TOO_LARGE,
                                    "application/json; charset=utf-8",
                                    r#"{"error":"PAYLOAD_TOO_LARGE","message":"Request body exceeds 2048-byte limit."}"#,
                                ));
                            }
                            buf.extend_from_slice(&chunk);
                        }
                    }
                    Err(_) => {
                        return Ok(build_response(
                            StatusCode::BAD_REQUEST,
                            "application/json; charset=utf-8",
                            r#"{"error":"INVALID_BODY"}"#,
                        ));
                    }
                }
            }

            let parsed: RawProbeRequest = match serde_json::from_slice(&buf) {
                Ok(p) => p,
                Err(_) => {
                    return Ok(build_response(
                        StatusCode::BAD_REQUEST,
                        "application/json; charset=utf-8",
                        r#"{"error":"INVALID_JSON","message":"Expected JSON object with left_target, right_target, and profile."}"#,
                    ));
                }
            };

            let left_id = match AllowedTargetId::parse_strict(&parsed.left_target) {
                Ok(id) => id,
                Err(msg) => {
                    let out = serde_json::json!({
                        "error": "SSRF_GUARD_REJECTED",
                        "field": "left_target",
                        "message": msg,
                    });
                    return Ok(build_response(
                        StatusCode::BAD_REQUEST,
                        "application/json; charset=utf-8",
                        out.to_string(),
                    ));
                }
            };

            let right_id = match AllowedTargetId::parse_strict(&parsed.right_target) {
                Ok(id) => id,
                Err(msg) => {
                    let out = serde_json::json!({
                        "error": "SSRF_GUARD_REJECTED",
                        "field": "right_target",
                        "message": msg,
                    });
                    return Ok(build_response(
                        StatusCode::BAD_REQUEST,
                        "application/json; charset=utf-8",
                        out.to_string(),
                    ));
                }
            };

            let profile = match ProbeProfile::parse_strict(&parsed.profile) {
                Ok(p) => p,
                Err(msg) => {
                    let out = serde_json::json!({
                        "error": "INVALID_PROFILE",
                        "field": "profile",
                        "message": msg,
                    });
                    return Ok(build_response(
                        StatusCode::BAD_REQUEST,
                        "application/json; charset=utf-8",
                        out.to_string(),
                    ));
                }
            };

            match run_comparison_probe(&state.config, left_id, right_id, profile, &state.tls_connector).await {
                Ok(report) => {
                    let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                    Ok(build_response(StatusCode::OK, "application/json; charset=utf-8", json))
                }
                Err(e) => {
                    let out = serde_json::json!({
                        "error": "PROBE_ERROR",
                        "message": e,
                    });
                    Ok(build_response(
                        StatusCode::BAD_GATEWAY,
                        "application/json; charset=utf-8",
                        out.to_string(),
                    ))
                }
            }
        }
        _ => Ok(build_response(
            StatusCode::NOT_FOUND,
            "application/json; charset=utf-8",
            r#"{"error":"NOT_FOUND"}"#,
        )),
    }
}

pub async fn run_scanner_server(state: Arc<ScannerAppState>) -> Result<(), BoxError> {
    let listener = TcpListener::bind(&state.config.listen_addr).await?;
    let graceful = GracefulShutdown::new();
    info!(
        "scanner.originzero.art server listening on {} (audit_db={}, rate_limit={} rpm)",
        state.config.listen_addr, state.config.audit_sqlite_path, state.config.rate_limit_rpm
    );

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("scanner TCP accept error: {}", e);
                        continue;
                    }
                };
                let st = Arc::clone(&state);
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(10));
                    let svc = service_fn(move |req| {
                        handle_scanner_request(req, peer, Arc::clone(&st))
                    });
                    let _ = watcher.watch(builder.serve_connection(TokioIo::new(stream), svc)).await;
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("scanner server shutting down...");
                break;
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), graceful.shutdown()).await;
    Ok(())
}

// ============================================================================
// MINIMAL STATIC ORIGIN HELPER (FOR LOOPBACK / UNSHIELDED CONTROL E2E TESTING)
// ============================================================================

fn safe_resolve_static_path(root: &Path, uri_path: &str) -> Option<PathBuf> {
    let clean = uri_path.trim_start_matches('/');
    let rel = if clean.is_empty() {
        PathBuf::from("index.html")
    } else if clean == "commons" || clean == "commons/" {
        PathBuf::from("commons.html")
    } else {
        PathBuf::from(clean)
    };

    let mut candidate = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(part) => candidate.push(part),
            _ => return None,
        }
    }
    if candidate.is_dir() {
        candidate.push("index.html");
    }
    Some(candidate)
}

fn mime_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn build_static_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, BoxError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let mut key_reader = BufReader::new(File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing TLS key"))?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

pub async fn run_static_origin_server(
    listen_addr: &str,
    root_dir: PathBuf,
    tls_cert_key: Option<(String, String)>,
    unshielded_control_banner_header: bool,
) -> Result<(), BoxError> {
    let tls_acceptor = match tls_cert_key {
        Some((c, k)) => Some(build_static_tls_acceptor(&c, &k)?),
        None => None,
    };
    let listener = TcpListener::bind(listen_addr).await?;
    let root = Arc::new(root_dir);
    info!(
        "static-origin listening on {} (root={}, tls={})",
        listen_addr,
        root.display(),
        tls_acceptor.is_some()
    );

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, _) = match res {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let root_clone = Arc::clone(&root);
                let acc = tls_acceptor.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let r = Arc::clone(&root_clone);
                        async move {
                            let target = safe_resolve_static_path(&r, req.uri().path());
                            let mut resp = match target.and_then(|p| fs::read(&p).ok().map(|b| (p, b))) {
                                Some((p, bytes)) => {
                                    let mut r = Response::new(Full::new(Bytes::from(bytes)));
                                    *r.status_mut() = StatusCode::OK;
                                    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(mime_for_path(&p)));
                                    r
                                }
                                None => {
                                    let mut r = Response::new(Full::new(Bytes::from_static(b"404 Not Found\n")));
                                    *r.status_mut() = StatusCode::NOT_FOUND;
                                    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
                                    r
                                }
                            };
                            resp.headers_mut().insert("x-content-type-options", HeaderValue::from_static("nosniff"));
                            if unshielded_control_banner_header {
                                resp.headers_mut().insert("x-origin-control-role", HeaderValue::from_static("unshielded-baseline"));
                            }
                            Ok::<_, Infallible>(resp)
                        }
                    });

                    let builder = AutoConnBuilder::new(TokioExecutor::new());
                    if let Some(acceptor) = acc {
                        if let Ok(tls_stream) = acceptor.accept(stream).await {
                            let _ = builder.serve_connection(TokioIo::new(tls_stream), svc).await;
                        }
                    } else {
                        let _ = builder.serve_connection(TokioIo::new(stream), svc).await;
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[tokio::test]
    async fn test_probe_endpoint_blocks_ssrf_and_cross_site_fetch() {
        let mut cfg = ScannerConfig::default();
        cfg.rate_limit_rpm = 2;
        let state = ScannerAppState::new(cfg).unwrap();
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 54321));

        // 1. Cross-site POST rejected by Fetch Metadata before touching rate limiter or sockets
        let cross_req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/probe")
            .header("sec-fetch-site", "cross-site")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        // Convert Full<Bytes> via local loopback test server to get hyper::body::Incoming
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st_srv = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let s = Arc::clone(&st_srv);
                    tokio::spawn(async move {
                        let svc = service_fn(move |r| handle_scanner_request(r, peer, Arc::clone(&s)));
                        let _ = AutoConnBuilder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }
        });

        let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
            hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

        let (parts, body) = cross_req.into_parts();
        let mut uri_parts = parts;
        uri_parts.uri = format!("http://{}/api/v1/probe", addr).parse().unwrap();
        let res_cross = client.request(Request::from_parts(uri_parts, body)).await.unwrap();
        assert_eq!(res_cross.status(), StatusCode::FORBIDDEN);

        // 2. Cloud link-local metadata SSRF payload -> 400 Bad Request (SSRF_GUARD_REJECTED)
        let ssrf_req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}/api/v1/probe", addr))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(
                br#"{"left_target":"http://169.254.169.254/latest/meta-data/","right_target":"originzero.art","profile":"gptbot"}"#,
            )))
            .unwrap();
        let res_ssrf = client.request(ssrf_req).await.unwrap();
        assert_eq!(res_ssrf.status(), StatusCode::BAD_REQUEST);
        let body_bytes = res_ssrf.collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body_bytes).contains("SSRF_GUARD_REJECTED"));

        // 3. Loopback SSH SSRF -> 400 Bad Request
        let ssh_req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}/api/v1/probe", addr))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(
                br#"{"left_target":"unsafe.originzero.art","right_target":"127.0.0.1:22","profile":"human"}"#,
            )))
            .unwrap();
        let res_ssh = client.request(ssh_req).await.unwrap();
        assert_eq!(res_ssh.status(), StatusCode::BAD_REQUEST);

        // 4. Third request exceeds 2 rpm token bucket -> 429 Too Many Requests
        let third_req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}/api/v1/probe", addr))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(
                br#"{"left_target":"unsafe.originzero.art","right_target":"originzero.art","profile":"gptbot"}"#,
            )))
            .unwrap();
        let res_rate = client.request(third_req).await.unwrap();
        assert_eq!(res_rate.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
