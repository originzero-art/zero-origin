// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Async Layer-7 Reverse Proxy Server (`tokio` + `hyper` v1 + `tokio-rustls`).
//! Features:
//! - Optional HAProxy PROXY protocol v1/v2 ingestion from `trusted_proxy_cidrs`
//! - Non-destructive TCP `peek()` for FoxIO JA4 extraction before TLS termination
//! - Multi-SNI TLS certificates (`ResolvesServerCertUsingSni`) + per-host `upstream_routes`
//! - Slowloris header-read timeouts (`TokioTimer`), pre-HTTP deadlines, concurrency `Semaphore`, & graceful shutdown
//! - Async FCrDNS search crawler verification (blocking spoofed `Googlebot`/`Bingbot` before upstream transfer)

use std::convert::Infallible;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use zero_origin_ja4::{parse_client_hello_ja4, Ja4Fingerprint};

use crate::classifier::{claimed_search_bot_family, EdgeClassifier, Verdict};
use crate::config::ProxyConfig;
use crate::fcrdns::FcrdnsVerifier;
use crate::proxy_protocol::read_proxy_header;
use crate::telemetry::AuditStore;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, BoxError>;

pub struct ProxyState {
    pub config: ProxyConfig,
    pub classifier: EdgeClassifier,
    pub fcrdns: FcrdnsVerifier,
    pub audit: AuditStore,
    pub http_client: Client<HttpsConnector<HttpConnector>, hyper::body::Incoming>,
    pub ai_txt_cached: String,
    pub tdmrep_cached: String,
    pub tls_acceptor: Option<TlsAcceptor>,
}

impl ProxyState {
    pub fn new(config: ProxyConfig) -> Result<Arc<Self>, BoxError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let audit = AuditStore::open(&config.sqlite_path)?;
        let classifier = EdgeClassifier::from_config(&config);
        let fcrdns = FcrdnsVerifier::new(
            config.fcrdns_resolver.as_deref(),
            config.fcrdns_cache_ttl_secs,
        );
        let ai_txt_cached = config.rights.render_ai_txt();
        let tdmrep_cached = config.rights.render_tdmrep_json()?;

        let tls_acceptor = build_tls_acceptor_from_config(&config)?;

        let mut http_conn = HttpConnector::new();
        http_conn.enforce_http(false);
        let https_conn = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_conn);
        let http_client = Client::builder(TokioExecutor::new()).build(https_conn);

        Ok(Arc::new(Self {
            config,
            classifier,
            fcrdns,
            audit,
            http_client,
            ai_txt_cached,
            tdmrep_cached,
            tls_acceptor,
        }))
    }
}

#[derive(Debug)]
struct SniWithFallbackResolver {
    sni: ResolvesServerCertUsingSni,
    fallback: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniWithFallbackResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.sni
            .resolve(client_hello)
            .or_else(|| self.fallback.clone())
    }
}

fn load_certified_key(cert_path: &str, key_path: &str) -> Result<CertifiedKey, BoxError> {
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing TLS private key"))?;

    let provider = rustls::crypto::ring::default_provider();
    let ck = CertifiedKey::from_der(certs, key, &provider)?;
    Ok(ck)
}

fn build_tls_acceptor_from_config(cfg: &ProxyConfig) -> Result<Option<TlsAcceptor>, BoxError> {
    let fallback = match (&cfg.tls_cert_path, &cfg.tls_key_path) {
        (Some(cert_p), Some(key_p)) => Some(Arc::new(load_certified_key(cert_p, key_p)?)),
        _ => None,
    };

    if fallback.is_none() && cfg.tls_sni_certs.is_empty() {
        return Ok(None);
    }

    let mut sni_resolver = ResolvesServerCertUsingSni::new();
    for entry in &cfg.tls_sni_certs {
        let ck = load_certified_key(&entry.cert_path, &entry.key_path)?;
        sni_resolver.add(&entry.server_name, ck)?;
    }

    let combined = SniWithFallbackResolver {
        sni: sni_resolver,
        fallback,
    };

    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(combined));
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(tls_cfg))))
}

fn full_body(s: impl Into<Bytes>) -> ProxyBody {
    Full::new(s.into())
        .map_err(|never| match never {})
        .boxed()
}

fn inject_rights_headers(
    headers: &mut hyper::HeaderMap,
    state: &ProxyState,
    ja4: Option<&Ja4Fingerprint>,
) {
    for (name, value) in state.config.rights.response_headers() {
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(hn, hv);
        }
    }
    if let Some(fp) = ja4 {
        if let Ok(hv) = HeaderValue::from_str(&fp.ja4) {
            headers.insert("x-zero-origin-ja4", hv);
        }
        if let Some(ref sni) = fp.sni {
            if let Ok(hv) = HeaderValue::from_str(sni) {
                headers.insert("x-zero-origin-sni", hv);
            }
        }
    }
}

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    for h in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(h);
    }
}

pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    peer_addr: SocketAddr,
    ja4: Option<Ja4Fingerprint>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let path = req.uri().path().to_string();

    let incoming_host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
        .or_else(|| ja4.as_ref().and_then(|f| f.sni.clone()));

    let xff_val = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let ua_val = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let has_cl = req.headers().contains_key(hyper::header::CONTENT_LENGTH);
    let has_te = req.headers().contains_key(hyper::header::TRANSFER_ENCODING);

    let (client_ip, verdict) = state.classifier.classify(
        peer_addr.ip(),
        xff_val.as_deref(),
        ua_val.as_deref(),
        ja4.as_ref(),
        has_cl,
        has_te,
    );

    let ja4_str = ja4.as_ref().map(|f| f.ja4.as_str());

    match verdict {
        Verdict::RejectBadRequest { rule_id } => {
            state
                .audit
                .record_event("REJECT_400", rule_id, client_ip, ja4_str, method.as_str(), &path);
            let mut resp = Response::new(full_body(
                "400 Bad Request: Malformed HTTP framing rejected by zero-origin.\n",
            ));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
        Verdict::BlockForbidden { rule_id } => {
            state
                .audit
                .record_event("BLOCK_403", &rule_id, client_ip, ja4_str, method.as_str(), &path);
            let mut resp = Response::new(full_body(format!(
                "403 Forbidden: Automated harvesting blocked by zero-origin Edge Shield ({}).\nPolicy: {}\n",
                rule_id, state.config.rights.license_uri
            )));
            *resp.status_mut() = StatusCode::FORBIDDEN;
            inject_rights_headers(resp.headers_mut(), &state, ja4.as_ref());
            return Ok(resp);
        }
        Verdict::RateLimited { rule_id } => {
            state
                .audit
                .record_event("RATE_429", rule_id, client_ip, ja4_str, method.as_str(), &path);
            let mut resp = Response::new(full_body(
                "429 Too Many Requests: Rate limit enforced by zero-origin Edge Shield.\n",
            ));
            *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            resp.headers_mut()
                .insert(hyper::header::RETRY_AFTER, HeaderValue::from_static("60"));
            inject_rights_headers(resp.headers_mut(), &state, ja4.as_ref());
            return Ok(resp);
        }
        Verdict::Allow => {}
    }

    // Async Forward-Confirmed Reverse DNS check for claimed traditional search indexers
    if state.config.verify_search_bots_fcrdns && state.config.rights.allow_search_indexing {
        if let Some(bot_family) = claimed_search_bot_family(ua_val.as_deref()) {
            if !state.fcrdns.verify_search_bot(client_ip, bot_family).await {
                state.audit.record_event(
                    "BLOCK_403",
                    "RULE-SPOOFED-SEARCH-BOT",
                    client_ip,
                    ja4_str,
                    method.as_str(),
                    &path,
                );
                let mut resp = Response::new(full_body(format!(
                    "403 Forbidden: Claimed search crawler failed FCrDNS verification ({}).\n",
                    state.config.rights.license_uri
                )));
                *resp.status_mut() = StatusCode::FORBIDDEN;
                inject_rights_headers(resp.headers_mut(), &state, ja4.as_ref());
                return Ok(resp);
            }
        }
    }

    // Direct self-hosted machine-readable rights endpoints
    if path == "/ai.txt" {
        let mut resp = Response::new(full_body(state.ai_txt_cached.clone()));
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        inject_rights_headers(resp.headers_mut(), &state, ja4.as_ref());
        return Ok(resp);
    }

    if path == "/.well-known/tdmrep.json" {
        let mut resp = Response::new(full_body(state.tdmrep_cached.clone()));
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        inject_rights_headers(resp.headers_mut(), &state, ja4.as_ref());
        return Ok(resp);
    }

    if path == "/license/tdm-reservation" || path == "/license/tdm-reservation/" {
        let license_doc = format!(
            "# originZero.Art // Sovereign TDM Reservation Policy\n\
             # Legal Instrument: Directive (EU) 2019/790 (DSM Directive), Article 4(3)\n\
             # Domain: {}\n\
             # Creator: {}\n\
             # Contact: {}\n\n\
             All text, visual artworks, photographic media, and metadata served from this origin\n\
             are expressly reserved by their human rightsholders pursuant to Article 4(3) of\n\
             Directive (EU) 2019/790 on copyright and related rights in the Digital Single Market.\n\
             Automated reproduction, scraping, or extraction for generative model training or\n\
             synthetic dataset assembly is strictly prohibited without prior written license.\n",
            state.config.rights.domain, state.config.rights.creator, state.config.rights.contact
        );
        let mut resp = Response::new(full_body(license_doc));
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        inject_rights_headers(resp.headers_mut(), &state, ja4.as_ref());
        return Ok(resp);
    }

    // Forward cleanly to isolated downstream private origin (host-routed or default)
    let upstream_base = state
        .config
        .resolve_upstream_for_host(incoming_host.as_deref())
        .trim_end_matches('/');
    let target_url = format!("{}{}", upstream_base, path_and_query);
    let target_uri: Uri = match target_url.parse() {
        Ok(u) => u,
        Err(_) => {
            let mut resp = Response::new(full_body("502 Bad Gateway: Invalid upstream target URI.\n"));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            return Ok(resp);
        }
    };

    let (mut parts, body) = req.into_parts();
    // Translate edge HTTP/2 (ALPN h2) down to HTTP/1.1 when forwarding over cleartext loopback http:// upstreams
    if target_uri.scheme_str() == Some("http") && parts.version == hyper::Version::HTTP_2 {
        parts.version = hyper::Version::HTTP_11;
    }
    // Remove incoming Host so hyper derives exact Host (H1) or :authority (H2) from target_uri without HTTP/2 duplicate-authority conflicts
    parts.headers.remove(hyper::header::HOST);
    parts.uri = target_uri;
    strip_hop_by_hop(&mut parts.headers);
    if let Some(ref h_val) = incoming_host {
        if let Ok(hv) = HeaderValue::from_str(h_val) {
            parts.headers.insert("x-forwarded-host", hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&client_ip.to_string()) {
        parts.headers.insert("x-forwarded-for", hv);
    }
    if let Some(ja4_val) = ja4_str {
        if let Ok(hv) = HeaderValue::from_str(ja4_val) {
            parts.headers.insert("x-zero-origin-ja4", hv);
        }
    }

    let upstream_req = Request::from_parts(parts, body);
    let upstream_deadline = Duration::from_secs(state.config.upstream_timeout_secs.max(1));
    match tokio::time::timeout(upstream_deadline, state.http_client.request(upstream_req)).await {
        Ok(Ok(mut upstream_res)) => {
            strip_hop_by_hop(upstream_res.headers_mut());
            inject_rights_headers(upstream_res.headers_mut(), &state, ja4.as_ref());
            let (res_parts, res_body) = upstream_res.into_parts();
            let boxed_body: ProxyBody = res_body.map_err(|e| Box::new(e) as BoxError).boxed();
            Ok(Response::from_parts(res_parts, boxed_body))
        }
        Ok(Err(err)) => {
            warn!("Upstream request error for {}: {}", target_url, err);
            let mut resp = Response::new(full_body("502 Bad Gateway: Downstream origin unreachable.\n"));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
        Err(_) => {
            warn!("Upstream request timed out for {} after {:?}", target_url, upstream_deadline);
            let mut resp = Response::new(full_body("504 Gateway Timeout: Downstream origin timed out.\n"));
            *resp.status_mut() = StatusCode::GATEWAY_TIMEOUT;
            Ok(resp)
        }
    }
}

/// Inspects raw wire HTTP headers before hyper framing normalization to catch
/// RFC 9112 request smuggling vectors (`Content-Length` + `Transfer-Encoding`,
/// or conflicting multiple `Content-Length` headers).
pub fn has_ambiguous_http_framing(buf: &[u8]) -> bool {
    let text = match std::str::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let head = match text.split("\r\n\r\n").next() {
        Some(h) => h,
        None => text,
    };
    let mut has_te = false;
    let mut cl_values: Vec<&str> = Vec::new();
    for line in head.split("\r\n").skip(1) {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("transfer-encoding:") {
            if !rest.trim().is_empty() {
                has_te = true;
            }
        } else if let Some((_, val)) = line.split_once(':') {
            if line[..line.find(':').unwrap_or(0)]
                .trim()
                .eq_ignore_ascii_case("content-length")
            {
                cl_values.push(val.trim());
            }
        }
    }
    if !cl_values.is_empty() && has_te {
        return true;
    }
    if cl_values.len() > 1 && cl_values.windows(2).any(|w| w[0] != w[1]) {
        return true;
    }
    false
}

fn build_conn_builder(cfg: &ProxyConfig) -> AutoConnBuilder<TokioExecutor> {
    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(cfg.header_read_timeout_secs.max(1)))
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(
            cfg.http2_keepalive_interval_secs.max(1),
        )))
        .keep_alive_timeout(Duration::from_secs(cfg.http2_keepalive_timeout_secs.max(1)))
        .max_concurrent_streams(200);
    builder
}

pub async fn serve_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<ProxyState>,
    watcher: Watcher,
) {
    let handshake_deadline = Duration::from_secs(state.config.tls_handshake_timeout_secs.max(1));

    // Strictly trusted HAProxy PROXY protocol v1/v2 ingestion (never accepted from public peers)
    let effective_peer = if state.config.accept_proxy_protocol
        && state.classifier.is_trusted_proxy(peer_addr.ip())
    {
        match tokio::time::timeout(handshake_deadline, read_proxy_header(&mut stream, peer_addr)).await
        {
            Ok(Ok(recovered)) => recovered,
            Ok(Err(e)) => {
                warn!("PROXY protocol error from trusted {}: {}", peer_addr, e);
                let _ = stream.shutdown().await;
                return;
            }
            Err(_) => {
                warn!("PROXY protocol read timed out from {}", peer_addr);
                let _ = stream.shutdown().await;
                return;
            }
        }
    } else {
        peer_addr
    };

    // Bounded pre-TLS non-destructive ClientHello peek
    let mut peek_buf = [0u8; 4096];
    let peek_len = match tokio::time::timeout(handshake_deadline, stream.peek(&mut peek_buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => 0,
        Err(_) => {
            warn!("Pre-handshake initial byte timeout (Slowloris) from {}", effective_peer);
            let _ = stream.shutdown().await;
            return;
        }
    };

    let ja4 = if peek_len > 0 {
        parse_client_hello_ja4(&peek_buf[..peek_len]).ok()
    } else {
        None
    };

    // Cleartext HTTP RFC 9112 smuggling check prior to HTTP parser normalization
    if state.tls_acceptor.is_none()
        && peek_len > 0
        && has_ambiguous_http_framing(&peek_buf[..peek_len])
    {
        state.audit.record_event(
            "REJECT_400",
            "RULE-RFC9112-SMUGGLING-CL-TE",
            effective_peer.ip(),
            None,
            "RAW",
            "/",
        );
        let body_msg = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 60\r\nConnection: close\r\n\r\n400 Bad Request: Ambiguous HTTP framing rejected (RFC9112).\n";
        let _ = stream.write_all(body_msg).await;
        let _ = stream.shutdown().await;
        return;
    }

    let builder = build_conn_builder(&state.config);

    if let Some(acceptor) = state.tls_acceptor.clone() {
        match tokio::time::timeout(handshake_deadline, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => {
                let io = TokioIo::new(tls_stream);
                let svc = service_fn(move |req| {
                    handle_request(req, effective_peer, ja4.clone(), Arc::clone(&state))
                });
                let conn = builder.serve_connection(io, svc);
                if let Err(e) = watcher.watch(conn).await {
                    error!("TLS HTTP serve error from {}: {}", effective_peer, e);
                }
            }
            Ok(Err(e)) => {
                warn!("TLS handshake rejected for {}: {}", effective_peer, e);
            }
            Err(_) => {
                warn!("TLS handshake timed out for {}", effective_peer);
            }
        }
    } else {
        let io = TokioIo::new(stream);
        let svc = service_fn(move |req| {
            handle_request(req, effective_peer, ja4.clone(), Arc::clone(&state))
        });
        let conn = builder.serve_connection(io, svc);
        if let Err(e) = watcher.watch(conn).await {
            error!("HTTP serve error from {}: {}", effective_peer, e);
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler install");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn run_proxy_server(state: Arc<ProxyState>) -> Result<(), BoxError> {
    let listener = TcpListener::bind(&state.config.listen_addr).await?;
    let max_conns = state.config.max_concurrent_connections.max(1);
    let conn_semaphore = Arc::new(Semaphore::new(max_conns));
    let graceful = GracefulShutdown::new();

    info!(
        "zero-origin L7 Edge Shield listening on {} -> forwarding to {} (max_conns={}, header_timeout={}s, proxy_protocol={})",
        state.config.listen_addr,
        state.config.upstream_origin,
        max_conns,
        state.config.header_read_timeout_secs,
        state.config.accept_proxy_protocol
    );

    let sig = shutdown_signal();
    tokio::pin!(sig);

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                let (mut stream, peer_addr) = match accept_res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("TCP accept error: {}", e);
                        continue;
                    }
                };
                let permit = match conn_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("Global connection limit ({}) reached; dropping {}", max_conns, peer_addr);
                        let _ = stream.shutdown().await;
                        continue;
                    }
                };
                let st = Arc::clone(&state);
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let _permit_guard = permit;
                    serve_connection(stream, peer_addr, st, watcher).await;
                });
            }
            _ = &mut sig => {
                info!("Shutdown signal received; draining active edge connections...");
                break;
            }
        }
    }

    drop(listener);
    let _ = tokio::time::timeout(Duration::from_secs(15), graceful.shutdown()).await;
    info!("zero-origin L7 Edge Shield drained cleanly.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    async fn spawn_mock_origin(label: &'static str, hits: Arc<AtomicUsize>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let hc = Arc::clone(&hits);
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                            let c = Arc::clone(&hc);
                            let xff = req
                                .headers()
                                .get("x-forwarded-for")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            async move {
                                c.fetch_add(1, Ordering::SeqCst);
                                let body = format!("{}|xff={}", label, xff);
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                            }
                        });
                        let _ = AutoConnBuilder::new(TokioExecutor::new())
                            .serve_connection(io, svc)
                            .await;
                    });
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_proxy_end_to_end_mitigation_and_header_injection() {
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let upstream_addr = spawn_mock_origin("DOWNSTREAM_PRIVATE_GALLERY_ASSET", Arc::clone(&upstream_hits)).await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let mut cfg = ProxyConfig::default();
        cfg.listen_addr = proxy_addr.to_string();
        cfg.upstream_origin = format!("http://{}", upstream_addr);
        cfg.sqlite_path = ":memory:".to_string();
        let state = ProxyState::new(cfg).unwrap();
        let st_accept = Arc::clone(&state);
        let graceful = Arc::new(GracefulShutdown::new());
        let g_clone = Arc::clone(&graceful);

        tokio::spawn(async move {
            loop {
                if let Ok((stream, peer)) = proxy_listener.accept().await {
                    let st = Arc::clone(&st_accept);
                    let w = g_clone.watcher();
                    tokio::spawn(serve_connection(stream, peer, st, w));
                }
            }
        });

        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();

        // Test A: GPTBot blocked at edge with 403 -> ZERO hits to private downstream origin
        let bot_req = Request::builder()
            .uri(format!("http://{}/artwork.jpg", proxy_addr))
            .header(hyper::header::USER_AGENT, "GPTBot/1.0")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let bot_res = client.request(bot_req).await.unwrap();
        assert_eq!(bot_res.status(), StatusCode::FORBIDDEN);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

        // Test B: Spoofed Googlebot on unverified loopback IP -> BLOCKED by FCrDNS with ZERO upstream hits
        let spoof_google = Request::builder()
            .uri(format!("http://{}/artwork.jpg", proxy_addr))
            .header(
                hyper::header::USER_AGENT,
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            )
            .body(Full::new(Bytes::new()))
            .unwrap();
        let spoof_res = client.request(spoof_google).await.unwrap();
        assert_eq!(spoof_res.status(), StatusCode::FORBIDDEN);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

        // Test C: Legitimate human visitor allowed -> Content-Usage & TDM headers injected
        let human_req = Request::builder()
            .uri(format!("http://{}/artwork.jpg", proxy_addr))
            .header(hyper::header::USER_AGENT, "Mozilla/5.0 (Macintosh) Safari/605.1.15")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let human_res = client.request(human_req).await.unwrap();
        assert_eq!(human_res.status(), StatusCode::OK);
        assert_eq!(human_res.headers().get("tdm-reservation").unwrap(), "1");
        assert_eq!(human_res.headers().get("content-usage").unwrap(), "train-ai=n, search=y");
        assert!(human_res.headers().contains_key("link"));
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        // Test D: Self-hosted /ai.txt endpoint
        let ai_req = Request::builder()
            .uri(format!("http://{}/ai.txt", proxy_addr))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let ai_res = client.request(ai_req).await.unwrap();
        assert_eq!(ai_res.status(), StatusCode::OK);
        let body_bytes = ai_res.collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Content-Usage: train-ai=n, search=y"));
        assert!(body_str.contains("Disallow-AI-Training: /"));
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_slowloris_partial_header_timeout_closes_socket() {
        let hits = Arc::new(AtomicUsize::new(0));
        let upstream_addr = spawn_mock_origin("OK", hits).await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let mut cfg = ProxyConfig::default();
        cfg.listen_addr = proxy_addr.to_string();
        cfg.upstream_origin = format!("http://{}", upstream_addr);
        cfg.sqlite_path = ":memory:".to_string();
        cfg.header_read_timeout_secs = 1;
        cfg.tls_handshake_timeout_secs = 2;
        let state = ProxyState::new(cfg).unwrap();
        let st_accept = Arc::clone(&state);
        let graceful = Arc::new(GracefulShutdown::new());
        let g_clone = Arc::clone(&graceful);

        tokio::spawn(async move {
            loop {
                if let Ok((stream, peer)) = proxy_listener.accept().await {
                    let st = Arc::clone(&st_accept);
                    let w = g_clone.watcher();
                    tokio::spawn(serve_connection(stream, peer, st, w));
                }
            }
        });

        // Open Slowloris socket sending incomplete headers without final CRLFCRLF
        let mut slow_client = TcpStream::connect(proxy_addr).await.unwrap();
        slow_client
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: ")
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let closed = tokio::time::timeout(Duration::from_secs(3), slow_client.read(&mut buf))
            .await
            .expect("Slowloris socket must be closed before 3s");
        assert_eq!(closed.unwrap_or(0), 0);
    }

    #[tokio::test]
    async fn test_proxy_protocol_v2_restores_client_ip_and_multi_host_routing() {
        let hits_a = Arc::new(AtomicUsize::new(0));
        let hits_b = Arc::new(AtomicUsize::new(0));
        let origin_a = spawn_mock_origin("ORIGIN_757", Arc::clone(&hits_a)).await;
        let origin_b = spawn_mock_origin("ORIGIN_SPARTAN", Arc::clone(&hits_b)).await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let mut cfg = ProxyConfig::default();
        cfg.listen_addr = proxy_addr.to_string();
        cfg.upstream_origin = format!("http://{}", origin_a);
        cfg.upstream_routes
            .insert("spartan.originzero.art".to_string(), format!("http://{}", origin_b));
        cfg.sqlite_path = ":memory:".to_string();
        cfg.accept_proxy_protocol = true;
        cfg.trusted_proxy_cidrs = vec!["127.0.0.1/32".to_string()];
        let state = ProxyState::new(cfg).unwrap();
        let st_accept = Arc::clone(&state);
        let graceful = Arc::new(GracefulShutdown::new());
        let g_clone = Arc::clone(&graceful);

        tokio::spawn(async move {
            loop {
                if let Ok((stream, peer)) = proxy_listener.accept().await {
                    let st = Arc::clone(&st_accept);
                    let w = g_clone.watcher();
                    tokio::spawn(serve_connection(stream, peer, st, w));
                }
            }
        });

        // Pipe PROXY protocol v2 binary header asserting client IP 203.0.113.45 -> Host: spartan.originzero.art
        let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&crate::proxy_protocol::PROXY_V2_SIG);
        pkt.push(0x21); // v2 PROXY
        pkt.push(0x11); // TCPv4
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&[203, 0, 113, 45]); // client IP
        pkt.extend_from_slice(&[127, 0, 0, 1]);
        pkt.extend_from_slice(&55555u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(
            b"GET / HTTP/1.1\r\nHost: spartan.originzero.art\r\nUser-Agent: TestBrowser/1.0\r\nConnection: close\r\n\r\n",
        );
        sock.write_all(&pkt).await.unwrap();

        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("200 OK"), "unexpected response: {}", resp_str);
        assert!(resp_str.contains("ORIGIN_SPARTAN|xff=203.0.113.45"), "missing routed body/IP: {}", resp_str);
        assert_eq!(hits_b.load(Ordering::SeqCst), 1);
        assert_eq!(hits_a.load(Ordering::SeqCst), 0);
    }
}
