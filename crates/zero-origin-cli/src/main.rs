// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! `zero-origin` CLI: Self-hosted Network Edge Shield & C2PA Provenance Toolkit.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use zero_origin_c2pa::canary::generate_deterministic_canary_png;
use zero_origin_c2pa::keygen::{
    generate_creator_identity, generate_tls_san_pki, write_identity_files, write_tls_pki_files,
};
use zero_origin_c2pa::signer::{sign_asset_bytes, SignParams};
use zero_origin_common::provenance::{ManifestFormat, SigningAlgorithm};
use zero_origin_proxy::config::ProxyConfig;
use zero_origin_proxy::server::{run_proxy_server, ProxyState};
use zero_origin_proxy::telemetry::AuditStore;
use zero_origin_scanner::config::ScannerConfig;
use zero_origin_scanner::server::{
    run_scanner_server, run_static_origin_server, ScannerAppState,
};
use zero_origin_verify::{audit_http_rights_headers, verify_asset_bytes};

#[derive(Parser)]
#[command(
    name = "zero-origin",
    version,
    about = "Self-hosted L7 Edge Shield & C2PA Cryptographic Provenance CLI for originZero.Art"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum AlgArg {
    Ed25519,
    Es256,
}

#[derive(Clone, ValueEnum)]
enum FormatArg {
    Json,
    Cose,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the L7 reverse-proxy edge shield & AI crawler mitigation daemon
    Serve {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Generate offline self-hosted Ed25519 or ECDSA P-256 keys & X.509 certificate
    Keygen {
        #[arg(long, value_enum, default_value_t = AlgArg::Ed25519)]
        alg: AlgArg,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "originzero.art")]
        domain: String,
        #[arg(short, long, default_value = "./keys")]
        out: PathBuf,
        #[arg(long, default_value = "creator")]
        prefix: String,
    },
    /// Cryptographically sign a JPEG/PNG/WebP/AVIF artwork losslessly with embedded JUMBF manifest
    Sign {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        key: PathBuf,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        creator: String,
        #[arg(long, default_value = "https://originzero.art")]
        url: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long, value_enum, default_value_t = FormatArg::Json)]
        format: FormatArg,
    },
    /// Verify C2PA JUMBF human authorship or inspect HTTP URL TDM headers
    Verify {
        /// Local image file path OR HTTP URL (http://...)
        target: String,
    },
    /// Display zero-PII blocked crawler summary from the SQLite WAL telemetry database
    Audit {
        #[arg(long, default_value = "./zero-origin-audit.db")]
        db: String,
    },
    /// Start the scanner.originzero.art Zero-SSRF Split-Screen Comparator & 99%->1% Academy server
    Scanner {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Generate deterministic ~1.84 MB Coordinate (0,0) benchmark canary pair (unsigned + Ed25519 C2PA signed)
    ProvisionCanary {
        #[arg(long)]
        out_unsigned: PathBuf,
        #[arg(long)]
        out_signed: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long, default_value = "Sebastian Paul Banszky")]
        creator: String,
        #[arg(long, default_value = "800")]
        width: u32,
        #[arg(long, default_value = "768")]
        height: u32,
    },
    /// Generate multi-SAN self-signed TLS server certificate for pre-cutover / local Triad verification
    TlsSelfsign {
        #[arg(long = "san", required = true)]
        sans: Vec<String>,
        #[arg(long, default_value = "originzero.art")]
        cn: String,
        #[arg(short, long, default_value = "./certs")]
        out: PathBuf,
        #[arg(long, default_value = "triad-tls")]
        prefix: String,
    },
    /// Minimal loopback/TLS static file server for originzero.art & unsafe.originzero.art Triad testing
    StaticOrigin {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        tls_cert: Option<String>,
        #[arg(long)]
        tls_key: Option<String>,
        #[arg(long, default_value_t = false)]
        unshielded_control: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { config } => {
            let cfg = match config {
                Some(path) => match ProxyConfig::from_file(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed loading config {:?}: {}", path, e);
                        return ExitCode::FAILURE;
                    }
                },
                None => ProxyConfig::default(),
            };
            let state = match ProxyState::new(cfg) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Proxy initialization failed: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = run_proxy_server(state).await {
                eprintln!("Proxy server exited with error: {}", e);
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }

        Commands::Keygen {
            alg,
            name,
            domain,
            out,
            prefix,
        } => {
            let alg_enum = match alg {
                AlgArg::Ed25519 => SigningAlgorithm::Ed25519,
                AlgArg::Es256 => SigningAlgorithm::Es256,
            };
            match generate_creator_identity(alg_enum, &name, &domain) {
                Ok(id) => match write_identity_files(&id, &out, &prefix) {
                    Ok(()) => {
                        println!(
                            "Generated {:?} identity files in {} ({}.key.pem [0600], {}.pub.pem, {}.cert.pem)",
                            alg_enum,
                            out.display(),
                            prefix,
                            prefix,
                            prefix
                        );
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("Failed writing identity files: {}", e);
                        ExitCode::FAILURE
                    }
                },
                Err(e) => {
                    eprintln!("Key generation failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Sign {
            input,
            output,
            key,
            cert,
            creator,
            url,
            title,
            format,
        } => {
            let raw_bytes = match fs::read(&input) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed reading input file {:?}: {}", input, e);
                    return ExitCode::FAILURE;
                }
            };
            let key_pem = match fs::read_to_string(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Failed reading private key {:?}: {}", key, e);
                    return ExitCode::FAILURE;
                }
            };
            let cert_pem = cert.and_then(|c| fs::read_to_string(c).ok());
            let manifest_format = match format {
                FormatArg::Json => ManifestFormat::Json,
                FormatArg::Cose => ManifestFormat::Cose,
            };

            let params = SignParams {
                creator_name: creator,
                creator_url: url,
                title,
                certificate_pem: cert_pem,
                manifest_format,
                ..Default::default()
            };

            match sign_asset_bytes(&raw_bytes, &key_pem, &params) {
                Ok(signed) => match fs::write(&output, signed) {
                    Ok(()) => {
                        println!("Successfully embedded lossless C2PA/JUMBF manifest -> {}", output.display());
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("Failed writing signed file {:?}: {}", output, e);
                        ExitCode::FAILURE
                    }
                },
                Err(e) => {
                    eprintln!("Signing failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Verify { target } => {
            if target.starts_with("http://") || target.starts_with("https://") {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let mut http_conn = HttpConnector::new();
                http_conn.enforce_http(false);
                let https_conn = HttpsConnectorBuilder::new()
                    .with_webpki_roots()
                    .https_or_http()
                    .enable_http1()
                    .enable_http2()
                    .wrap_connector(http_conn);
                let client: Client<HttpsConnector<HttpConnector>, Full<Bytes>> =
                    Client::builder(TokioExecutor::new()).build(https_conn);

                let req = match Request::builder()
                    .uri(&target)
                    .header(hyper::header::USER_AGENT, "zero-origin-verifier/0.1 (originZero.Art)")
                    .body(Full::new(Bytes::new()))
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Invalid URL {}: {}", target, e);
                        return ExitCode::FAILURE;
                    }
                };
                match client.request(req).await {
                    Ok(resp) => {
                        let status_code = resp.status().as_u16();
                        let pairs: Vec<(String, String)> = resp
                            .headers()
                            .iter()
                            .filter_map(|(k, v)| {
                                v.to_str()
                                    .ok()
                                    .map(|vs| (k.as_str().to_string(), vs.to_string()))
                            })
                            .collect();
                        let ref_pairs: Vec<(&str, &str)> =
                            pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                        let http_audit = audit_http_rights_headers(ref_pairs);

                        let body = resp.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
                        let asset_res = verify_asset_bytes(&body).ok();

                        let out = serde_json::json!({
                            "url": target,
                            "status": status_code,
                            "http_rights": http_audit,
                            "provenance": asset_res,
                        });
                        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("HTTP/HTTPS inspection failed: {}", e);
                        ExitCode::FAILURE
                    }
                }
            } else {
                let bytes = match fs::read(&target) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("Failed reading file {}: {}", target, e);
                        return ExitCode::FAILURE;
                    }
                };
                match verify_asset_bytes(&bytes) {
                    Ok(report) => {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("VERIFICATION FAILED: {}", e);
                        ExitCode::FAILURE
                    }
                }
            }
        }

        Commands::Audit { db } => match AuditStore::open(&db) {
            Ok(store) => match store.summary() {
                Ok(sum) => {
                    let json = serde_json::json!({
                        "total_blocked_403": sum.total_blocked,
                        "total_rate_limited_429": sum.total_rate_limited,
                        "top_rules": sum.recent_rules,
                    });
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Audit query error: {}", e);
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("Failed opening SQLite database {}: {}", db, e);
                ExitCode::FAILURE
            }
        },

        Commands::Scanner { config } => {
            let cfg = match config {
                Some(path) => match ScannerConfig::from_file(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed loading scanner config {:?}: {}", path, e);
                        return ExitCode::FAILURE;
                    }
                },
                None => ScannerConfig::default(),
            };
            let state = match ScannerAppState::new(cfg) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Scanner initialization failed: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = run_scanner_server(state).await {
                eprintln!("Scanner server exited with error: {}", e);
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }

        Commands::ProvisionCanary {
            out_unsigned,
            out_signed,
            key,
            cert,
            creator,
            width,
            height,
        } => {
            let raw_png = generate_deterministic_canary_png(width, height);
            if let Some(parent) = out_unsigned.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Some(parent) = out_signed.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(e) = fs::write(&out_unsigned, &raw_png) {
                eprintln!("Failed writing unsigned canary {:?}: {}", out_unsigned, e);
                return ExitCode::FAILURE;
            }
            let key_pem = match fs::read_to_string(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Failed reading private key {:?}: {}", key, e);
                    return ExitCode::FAILURE;
                }
            };
            let cert_pem = cert.and_then(|c| fs::read_to_string(c).ok());
            let params = SignParams {
                creator_name: creator,
                creator_url: "https://originzero.art".to_string(),
                title: Some("originZero.Art Coordinate (0,0) Benchmark Canary".to_string()),
                certificate_pem: cert_pem,
                manifest_format: ManifestFormat::Cose,
                ..Default::default()
            };
            match sign_asset_bytes(&raw_png, &key_pem, &params) {
                Ok(signed) => match fs::write(&out_signed, &signed) {
                    Ok(()) => {
                        println!(
                            "Provisioned deterministic canary pair: unsigned={} ({} bytes), signed={} ({} bytes)",
                            out_unsigned.display(),
                            raw_png.len(),
                            out_signed.display(),
                            signed.len()
                        );
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("Failed writing signed canary {:?}: {}", out_signed, e);
                        return ExitCode::FAILURE;
                    }
                },
                Err(e) => {
                    eprintln!("Signing canary failed: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        }

        Commands::TlsSelfsign {
            sans,
            cn,
            out,
            prefix,
        } => match generate_tls_san_pki(&sans, &cn) {
            Ok(pki) => match write_tls_pki_files(&pki, &out, &prefix) {
                Ok(()) => {
                    println!(
                        "Generated RFC 5280 TLS PKI in {} ({}-ca.cert.pem, {}.cert.pem, {}.key.pem [0600])",
                        out.display(),
                        prefix,
                        prefix,
                        prefix
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Failed writing TLS files: {}", e);
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("TLS SAN generation failed: {}", e);
                ExitCode::FAILURE
            }
        },

        Commands::StaticOrigin {
            listen,
            root,
            tls_cert,
            tls_key,
            unshielded_control,
        } => {
            let tls_pair = match (tls_cert, tls_key) {
                (Some(c), Some(k)) => Some((c, k)),
                _ => None,
            };
            if let Err(e) = run_static_origin_server(&listen, root, tls_pair, unshielded_control).await {
                eprintln!("StaticOrigin server exited with error: {}", e);
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}
