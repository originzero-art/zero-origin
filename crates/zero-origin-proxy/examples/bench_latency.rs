// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Deterministic Micro-Benchmark: JA4 Wire Parsing & Edge Classifier Latency.
//! Run with: `cargo run --release -p zero-origin-proxy --example bench_latency`

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use zero_origin_ja4::parse_client_hello_ja4;
use zero_origin_proxy::classifier::EdgeClassifier;
use zero_origin_proxy::config::ProxyConfig;

fn main() {
    // Realistic TLS 1.3 ClientHello fixture
    let mut pkt = vec![
        0x16, 0x03, 0x01, 0x00, 0x45, // rec header
        0x01, 0x00, 0x00, 0x41, // handshake header
        0x03, 0x03, // legacy tls 1.2
    ];
    pkt.extend_from_slice(&[0x11; 32]); // random
    pkt.push(0); // sid
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
    pkt.extend_from_slice(&[1, 0]); // comp
    pkt.extend_from_slice(&13u16.to_be_bytes()); // ext len
    pkt.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]); // supported_versions
    pkt.extend_from_slice(&[0x00, 0x10, 0x00, 0x02, 0x01, b'h']); // short ext padding (alpn stub)

    let iterations = 50_000usize;
    let mut latencies_ns = Vec::with_capacity(iterations);

    let classifier = EdgeClassifier::from_config(&ProxyConfig::default());
    let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

    let total_start = Instant::now();
    for i in 0..iterations {
        let t0 = Instant::now();
        let fp = parse_client_hello_ja4(&pkt).ok();
        let ua = if i % 5 == 0 {
            Some("GPTBot/1.0")
        } else {
            Some("Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36")
        };
        let _ = classifier.classify(peer, None, ua, fp.as_ref(), false, false);
        latencies_ns.push(t0.elapsed().as_nanos());
    }
    let wall = total_start.elapsed();
    latencies_ns.sort_unstable();

    let p50 = latencies_ns[iterations / 2] as f64 / 1000.0;
    let p99 = latencies_ns[(iterations * 99) / 100] as f64 / 1000.0;
    let rps = iterations as f64 / wall.as_secs_f64();

    println!(
        "Benchmarked {} classification+JA4 evaluations in {:.2?}: {:.0} req/s | p50 = {:.2} us | p99 = {:.2} us",
        iterations, wall, rps, p50, p99
    );
    assert!(p99 < 2000.0, "p99 latency exceeded 2.0ms budget!");
}
