// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Bounds-checked HAProxy PROXY protocol v1 (ASCII) & v2 (Binary) wire parser.
//! Invoked strictly when incoming peer IP matches `trusted_proxy_cidrs`, enabling
//! `nginx stream { ssl_preread on; proxy_protocol on; }` to preserve both real
//! client source IPs and untouched downstream TLS ClientHello records for JA4.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Mandatory 12-byte HAProxy PROXY protocol v2 binary signature.
pub const PROXY_V2_SIG: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

/// Hard upper bound on accepted PROXY v2 header payload bytes to block amplification.
const MAX_PROXY_V2_BODY_LEN: usize = 2048;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProxyProtocolError {
    #[error("expected PROXY protocol header from trusted proxy but none detected")]
    MissingHeader,
    #[error("malformed PROXY protocol v1 line")]
    MalformedV1,
    #[error("malformed or unsupported PROXY protocol v2 header")]
    MalformedV2,
    #[error("PROXY protocol v2 header exceeds maximum safe size")]
    OversizedV2,
    #[error("socket read failure: {0}")]
    Io(String),
}

/// Consumes an HAProxy PROXY protocol v1 or v2 header from the beginning of `stream`
/// and returns the recovered effective peer `SocketAddr`.
pub async fn read_proxy_header(
    stream: &mut TcpStream,
    fallback_peer: SocketAddr,
) -> Result<SocketAddr, ProxyProtocolError> {
    let mut peek_hdr = [0u8; 16];
    let n = stream
        .peek(&mut peek_hdr)
        .await
        .map_err(|e| ProxyProtocolError::Io(e.to_string()))?;

    if n >= 16 && peek_hdr[..12] == PROXY_V2_SIG {
        return read_proxy_v2(stream, fallback_peer).await;
    }

    if n >= 6 && &peek_hdr[..6] == b"PROXY " {
        return read_proxy_v1(stream, fallback_peer).await;
    }

    Err(ProxyProtocolError::MissingHeader)
}

async fn read_proxy_v2(
    stream: &mut TcpStream,
    fallback_peer: SocketAddr,
) -> Result<SocketAddr, ProxyProtocolError> {
    let mut hdr = [0u8; 16];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| ProxyProtocolError::Io(e.to_string()))?;

    if hdr[..12] != PROXY_V2_SIG {
        return Err(ProxyProtocolError::MalformedV2);
    }

    let ver_cmd = hdr[12];
    let version = ver_cmd >> 4;
    let cmd = ver_cmd & 0x0f;
    if version != 2 {
        return Err(ProxyProtocolError::MalformedV2);
    }

    let family_proto = hdr[13];
    let body_len = u16::from_be_bytes([hdr[14], hdr[15]]) as usize;
    if body_len > MAX_PROXY_V2_BODY_LEN {
        return Err(ProxyProtocolError::OversizedV2);
    }

    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| ProxyProtocolError::Io(e.to_string()))?;
    }

    // LOCAL (0x00) is for health checks between proxy and backend -> retain peer_addr
    if cmd == 0x00 {
        return Ok(fallback_peer);
    }
    if cmd != 0x01 {
        return Err(ProxyProtocolError::MalformedV2);
    }

    match family_proto {
        // AF_INET (1) + STREAM/DGRAM (1/2): src4 + dst4 + sport2 + dport2 = 12 bytes
        0x11 | 0x12 => {
            if body.len() < 12 {
                return Err(ProxyProtocolError::MalformedV2);
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(body[0], body[1], body[2], body[3]));
            let src_port = u16::from_be_bytes([body[8], body[9]]);
            Ok(SocketAddr::new(src_ip, src_port))
        }
        // AF_INET6 (2) + STREAM/DGRAM (1/2): src16 + dst16 + sport2 + dport2 = 36 bytes
        0x21 | 0x22 => {
            if body.len() < 36 {
                return Err(ProxyProtocolError::MalformedV2);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            let src_ip = IpAddr::V6(Ipv6Addr::from(octets));
            let src_port = u16::from_be_bytes([body[32], body[33]]);
            Ok(SocketAddr::new(src_ip, src_port))
        }
        // AF_UNSPEC (0)
        0x00 => Ok(fallback_peer),
        _ => Err(ProxyProtocolError::MalformedV2),
    }
}

async fn read_proxy_v1(
    stream: &mut TcpStream,
    fallback_peer: SocketAddr,
) -> Result<SocketAddr, ProxyProtocolError> {
    // Max PROXY v1 line per spec is 107 bytes (e.g., IPv6 fields + CRLF)
    let mut peek_line = [0u8; 128];
    let n = stream
        .peek(&mut peek_line)
        .await
        .map_err(|e| ProxyProtocolError::Io(e.to_string()))?;

    let crlf_pos = peek_line[..n]
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(ProxyProtocolError::MalformedV1)?;

    let exact_len = crlf_pos + 2;
    let mut raw_line = vec![0u8; exact_len];
    stream
        .read_exact(&mut raw_line)
        .await
        .map_err(|e| ProxyProtocolError::Io(e.to_string()))?;

    let text = std::str::from_utf8(&raw_line[..crlf_pos])
        .map_err(|_| ProxyProtocolError::MalformedV1)?;
    let parts: Vec<&str> = text.split(' ').collect();
    if parts.len() >= 2 && parts[0] == "PROXY" && parts[1] == "UNKNOWN" {
        return Ok(fallback_peer);
    }
    if parts.len() != 6 || parts[0] != "PROXY" {
        return Err(ProxyProtocolError::MalformedV1);
    }

    let src_ip: IpAddr = match parts[1] {
        "TCP4" => parts[2]
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|_| ProxyProtocolError::MalformedV1)?,
        "TCP6" => parts[2]
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .map_err(|_| ProxyProtocolError::MalformedV1)?,
        _ => return Err(ProxyProtocolError::MalformedV1),
    };
    let src_port: u16 = parts[4]
        .parse::<u16>()
        .map_err(|_| ProxyProtocolError::MalformedV1)?;
    Ok(SocketAddr::new(src_ip, src_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn test_pair_with_bytes(payload: Vec<u8>) -> Result<SocketAddr, ProxyProtocolError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(&payload).await.unwrap();
            // Send marker TLS ClientHello initial byte afterwards to verify cursor alignment
            client.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
            let _ = client.shutdown().await;
        });

        let (mut server_stream, fallback) = listener.accept().await.unwrap();
        let res = read_proxy_header(&mut server_stream, fallback).await;
        if res.is_ok() {
            let mut after = [0u8; 3];
            let read_n = server_stream.read_exact(&mut after).await.unwrap();
            assert_eq!(read_n, 3);
            assert_eq!(after, [0x16, 0x03, 0x01]);
        }
        writer.await.unwrap();
        res
    }

    #[tokio::test]
    async fn test_proxy_v1_tcp4_and_cursor_alignment() {
        let line = b"PROXY TCP4 198.51.100.77 10.0.0.1 54321 443\r\n".to_vec();
        let res = test_pair_with_bytes(line).await.unwrap();
        assert_eq!(res, "198.51.100.77:54321".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_proxy_v2_ipv4_with_trailing_tlv() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&PROXY_V2_SIG);
        hdr.push(0x21); // v2 + PROXY
        hdr.push(0x11); // TCPv4
        // 12B addr block + 6B dummy TLV (type 0x02, len 3, "foo")
        hdr.extend_from_slice(&18u16.to_be_bytes());
        hdr.extend_from_slice(&[203, 0, 113, 99]); // src IP
        hdr.extend_from_slice(&[127, 0, 0, 1]); // dst IP
        hdr.extend_from_slice(&44444u16.to_be_bytes()); // src port
        hdr.extend_from_slice(&443u16.to_be_bytes()); // dst port
        hdr.extend_from_slice(&[0x02, 0x00, 0x03, b'f', b'o', b'o']);

        let res = test_pair_with_bytes(hdr).await.unwrap();
        assert_eq!(res, "203.0.113.99:44444".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_proxy_v2_oversized_rejected() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&PROXY_V2_SIG);
        hdr.push(0x21);
        hdr.push(0x11);
        hdr.extend_from_slice(&(MAX_PROXY_V2_BODY_LEN as u16 + 1).to_be_bytes());
        let res = test_pair_with_bytes(hdr).await;
        assert_eq!(res, Err(ProxyProtocolError::OversizedV2));
    }
}
