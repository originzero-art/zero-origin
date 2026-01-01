// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! `zero-origin-ja4`: Non-destructive wire-level TLS ClientHello parser &
//! FoxIO JA4 fingerprint calculator. Designed for `TcpStream::peek` inspection
//! prior to `tokio-rustls` handshake acceptance without mutating the socket cursor.

use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ja4ParseError {
    #[error("packet does not begin with a TLS Handshake record (0x16)")]
    NotTlsHandshake,
    #[error("TLS handshake message is not ClientHello (0x01)")]
    NotClientHello,
    #[error("truncated or malformed TLS ClientHello record at byte offset {0}")]
    TruncatedOrMalformed(usize),
}

/// Complete extracted ClientHello metadata and FoxIO JA4 fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Fingerprint {
    /// Standard hashed JA4 string (`ja4_a_ja4_b_ja4_c`, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`).
    pub ja4: String,
    /// Unhashed JA4 components useful for heuristic debugging & rule authoring.
    pub ja4_raw: String,
    /// Extracted SNI hostname if present.
    pub sni: Option<String>,
    /// Negotiated first ALPN token if present.
    pub first_alpn: Option<String>,
    /// Non-GREASE cipher suite count (capped at 99 for formatting).
    pub cipher_count: u8,
    /// Non-GREASE extension count (capped at 99 for formatting).
    pub extension_count: u8,
    /// Indicates RFC 8701 GREASE values were observed (typical of real browsers, often omitted by bots).
    pub observed_grease: bool,
}

#[inline]
pub fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && (val >> 8) == (val & 0xff)
}

fn tls_version_label(ver: u16) -> &'static str {
    match ver {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

fn format_alpn_tag(alpn: Option<&str>) -> String {
    match alpn {
        None => "00".to_string(),
        Some(s) if s.is_empty() => "00".to_string(),
        Some(s) => {
            let bytes = s.as_bytes();
            let first = bytes[0];
            let last = bytes[bytes.len() - 1];
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
                format!("{}{}", first as char, last as char)
            } else {
                // Non-alphanumeric edge fallback per spec: first/last nibble hex or 99
                format!("{:02x}", first)
            }
        }
    }
}

fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, Ja4ParseError> {
    let bytes = buf
        .get(*pos..*pos + 2)
        .ok_or(Ja4ParseError::TruncatedOrMalformed(*pos))?;
    *pos += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8, Ja4ParseError> {
    let b = *buf.get(*pos).ok_or(Ja4ParseError::TruncatedOrMalformed(*pos))?;
    *pos += 1;
    Ok(b)
}

fn sha256_12(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let full = hex::encode(hasher.finalize());
    full[..12].to_string()
}

/// Parses raw peeked TCP bytes starting at a TLS ClientHello record (`0x16`).
/// Strictly bounds-checked: never panics on malicious or truncated packets.
pub fn parse_client_hello_ja4(buf: &[u8]) -> Result<Ja4Fingerprint, Ja4ParseError> {
    if buf.len() < 44 {
        if !buf.is_empty() && buf[0] != 0x16 {
            return Err(Ja4ParseError::NotTlsHandshake);
        }
        return Err(Ja4ParseError::TruncatedOrMalformed(0));
    }

    // Record layer
    if buf[0] != 0x16 {
        return Err(Ja4ParseError::NotTlsHandshake);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5usize.saturating_add(record_len).min(buf.len());

    // Handshake layer
    let hs_type = buf[5];
    if hs_type != 0x01 {
        return Err(Ja4ParseError::NotClientHello);
    }

    let mut pos = 9usize; // Start of ClientHello body (skip 5 rec + 4 hs header)
    let legacy_version = read_u16(buf, &mut pos)?;

    // Skip 32-byte ClientHello.random
    if pos + 32 > record_end {
        return Err(Ja4ParseError::TruncatedOrMalformed(pos));
    }
    pos += 32;

    // Session ID
    let sid_len = read_u8(buf, &mut pos)? as usize;
    if pos + sid_len > record_end {
        return Err(Ja4ParseError::TruncatedOrMalformed(pos));
    }
    pos += sid_len;

    // Cipher suites
    let cs_len = read_u16(buf, &mut pos)? as usize;
    if cs_len % 2 != 0 || pos + cs_len > record_end {
        return Err(Ja4ParseError::TruncatedOrMalformed(pos));
    }
    let cs_end = pos + cs_len;
    let mut ciphers = Vec::with_capacity(cs_len / 2);
    let mut observed_grease = false;
    while pos < cs_end {
        let cs = read_u16(buf, &mut pos)?;
        if is_grease(cs) {
            observed_grease = true;
        } else {
            ciphers.push(cs);
        }
    }

    // Compression methods
    let comp_len = read_u8(buf, &mut pos)? as usize;
    if pos + comp_len > record_end {
        return Err(Ja4ParseError::TruncatedOrMalformed(pos));
    }
    pos += comp_len;

    // Extensions
    let mut highest_tls_ver = legacy_version;
    let mut sni: Option<String> = None;
    let mut first_alpn: Option<String> = None;
    let mut total_non_grease_exts = 0usize;
    let mut filtered_exts = Vec::new();
    let mut sig_algs = Vec::new();

    if pos + 2 <= record_end {
        let ext_total_len = read_u16(buf, &mut pos)? as usize;
        let ext_end = pos
            .checked_add(ext_total_len)
            .ok_or(Ja4ParseError::TruncatedOrMalformed(pos))?;
        if ext_end > record_end {
            return Err(Ja4ParseError::TruncatedOrMalformed(pos));
        }

        while pos + 4 <= ext_end {
            let ext_type = read_u16(buf, &mut pos)?;
            let ext_len = read_u16(buf, &mut pos)? as usize;
            if pos + ext_len > ext_end {
                return Err(Ja4ParseError::TruncatedOrMalformed(pos));
            }
            let ext_data = &buf[pos..pos + ext_len];
            pos += ext_len;

            if is_grease(ext_type) {
                observed_grease = true;
                continue;
            }
            total_non_grease_exts += 1;

            // Omit SNI (0x0000) and ALPN (0x0010) from ja4_c hash per FoxIO JA4 spec
            if ext_type != 0x0000 && ext_type != 0x0010 {
                filtered_exts.push(ext_type);
            }

            match ext_type {
                0x0000 => {
                    // SNI extension
                    if ext_data.len() >= 5 {
                        let name_type = ext_data[2];
                        let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                        if name_type == 0x00 && 5 + name_len <= ext_data.len() {
                            if let Ok(host) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                                sni = Some(host.to_string());
                            }
                        }
                    }
                }
                0x0010 => {
                    // ALPN extension
                    if ext_data.len() >= 3 {
                        let first_len = ext_data[2] as usize;
                        if 3 + first_len <= ext_data.len() {
                            if let Ok(proto) = std::str::from_utf8(&ext_data[3..3 + first_len]) {
                                first_alpn = Some(proto.to_string());
                            }
                        }
                    }
                }
                0x002b => {
                    // supported_versions extension
                    if !ext_data.is_empty() {
                        let list_len = ext_data[0] as usize;
                        let mut p = 1usize;
                        let limit = (1 + list_len).min(ext_data.len());
                        let mut best = 0u16;
                        while p + 1 < limit {
                            let v = u16::from_be_bytes([ext_data[p], ext_data[p + 1]]);
                            if !is_grease(v) && v > best {
                                best = v;
                            }
                            p += 2;
                        }
                        if best > 0 {
                            highest_tls_ver = best;
                        }
                    }
                }
                0x000d => {
                    // signature_algorithms extension (keep original wire order)
                    if ext_data.len() >= 2 {
                        let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        let mut p = 2usize;
                        let limit = (2 + list_len).min(ext_data.len());
                        while p + 1 < limit {
                            let alg = u16::from_be_bytes([ext_data[p], ext_data[p + 1]]);
                            sig_algs.push(format!("{:04x}", alg));
                            p += 2;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let cipher_count = ciphers.len().min(99) as u8;
    let extension_count = total_non_grease_exts.min(99) as u8;
    let sni_char = if sni.is_some() { 'd' } else { 'i' };
    let ver_str = tls_version_label(highest_tls_ver);
    let alpn_tag = format_alpn_tag(first_alpn.as_deref());

    let ja4_a = format!(
        "t{}{}{:02}{:02}{}",
        ver_str, sni_char, cipher_count, extension_count, alpn_tag
    );

    ciphers.sort_unstable();
    let raw_ciphers: Vec<String> = ciphers.iter().map(|c| format!("{:04x}", c)).collect();
    let ja4_b_raw = raw_ciphers.join(",");
    let ja4_b = sha256_12(&ja4_b_raw);

    filtered_exts.sort_unstable();
    let raw_exts: Vec<String> = filtered_exts.iter().map(|e| format!("{:04x}", e)).collect();
    let ext_part = raw_exts.join(",");
    let sig_part = sig_algs.join(",");
    let ja4_c_raw = if sig_part.is_empty() {
        ext_part.clone()
    } else {
        format!("{}_{}", ext_part, sig_part)
    };
    let ja4_c = if ext_part.is_empty() && sig_part.is_empty() {
        "000000000000".to_string()
    } else {
        sha256_12(&ja4_c_raw)
    };

    Ok(Ja4Fingerprint {
        ja4: format!("{}_{}_{}", ja4_a, ja4_b, ja4_c),
        ja4_raw: format!("{}_{}_{}", ja4_a, ja4_b_raw, ja4_c_raw),
        sni,
        first_alpn,
        cipher_count,
        extension_count,
        observed_grease,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x2a2a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x002b));
    }

    #[test]
    fn test_synthetic_tls13_client_hello_with_sni_alpn_and_grease() {
        // Construct deterministic minimal ClientHello packet
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // Legacy TLS 1.2
        body.extend_from_slice(&[0xaa; 32]); // Random
        body.push(0x00); // Session ID len 0

        // Ciphers: GREASE 0x0a0a, TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&0x0a0au16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());

        // Compression: null
        body.push(1);
        body.push(0);

        // Extensions
        let mut exts = Vec::new();
        // GREASE extension 0x3a3a
        exts.extend_from_slice(&0x3a3au16.to_be_bytes());
        exts.extend_from_slice(&0u16.to_be_bytes());

        // SNI (0x0000): "originzero.art" (14 bytes)
        let host = b"originzero.art";
        let sni_entry_len = (1 + 2 + host.len()) as u16;
        let sni_ext_len = 2 + sni_entry_len;
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&sni_ext_len.to_be_bytes());
        exts.extend_from_slice(&sni_entry_len.to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&(host.len() as u16).to_be_bytes());
        exts.extend_from_slice(host);

        // ALPN (0x0010): "h2"
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&5u16.to_be_bytes()); // ext len
        exts.extend_from_slice(&3u16.to_be_bytes()); // list len
        exts.push(2);
        exts.extend_from_slice(b"h2");

        // supported_versions (0x002b): 0x0304 (TLS 1.3)
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.push(2);
        exts.extend_from_slice(&0x0304u16.to_be_bytes());

        // signature_algorithms (0x000d): 0x0403, 0x0804
        exts.extend_from_slice(&0x000du16.to_be_bytes());
        exts.extend_from_slice(&6u16.to_be_bytes());
        exts.extend_from_slice(&4u16.to_be_bytes());
        exts.extend_from_slice(&0x0403u16.to_be_bytes());
        exts.extend_from_slice(&0x0804u16.to_be_bytes());

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header
        let hs_len = body.len() as u32;
        let mut hs = vec![0x01, ((hs_len >> 16) & 0xff) as u8, ((hs_len >> 8) & 0xff) as u8, (hs_len & 0xff) as u8];
        hs.extend_from_slice(&body);

        // Record header
        let mut pkt = vec![0x16, 0x03, 0x01];
        pkt.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&hs);

        let parsed = parse_client_hello_ja4(&pkt).expect("valid ClientHello");
        assert!(parsed.observed_grease);
        assert_eq!(parsed.sni.as_deref(), Some("originzero.art"));
        assert_eq!(parsed.first_alpn.as_deref(), Some("h2"));
        assert_eq!(parsed.cipher_count, 2); // 0x1301, 0x1302 (GREASE excluded)
        assert_eq!(parsed.extension_count, 4); // SNI, ALPN, supported_versions, sig_algs (GREASE excluded)
        assert!(parsed.ja4.starts_with("t13d0204h2_"));
        assert!(parsed.ja4_raw.contains("1301,1302_000d,002b_0403,0804"));
    }

    #[test]
    fn test_plain_http_rejected_cleanly_without_panic() {
        let http_get = b"GET / HTTP/1.1\r\nHost: originzero.art\r\n\r\n";
        assert_eq!(parse_client_hello_ja4(http_get), Err(Ja4ParseError::NotTlsHandshake));
    }

    #[test]
    fn test_malformed_truncated_packet_never_panics() {
        let fuzz = vec![0x16, 0x03, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00, 0xfa, 0x03, 0x03];
        assert!(matches!(
            parse_client_hello_ja4(&fuzz),
            Err(Ja4ParseError::TruncatedOrMalformed(_))
        ));
    }
}
