// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Minimal deterministic RFC 8949 CBOR, RFC 9052 `COSE_Sign1`, and X.509 DER SPKI extractor (`Apache-2.0`).
//! Keeps `zero-origin-common` and `zero-origin-verify` 100% pure-Rust without C/FFI dependencies.

use thiserror::Error;

/// COSE Header parameter IDs (RFC 9052 / RFC 9360).
pub const COSE_HDR_ALG: i64 = 1;
pub const COSE_HDR_X5CHAIN: i64 = 33;

/// COSE Algorithm IDs (IANA COSE Algorithms Registry).
pub const COSE_ALG_ES256: i64 = -7;
pub const COSE_ALG_EDDSA: i64 = -8;

/// CBOR Tag for `COSE_Sign1` (RFC 9052 Section 4.2).
pub const CBOR_TAG_COSE_SIGN1: u64 = 18;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CborError {
    #[error("unexpected end of CBOR buffer")]
    UnexpectedEof,
    #[error("unsupported or invalid CBOR major type / additional info: {0}")]
    UnsupportedType(u8),
    #[error("invalid UTF-8 text string in CBOR")]
    InvalidUtf8,
    #[error("CBOR nesting exceeds maximum safe depth")]
    RecursionLimit,
    #[error("invalid COSE_Sign1 structure: {0}")]
    InvalidCose(String),
    #[error("invalid X.509 DER certificate structure")]
    InvalidDerCert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Tag(u64, Box<CborValue>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCoseSign1 {
    pub alg: i64,
    pub protected_bstr: Vec<u8>,
    pub payload_bstr: Vec<u8>,
    pub signature_bstr: Vec<u8>,
    pub x5chain_leaf_der: Option<Vec<u8>>,
    pub fallback_pub_pem: Option<String>,
}

fn push_type_arg(out: &mut Vec<u8>, major: u8, val: u64) {
    let mt = major << 5;
    if val < 24 {
        out.push(mt | (val as u8));
    } else if val <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(val as u8);
    } else if val <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&val.to_be_bytes());
    }
}

pub fn encode_cbor(val: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_cbor_into(val, &mut out);
    out
}

fn encode_cbor_into(val: &CborValue, out: &mut Vec<u8>) {
    match val {
        CborValue::Int(n) => {
            if *n >= 0 {
                push_type_arg(out, 0, *n as u64);
            } else {
                // RFC 8949 negative int encodes `-1 - n`
                let enc = (-1i128 - (*n as i128)) as u64;
                push_type_arg(out, 1, enc);
            }
        }
        CborValue::Bytes(b) => {
            push_type_arg(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        CborValue::Text(s) => {
            push_type_arg(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        CborValue::Array(items) => {
            push_type_arg(out, 4, items.len() as u64);
            for it in items {
                encode_cbor_into(it, out);
            }
        }
        CborValue::Map(entries) => {
            push_type_arg(out, 5, entries.len() as u64);
            for (k, v) in entries {
                encode_cbor_into(k, out);
                encode_cbor_into(v, out);
            }
        }
        CborValue::Tag(tag, inner) => {
            push_type_arg(out, 6, *tag);
            encode_cbor_into(inner, out);
        }
        CborValue::Bool(b) => {
            out.push(if *b { 0xf5 } else { 0xf4 });
        }
        CborValue::Null => {
            out.push(0xf6);
        }
    }
}

fn read_arg(data: &[u8], pos: &mut usize, addl: u8) -> Result<u64, CborError> {
    match addl {
        0..=23 => Ok(addl as u64),
        24 => {
            let b = *data.get(*pos).ok_or(CborError::UnexpectedEof)?;
            *pos += 1;
            Ok(b as u64)
        }
        25 => {
            let s = data.get(*pos..*pos + 2).ok_or(CborError::UnexpectedEof)?;
            *pos += 2;
            Ok(u16::from_be_bytes([s[0], s[1]]) as u64)
        }
        26 => {
            let s = data.get(*pos..*pos + 4).ok_or(CborError::UnexpectedEof)?;
            *pos += 4;
            Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64)
        }
        27 => {
            let s = data.get(*pos..*pos + 8).ok_or(CborError::UnexpectedEof)?;
            *pos += 8;
            Ok(u64::from_be_bytes([
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            ]))
        }
        other => Err(CborError::UnsupportedType(other)),
    }
}

pub fn decode_cbor(data: &[u8]) -> Result<CborValue, CborError> {
    let mut pos = 0usize;
    let val = decode_cbor_inner(data, &mut pos, 0)?;
    Ok(val)
}

fn decode_cbor_inner(data: &[u8], pos: &mut usize, depth: usize) -> Result<CborValue, CborError> {
    if depth > 32 {
        return Err(CborError::RecursionLimit);
    }
    let initial = *data.get(*pos).ok_or(CborError::UnexpectedEof)?;
    *pos += 1;
    let major = initial >> 5;
    let addl = initial & 0x1f;

    match major {
        0 => {
            let n = read_arg(data, pos, addl)?;
            i64::try_from(n)
                .map(CborValue::Int)
                .map_err(|_| CborError::UnsupportedType(initial))
        }
        1 => {
            let n = read_arg(data, pos, addl)?;
            let signed = -1i128 - (n as i128);
            i64::try_from(signed)
                .map(CborValue::Int)
                .map_err(|_| CborError::UnsupportedType(initial))
        }
        2 => {
            let len = read_arg(data, pos, addl)? as usize;
            let end = pos.checked_add(len).ok_or(CborError::UnexpectedEof)?;
            let slice = data.get(*pos..end).ok_or(CborError::UnexpectedEof)?;
            *pos = end;
            Ok(CborValue::Bytes(slice.to_vec()))
        }
        3 => {
            let len = read_arg(data, pos, addl)? as usize;
            let end = pos.checked_add(len).ok_or(CborError::UnexpectedEof)?;
            let slice = data.get(*pos..end).ok_or(CborError::UnexpectedEof)?;
            *pos = end;
            let s = std::str::from_utf8(slice).map_err(|_| CborError::InvalidUtf8)?;
            Ok(CborValue::Text(s.to_string()))
        }
        4 => {
            let len = (read_arg(data, pos, addl)? as usize).min(4096);
            let mut items = Vec::with_capacity(len.min(64));
            for _ in 0..len {
                items.push(decode_cbor_inner(data, pos, depth + 1)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => {
            let len = (read_arg(data, pos, addl)? as usize).min(4096);
            let mut entries = Vec::with_capacity(len.min(64));
            for _ in 0..len {
                let k = decode_cbor_inner(data, pos, depth + 1)?;
                let v = decode_cbor_inner(data, pos, depth + 1)?;
                entries.push((k, v));
            }
            Ok(CborValue::Map(entries))
        }
        6 => {
            let tag = read_arg(data, pos, addl)?;
            let inner = decode_cbor_inner(data, pos, depth + 1)?;
            Ok(CborValue::Tag(tag, Box::new(inner)))
        }
        7 => match addl {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            _ => Err(CborError::UnsupportedType(initial)),
        },
        _ => Err(CborError::UnsupportedType(initial)),
    }
}

/// Builds RFC 9052 `Sig_structure = ["Signature1", protected, external_aad(""), payload]`.
pub fn cose_sig_structure(protected_bstr: &[u8], payload_bstr: &[u8]) -> Vec<u8> {
    encode_cbor(&CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected_bstr.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload_bstr.to_vec()),
    ]))
}

pub fn encode_cose_sign1(
    alg: i64,
    x5chain_leaf_der: Option<&[u8]>,
    fallback_pub_pem: Option<&str>,
    payload_bstr: Vec<u8>,
    signer: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut prot_map = vec![(CborValue::Int(COSE_HDR_ALG), CborValue::Int(alg))];
    if let Some(cert_der) = x5chain_leaf_der {
        prot_map.push((
            CborValue::Int(COSE_HDR_X5CHAIN),
            CborValue::Array(vec![CborValue::Bytes(cert_der.to_vec())]),
        ));
    }
    let protected_bstr = encode_cbor(&CborValue::Map(prot_map));
    let to_be_signed = cose_sig_structure(&protected_bstr, &payload_bstr);
    let sig_bytes = signer(&to_be_signed);

    let mut unprot_map = Vec::new();
    if let Some(pem) = fallback_pub_pem {
        unprot_map.push((
            CborValue::Text("pub_pem".to_string()),
            CborValue::Text(pem.to_string()),
        ));
    }

    encode_cbor(&CborValue::Tag(
        CBOR_TAG_COSE_SIGN1,
        Box::new(CborValue::Array(vec![
            CborValue::Bytes(protected_bstr),
            CborValue::Map(unprot_map),
            CborValue::Bytes(payload_bstr),
            CborValue::Bytes(sig_bytes),
        ])),
    ))
}

pub fn decode_cose_sign1(raw: &[u8]) -> Result<DecodedCoseSign1, CborError> {
    let parsed = decode_cbor(raw)?;
    let arr = match parsed {
        CborValue::Tag(CBOR_TAG_COSE_SIGN1, inner) => match *inner {
            CborValue::Array(a) => a,
            _ => return Err(CborError::InvalidCose("tagged COSE_Sign1 is not an array".into())),
        },
        CborValue::Array(a) => a,
        _ => return Err(CborError::InvalidCose("expected CBOR Tag(18) Array(4)".into())),
    };
    if arr.len() != 4 {
        return Err(CborError::InvalidCose("COSE_Sign1 requires 4 elements".into()));
    }

    let protected_bstr = match &arr[0] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(CborError::InvalidCose("protected header must be bstr".into())),
    };
    let unprotected = match &arr[1] {
        CborValue::Map(m) => m,
        _ => return Err(CborError::InvalidCose("unprotected header must be map".into())),
    };
    let payload_bstr = match &arr[2] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(CborError::InvalidCose("payload must be bstr".into())),
    };
    let signature_bstr = match &arr[3] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(CborError::InvalidCose("signature must be bstr".into())),
    };

    let prot_val = decode_cbor(&protected_bstr)?;
    let prot_map = match prot_val {
        CborValue::Map(m) => m,
        _ => return Err(CborError::InvalidCose("protected bstr did not decode to map".into())),
    };

    let mut alg = None;
    let mut x5chain_leaf_der = None;
    for (k, v) in prot_map {
        match k {
            CborValue::Int(COSE_HDR_ALG) => {
                if let CborValue::Int(a) = v {
                    alg = Some(a);
                }
            }
            CborValue::Int(COSE_HDR_X5CHAIN) => match v {
                CborValue::Bytes(b) => x5chain_leaf_der = Some(b),
                CborValue::Array(items) => {
                    if let Some(CborValue::Bytes(first)) = items.into_iter().next() {
                        x5chain_leaf_der = Some(first);
                    }
                }
                _ => {}
            },
            CborValue::Text(ref s) if s == "x5chain" => match v {
                CborValue::Bytes(b) => x5chain_leaf_der = Some(b),
                CborValue::Array(items) => {
                    if let Some(CborValue::Bytes(first)) = items.into_iter().next() {
                        x5chain_leaf_der = Some(first);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    let mut fallback_pub_pem = None;
    for (k, v) in unprotected {
        if let (CborValue::Text(key), CborValue::Text(val)) = (k, v) {
            if key == "pub_pem" {
                fallback_pub_pem = Some(val.clone());
            }
        }
    }

    let alg_val = alg.ok_or_else(|| CborError::InvalidCose("missing alg header".into()))?;
    Ok(DecodedCoseSign1 {
        alg: alg_val,
        protected_bstr,
        payload_bstr,
        signature_bstr,
        x5chain_leaf_der,
        fallback_pub_pem,
    })
}

fn read_der_tlv(data: &[u8], pos: usize) -> Result<(u8, usize, usize), CborError> {
    let tag = *data.get(pos).ok_or(CborError::InvalidDerCert)?;
    let first_len = *data.get(pos + 1).ok_or(CborError::InvalidDerCert)?;
    let (len, val_start) = if (first_len & 0x80) == 0 {
        (first_len as usize, pos + 2)
    } else {
        let count = (first_len & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(CborError::InvalidDerCert);
        }
        let len_bytes = data
            .get(pos + 2..pos + 2 + count)
            .ok_or(CborError::InvalidDerCert)?;
        let mut l = 0usize;
        for &b in len_bytes {
            l = (l << 8) | (b as usize);
        }
        (l, pos + 2 + count)
    };
    let val_end = val_start.checked_add(len).ok_or(CborError::InvalidDerCert)?;
    if val_end > data.len() {
        return Err(CborError::InvalidDerCert);
    }
    Ok((tag, val_start, val_end))
}

/// Extracts the exact SubjectPublicKeyInfo (SPKI) DER byte slice from an RFC 5280 X.509 DER certificate.
pub fn extract_x509_spki_from_der(cert_der: &[u8]) -> Result<&[u8], CborError> {
    let (cert_tag, cert_val_start, _) = read_der_tlv(cert_der, 0)?;
    if cert_tag != 0x30 {
        return Err(CborError::InvalidDerCert);
    }
    // TBSCertificate is first child SEQUENCE inside Certificate
    let (tbs_tag, tbs_start, tbs_end) = read_der_tlv(cert_der, cert_val_start)?;
    if tbs_tag != 0x30 {
        return Err(CborError::InvalidDerCert);
    }
    let mut cur = tbs_start;
    let (tag0, _, end0) = read_der_tlv(cert_der, cur)?;
    // Skip optional [0] explicit version wrapper
    if tag0 == 0xa0 {
        cur = end0;
    }
    // Skip serialNumber, signature AlgId, issuer Name, validity, subject Name (5 TLV nodes)
    for _ in 0..5 {
        let (_, _, next_end) = read_der_tlv(cert_der, cur)?;
        cur = next_end;
    }
    if cur >= tbs_end {
        return Err(CborError::InvalidDerCert);
    }
    let (spki_tag, _, spki_end) = read_der_tlv(cert_der, cur)?;
    if spki_tag != 0x30 {
        return Err(CborError::InvalidDerCert);
    }
    Ok(&cert_der[cur..spki_end])
}
