// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! C2PA JUMBF Manifest Schema & Offline Signature Verification (Apache-2.0).
//! Decodes ISO/IEC 19566-5 JUMBF superboxes (both JSON envelope and native
//! RFC 8949 CBOR + RFC 9052 `COSE_Sign1` boxes with RFC 9360 `x5chain`) and
//! verifies Ed25519 / ECDSA P-256 signatures against asset content hashes
//! completely offline with zero SaaS dependencies.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePublicKey as EdDecodePublicKey, EncodePublicKey as EdEncodePublicKey};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey, Verifier};
use p256::ecdsa::signature::Verifier as P256Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey as P256DecodePublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cbor_cose::{
    cose_sig_structure, decode_cbor, decode_cose_sign1, encode_cbor, extract_x509_spki_from_der,
    CborValue, COSE_ALG_EDDSA, COSE_ALG_ES256,
};
use crate::container::C2PA_JUMBF_UUID;

/// Supported JUMBF claim serialization formats.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ManifestFormat {
    Json,
    Cose,
}

/// Signing algorithm identifier stored in the originZero.Art C2PA envelope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgorithm {
    Ed25519,
    Es256,
}

/// Core human authorship & provenance claim signed inside the C2PA manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginManifestClaim {
    pub spec_version: String,
    pub claim_generator: String,
    pub creator_name: String,
    pub creator_url: String,
    pub title: Option<String>,
    pub actions: Vec<String>,
    pub tdm_reservation: bool,
    pub tdm_policy: String,
    pub asset_sha256: String,
    pub created_utc: String,
}

/// Serialized signed provenance envelope embedded within the JUMBF payload box.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedProvenanceEnvelope {
    pub alg: SigningAlgorithm,
    pub public_key_pem: String,
    pub certificate_pem: Option<String>,
    /// Canonical JSON bytes (compact deterministic serialization) of `OriginManifestClaim`.
    pub claim_json: String,
    /// Base64-encoded cryptographic signature over `claim_json.as_bytes()`.
    pub signature_b64: String,
}

#[derive(Debug, Error)]
pub enum ProvenanceError {
    #[error("invalid JUMBF superbox header or UUID mismatch")]
    InvalidJumbfBox,
    #[error("malformed provenance envelope JSON: {0}")]
    InvalidEnvelope(String),
    #[error("malformed CBOR/COSE provenance structure: {0}")]
    InvalidCose(String),
    #[error("cryptographic signature invalid or tampered")]
    SignatureInvalid,
    #[error("asset content SHA-256 mismatch: expected {expected}, computed {actual}")]
    ContentHashMismatch { expected: String, actual: String },
    #[error("invalid public key or certificate encoding: {0}")]
    InvalidKey(String),
}

fn build_jumd_box(uuid: &[u8; 16], label: &str) -> Vec<u8> {
    let mut label_bytes = label.as_bytes().to_vec();
    label_bytes.push(0x00);
    let jumd_size = (8 + 16 + 1 + label_bytes.len()) as u32;
    let mut jumd = Vec::with_capacity(jumd_size as usize);
    jumd.extend_from_slice(&jumd_size.to_be_bytes());
    jumd.extend_from_slice(b"jumd");
    jumd.extend_from_slice(uuid);
    jumd.push(0x03); // Requestable + Label Present
    jumd.extend_from_slice(&label_bytes);
    jumd
}

fn wrap_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = (8 + payload.len()) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(fourcc);
    out.extend_from_slice(payload);
    out
}

/// Decodes a PEM `CERTIFICATE` block to raw DER bytes cleanly.
pub fn decode_pem_certificate_der(cert_pem: &str) -> Result<Vec<u8>, ProvenanceError> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let s = cert_pem
        .find(begin)
        .ok_or_else(|| ProvenanceError::InvalidKey("missing BEGIN CERTIFICATE header".into()))?;
    let rest = &cert_pem[s + begin.len()..];
    let e = rest
        .find(end)
        .ok_or_else(|| ProvenanceError::InvalidKey("missing END CERTIFICATE footer".into()))?;
    let b64_clean: String = rest[..e].chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(b64_clean.as_bytes())
        .map_err(|err| ProvenanceError::InvalidKey(format!("base64 cert decode: {}", err)))
}

/// Packs a `SignedProvenanceEnvelope` inside an ISO/IEC 19566-5 JUMBF superbox (`jumb` + `jumd` + `json`).
pub fn encode_jumbf_superbox(envelope: &SignedProvenanceEnvelope) -> Result<Vec<u8>, serde_json::Error> {
    let json_bytes = serde_json::to_vec(envelope)?;
    let jumd = build_jumd_box(&C2PA_JUMBF_UUID, "c2pa");
    let cbox = wrap_box(b"json", &json_bytes);

    let mut children = Vec::with_capacity(jumd.len() + cbox.len());
    children.extend_from_slice(&jumd);
    children.extend_from_slice(&cbox);
    Ok(wrap_box(b"jumb", &children))
}

/// Encodes `OriginManifestClaim` deterministically as an RFC 8949 CBOR map.
pub fn encode_claim_cbor(claim: &OriginManifestClaim) -> Vec<u8> {
    let mut entries = vec![
        (CborValue::Text("spec_version".into()), CborValue::Text(claim.spec_version.clone())),
        (CborValue::Text("claim_generator".into()), CborValue::Text(claim.claim_generator.clone())),
        (CborValue::Text("creator_name".into()), CborValue::Text(claim.creator_name.clone())),
        (CborValue::Text("creator_url".into()), CborValue::Text(claim.creator_url.clone())),
        (
            CborValue::Text("title".into()),
            match &claim.title {
                Some(t) => CborValue::Text(t.clone()),
                None => CborValue::Null,
            },
        ),
        (
            CborValue::Text("actions".into()),
            CborValue::Array(claim.actions.iter().map(|a| CborValue::Text(a.clone())).collect()),
        ),
        (CborValue::Text("tdm_reservation".into()), CborValue::Bool(claim.tdm_reservation)),
        (CborValue::Text("tdm_policy".into()), CborValue::Text(claim.tdm_policy.clone())),
        (CborValue::Text("asset_sha256".into()), CborValue::Text(claim.asset_sha256.clone())),
        (CborValue::Text("created_utc".into()), CborValue::Text(claim.created_utc.clone())),
    ];
    encode_cbor(&CborValue::Map(std::mem::take(&mut entries)))
}

/// Decodes a canonical CBOR claim map back into `OriginManifestClaim`.
pub fn decode_claim_cbor(raw: &[u8]) -> Result<OriginManifestClaim, ProvenanceError> {
    let val = decode_cbor(raw).map_err(|e| ProvenanceError::InvalidCose(e.to_string()))?;
    let map = match val {
        CborValue::Map(m) => m,
        _ => return Err(ProvenanceError::InvalidCose("claim CBOR must be map".into())),
    };

    let get_str = |key: &str| -> Option<String> {
        map.iter().find_map(|(k, v)| match (k, v) {
            (CborValue::Text(ks), CborValue::Text(vs)) if ks == key => Some(vs.clone()),
            _ => None,
        })
    };
    let title = map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(ks), CborValue::Text(vs)) if ks == "title" => Some(Some(vs.clone())),
        (CborValue::Text(ks), CborValue::Null) if ks == "title" => Some(None),
        _ => None,
    }).flatten();
    let actions = map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(ks), CborValue::Array(arr)) if ks == "actions" => Some(
            arr.iter()
                .filter_map(|x| match x {
                    CborValue::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        ),
        _ => None,
    }).unwrap_or_default();
    let tdm_reservation = map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(ks), CborValue::Bool(b)) if ks == "tdm_reservation" => Some(*b),
        _ => None,
    }).unwrap_or(true);

    Ok(OriginManifestClaim {
        spec_version: get_str("spec_version").ok_or_else(|| ProvenanceError::InvalidCose("missing spec_version".into()))?,
        claim_generator: get_str("claim_generator").ok_or_else(|| ProvenanceError::InvalidCose("missing claim_generator".into()))?,
        creator_name: get_str("creator_name").ok_or_else(|| ProvenanceError::InvalidCose("missing creator_name".into()))?,
        creator_url: get_str("creator_url").ok_or_else(|| ProvenanceError::InvalidCose("missing creator_url".into()))?,
        title,
        actions,
        tdm_reservation,
        tdm_policy: get_str("tdm_policy").ok_or_else(|| ProvenanceError::InvalidCose("missing tdm_policy".into()))?,
        asset_sha256: get_str("asset_sha256").ok_or_else(|| ProvenanceError::InvalidCose("missing asset_sha256".into()))?,
        created_utc: get_str("created_utc").ok_or_else(|| ProvenanceError::InvalidCose("missing created_utc".into()))?,
    })
}

/// Packs C2PA 2.1 `c2pa.claim` CBOR + `c2pa.signature` COSE_Sign1 inside an ISO/IEC 19566-5 JUMBF superbox.
pub fn encode_cose_jumbf_superbox(claim_cbor: &[u8], cose_sign1: &[u8]) -> Vec<u8> {
    let outer_jumd = build_jumd_box(&C2PA_JUMBF_UUID, "c2pa");

    let mut claim_inner = Vec::new();
    claim_inner.extend_from_slice(&build_jumd_box(&C2PA_JUMBF_UUID, "c2pa.claim"));
    claim_inner.extend_from_slice(&wrap_box(b"cbor", claim_cbor));
    let claim_superbox = wrap_box(b"jumb", &claim_inner);

    let mut sig_inner = Vec::new();
    sig_inner.extend_from_slice(&build_jumd_box(&C2PA_JUMBF_UUID, "c2pa.signature"));
    sig_inner.extend_from_slice(&wrap_box(b"cbor", cose_sign1));
    let sig_superbox = wrap_box(b"jumb", &sig_inner);

    let mut children = Vec::with_capacity(outer_jumd.len() + claim_superbox.len() + sig_superbox.len());
    children.extend_from_slice(&outer_jumd);
    children.extend_from_slice(&claim_superbox);
    children.extend_from_slice(&sig_superbox);
    wrap_box(b"jumb", &children)
}

/// Decodes an ISO/IEC 19566-5 JUMBF superbox into a `SignedProvenanceEnvelope` (JSON legacy path).
pub fn decode_jumbf_superbox(jumb: &[u8]) -> Result<SignedProvenanceEnvelope, ProvenanceError> {
    if jumb.len() < 8 || &jumb[4..8] != b"jumb" {
        return Err(ProvenanceError::InvalidJumbfBox);
    }
    let declared_len = u32::from_be_bytes([jumb[0], jumb[1], jumb[2], jumb[3]]) as usize;
    if declared_len > jumb.len() || declared_len < 8 {
        return Err(ProvenanceError::InvalidJumbfBox);
    }

    let mut pos = 8usize;
    let mut verified_uuid = false;
    let mut envelope_json: Option<&[u8]> = None;

    while pos + 8 <= declared_len {
        let box_len = u32::from_be_bytes([jumb[pos], jumb[pos + 1], jumb[pos + 2], jumb[pos + 3]]) as usize;
        let box_type = &jumb[pos + 4..pos + 8];
        if box_len < 8 || pos + box_len > declared_len {
            return Err(ProvenanceError::InvalidJumbfBox);
        }
        let body = &jumb[pos + 8..pos + box_len];

        if box_type == b"jumd" && body.len() >= 16 && body[..16] == C2PA_JUMBF_UUID {
            verified_uuid = true;
        } else if box_type == b"json" {
            envelope_json = Some(body);
        }

        pos += box_len;
    }

    if !verified_uuid {
        return Err(ProvenanceError::InvalidJumbfBox);
    }
    let raw_json = envelope_json.ok_or(ProvenanceError::InvalidJumbfBox)?;
    serde_json::from_slice(raw_json)
        .map_err(|e| ProvenanceError::InvalidEnvelope(e.to_string()))
}

fn parse_child_superbox_cbor(box_bytes: &[u8]) -> Result<(String, &[u8]), ProvenanceError> {
    if box_bytes.len() < 8 || &box_bytes[4..8] != b"jumb" {
        return Err(ProvenanceError::InvalidJumbfBox);
    }
    let declared = u32::from_be_bytes([box_bytes[0], box_bytes[1], box_bytes[2], box_bytes[3]]) as usize;
    if declared > box_bytes.len() || declared < 8 {
        return Err(ProvenanceError::InvalidJumbfBox);
    }
    let mut pos = 8usize;
    let mut label = String::new();
    let mut cbor_payload: Option<&[u8]> = None;
    while pos + 8 <= declared {
        let blen = u32::from_be_bytes([box_bytes[pos], box_bytes[pos + 1], box_bytes[pos + 2], box_bytes[pos + 3]]) as usize;
        let btype = &box_bytes[pos + 4..pos + 8];
        if blen < 8 || pos + blen > declared {
            return Err(ProvenanceError::InvalidJumbfBox);
        }
        let body = &box_bytes[pos + 8..pos + blen];
        if btype == b"jumd" && body.len() > 17 {
            let lbl_raw = &body[17..];
            let end = lbl_raw.iter().position(|&b| b == 0).unwrap_or(lbl_raw.len());
            label = String::from_utf8_lossy(&lbl_raw[..end]).to_string();
        } else if btype == b"cbor" {
            cbor_payload = Some(body);
        }
        pos += blen;
    }
    let payload = cbor_payload.ok_or(ProvenanceError::InvalidJumbfBox)?;
    Ok((label, payload))
}

/// Verifies either a JSON JUMBF manifest OR a native CBOR + COSE_Sign1 JUMBF manifest (`x5chain` bound).
pub fn verify_jumbf_superbox_any(
    jumb: &[u8],
    computed_asset_sha256: &str,
) -> Result<(SigningAlgorithm, OriginManifestClaim), ProvenanceError> {
    if let Ok(env) = decode_jumbf_superbox(jumb) {
        let alg = env.alg;
        let claim = verify_provenance_envelope(&env, computed_asset_sha256)?;
        return Ok((alg, claim));
    }

    // Native CBOR + COSE_Sign1 path (`c2pa.claim` + `c2pa.signature`)
    if jumb.len() < 8 || &jumb[4..8] != b"jumb" {
        return Err(ProvenanceError::InvalidJumbfBox);
    }
    let declared_len = u32::from_be_bytes([jumb[0], jumb[1], jumb[2], jumb[3]]) as usize;
    if declared_len > jumb.len() || declared_len < 8 {
        return Err(ProvenanceError::InvalidJumbfBox);
    }
    let mut pos = 8usize;
    let mut verified_uuid = false;
    let mut claim_cbor: Option<&[u8]> = None;
    let mut sig_cbor: Option<&[u8]> = None;

    while pos + 8 <= declared_len {
        let box_len = u32::from_be_bytes([jumb[pos], jumb[pos + 1], jumb[pos + 2], jumb[pos + 3]]) as usize;
        let box_type = &jumb[pos + 4..pos + 8];
        if box_len < 8 || pos + box_len > declared_len {
            return Err(ProvenanceError::InvalidJumbfBox);
        }
        let full_child = &jumb[pos..pos + box_len];
        let body = &jumb[pos + 8..pos + box_len];
        if box_type == b"jumd" && body.len() >= 16 && body[..16] == C2PA_JUMBF_UUID {
            verified_uuid = true;
        } else if box_type == b"jumb" {
            if let Ok((lbl, payload)) = parse_child_superbox_cbor(full_child) {
                if lbl == "c2pa.claim" {
                    claim_cbor = Some(payload);
                } else if lbl == "c2pa.signature" {
                    sig_cbor = Some(payload);
                }
            }
        }
        pos += box_len;
    }

    if !verified_uuid {
        return Err(ProvenanceError::InvalidJumbfBox);
    }
    let raw_claim = claim_cbor.ok_or(ProvenanceError::InvalidJumbfBox)?;
    let raw_sig = sig_cbor.ok_or(ProvenanceError::InvalidJumbfBox)?;
    let cose = decode_cose_sign1(raw_sig).map_err(|e| ProvenanceError::InvalidCose(e.to_string()))?;

    if cose.payload_bstr != raw_claim {
        return Err(ProvenanceError::InvalidCose("COSE payload bytes mismatch c2pa.claim box".into()));
    }

    let sig_struct = cose_sig_structure(&cose.protected_bstr, &cose.payload_bstr);
    let alg_enum = match cose.alg {
        COSE_ALG_EDDSA => {
            let vk = if let Some(ref der) = cose.x5chain_leaf_der {
                let spki = extract_x509_spki_from_der(der)
                    .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?;
                <EdVerifyingKey as EdDecodePublicKey>::from_public_key_der(spki)
                    .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?
            } else if let Some(ref pem) = cose.fallback_pub_pem {
                <EdVerifyingKey as EdDecodePublicKey>::from_public_key_pem(pem)
                    .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?
            } else {
                return Err(ProvenanceError::InvalidKey("COSE_Sign1 lacks x5chain or fallback public key".into()));
            };
            let sig = EdSignature::from_slice(&cose.signature_bstr)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            vk.verify(&sig_struct, &sig)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            SigningAlgorithm::Ed25519
        }
        COSE_ALG_ES256 => {
            let vk = if let Some(ref der) = cose.x5chain_leaf_der {
                let spki = extract_x509_spki_from_der(der)
                    .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?;
                <P256VerifyingKey as P256DecodePublicKey>::from_public_key_der(spki)
                    .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?
            } else if let Some(ref pem) = cose.fallback_pub_pem {
                <P256VerifyingKey as P256DecodePublicKey>::from_public_key_pem(pem)
                    .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?
            } else {
                return Err(ProvenanceError::InvalidKey("COSE_Sign1 lacks x5chain or fallback public key".into()));
            };
            let sig = P256Signature::from_slice(&cose.signature_bstr)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            P256Verifier::verify(&vk, &sig_struct, &sig)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            SigningAlgorithm::Es256
        }
        other => {
            return Err(ProvenanceError::InvalidCose(format!("unsupported COSE alg {}", other)));
        }
    };

    let claim = decode_claim_cbor(raw_claim)?;
    if claim.asset_sha256 != computed_asset_sha256 {
        return Err(ProvenanceError::ContentHashMismatch {
            expected: claim.asset_sha256,
            actual: computed_asset_sha256.to_string(),
        });
    }

    Ok((alg_enum, claim))
}

fn check_cert_spki_binding(cert_pem: &str, key_spki_der: &[u8]) -> Result<(), ProvenanceError> {
    let cert_der = decode_pem_certificate_der(cert_pem)?;
    let cert_spki = extract_x509_spki_from_der(&cert_der)
        .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?;
    if cert_spki != key_spki_der {
        return Err(ProvenanceError::InvalidKey(
            "embedded certificate SPKI does not match signing public key".into(),
        ));
    }
    Ok(())
}

/// Verifies cryptographic signature, optional X.509 cert SPKI binding, AND asset content-binding SHA-256 digest.
pub fn verify_provenance_envelope(
    envelope: &SignedProvenanceEnvelope,
    computed_asset_sha256: &str,
) -> Result<OriginManifestClaim, ProvenanceError> {
    let claim: OriginManifestClaim = serde_json::from_str(&envelope.claim_json)
        .map_err(|e| ProvenanceError::InvalidEnvelope(e.to_string()))?;

    let sig_bytes = B64
        .decode(envelope.signature_b64.as_bytes())
        .map_err(|_| ProvenanceError::SignatureInvalid)?;

    let key_spki_der = match envelope.alg {
        SigningAlgorithm::Ed25519 => {
            let vk = <EdVerifyingKey as EdDecodePublicKey>::from_public_key_pem(&envelope.public_key_pem)
                .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?;
            let sig = EdSignature::from_slice(&sig_bytes)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            vk.verify(envelope.claim_json.as_bytes(), &sig)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            vk.to_public_key_der()
                .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?
        }
        SigningAlgorithm::Es256 => {
            let vk = <P256VerifyingKey as P256DecodePublicKey>::from_public_key_pem(&envelope.public_key_pem)
                .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?;
            let sig = P256Signature::from_slice(&sig_bytes)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            vk.verify(envelope.claim_json.as_bytes(), &sig)
                .map_err(|_| ProvenanceError::SignatureInvalid)?;
            vk.to_public_key_der()
                .map_err(|e| ProvenanceError::InvalidKey(e.to_string()))?
        }
    };

    if let Some(ref cert_pem) = envelope.certificate_pem {
        check_cert_spki_binding(cert_pem, key_spki_der.as_bytes())?;
    }

    if claim.asset_sha256 != computed_asset_sha256 {
        return Err(ProvenanceError::ContentHashMismatch {
            expected: claim.asset_sha256,
            actual: computed_asset_sha256.to_string(),
        });
    }

    Ok(claim)
}
