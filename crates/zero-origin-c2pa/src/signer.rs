// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Lossless C2PA/JUMBF Manifest Signer & Container Injector (AGPL-3.0-or-later).
//! Injects signed JUMBF superboxes into JPEG (`APP11`), PNG (`caBX`),
//! WebP (`RIFF`/`C2PA`), and AVIF (`ISOBMFF` `uuid`) bit-exactly.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signer, SigningKey as EdSigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::LineEnding;
use thiserror::Error;
use zeroize::Zeroizing;

use zero_origin_common::cbor_cose::{encode_cose_sign1, COSE_ALG_EDDSA, COSE_ALG_ES256};
use zero_origin_common::container::{
    compute_sha256_hex, detect_format, ContainerError, MediaFormat, ISOBMFF_C2PA_UUID,
    JPEG_APP11_MARKER, JPEG_JUMBF_IDENT, PNG_C2PA_CHUNK, WEBP_C2PA_CHUNK,
};
use zero_origin_common::provenance::{
    decode_pem_certificate_der, encode_claim_cbor, encode_cose_jumbf_superbox,
    encode_jumbf_superbox, ManifestFormat, OriginManifestClaim, SignedProvenanceEnvelope,
    SigningAlgorithm,
};
use zero_origin_common::DEFAULT_TDM_LICENSE_URI;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("container format error: {0}")]
    Container(#[from] ContainerError),
    #[error("cryptographic signing failure: {0}")]
    Crypto(String),
    #[error("manifest serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Parameters provided by the human creator when signing an artwork.
pub struct SignParams {
    pub creator_name: String,
    pub creator_url: String,
    pub title: Option<String>,
    pub tdm_reservation: bool,
    pub tdm_policy: String,
    pub certificate_pem: Option<String>,
    pub manifest_format: ManifestFormat,
}

impl Default for SignParams {
    fn default() -> Self {
        Self {
            creator_name: "Human Creator".to_string(),
            creator_url: "https://originzero.art".to_string(),
            title: None,
            tdm_reservation: true,
            tdm_policy: DEFAULT_TDM_LICENSE_URI.to_string(),
            certificate_pem: None,
            manifest_format: ManifestFormat::Json,
        }
    }
}

/// Cryptographically signs raw media bytes using an Ed25519 or ECDSA P-256 PKCS#8 PEM key
/// and returns lossless container bytes embedding the JUMBF C2PA manifest.
pub fn sign_asset_bytes(
    raw_asset: &[u8],
    private_key_pem: &str,
    params: &SignParams,
) -> Result<Vec<u8>, SignerError> {
    let format = detect_format(raw_asset)?;
    let asset_sha256 = compute_sha256_hex(raw_asset);

    let claim = OriginManifestClaim {
        spec_version: "1.0-c2pa-compatible".to_string(),
        claim_generator: "zero-origin/0.1.0-mvp (originZero.Art)".to_string(),
        creator_name: params.creator_name.clone(),
        creator_url: params.creator_url.clone(),
        title: params.title.clone(),
        actions: vec!["c2pa.created".to_string()],
        tdm_reservation: params.tdm_reservation,
        tdm_policy: params.tdm_policy.clone(),
        asset_sha256,
        created_utc: Utc::now().to_rfc3339(),
    };

    let key_pem_buf = Zeroizing::new(private_key_pem.to_string());

    let jumb_box = match params.manifest_format {
        ManifestFormat::Json => {
            let claim_json = serde_json::to_string(&claim)?;
            let (alg, public_key_pem, signature_b64) =
                if let Ok(ed_sk) = EdSigningKey::from_pkcs8_pem(&key_pem_buf) {
                    let pub_pem = ed_sk
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| SignerError::Crypto(e.to_string()))?;
                    let sig = ed_sk.sign(claim_json.as_bytes());
                    (SigningAlgorithm::Ed25519, pub_pem, B64.encode(sig.to_bytes()))
                } else if let Ok(p256_sk) = P256SigningKey::from_pkcs8_pem(&key_pem_buf) {
                    let pub_pem = p256_sk
                        .verifying_key()
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| SignerError::Crypto(e.to_string()))?;
                    let sig: P256Signature = p256_sk.sign(claim_json.as_bytes());
                    (SigningAlgorithm::Es256, pub_pem, B64.encode(sig.to_bytes()))
                } else {
                    return Err(SignerError::Crypto(
                        "unsupported or invalid PKCS#8 PEM private key (expected Ed25519 or P-256)".to_string(),
                    ));
                };

            let envelope = SignedProvenanceEnvelope {
                alg,
                public_key_pem,
                certificate_pem: params.certificate_pem.clone(),
                claim_json,
                signature_b64,
            };
            encode_jumbf_superbox(&envelope)?
        }
        ManifestFormat::Cose => {
            let claim_cbor = encode_claim_cbor(&claim);
            let x5chain_der = match &params.certificate_pem {
                Some(pem) => Some(
                    decode_pem_certificate_der(pem)
                        .map_err(|e| SignerError::Crypto(e.to_string()))?,
                ),
                None => None,
            };

            let cose_bytes = if let Ok(ed_sk) = EdSigningKey::from_pkcs8_pem(&key_pem_buf) {
                let pub_pem = ed_sk
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|e| SignerError::Crypto(e.to_string()))?;
                let fallback = if x5chain_der.is_none() {
                    Some(pub_pem.as_str())
                } else {
                    None
                };
                encode_cose_sign1(
                    COSE_ALG_EDDSA,
                    x5chain_der.as_deref(),
                    fallback,
                    claim_cbor.clone(),
                    |tbs| ed_sk.sign(tbs).to_bytes().to_vec(),
                )
            } else if let Ok(p256_sk) = P256SigningKey::from_pkcs8_pem(&key_pem_buf) {
                let pub_pem = p256_sk
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|e| SignerError::Crypto(e.to_string()))?;
                let fallback = if x5chain_der.is_none() {
                    Some(pub_pem.as_str())
                } else {
                    None
                };
                encode_cose_sign1(
                    COSE_ALG_ES256,
                    x5chain_der.as_deref(),
                    fallback,
                    claim_cbor.clone(),
                    |tbs| {
                        let sig: P256Signature = p256_sk.sign(tbs);
                        sig.to_bytes().to_vec()
                    },
                )
            } else {
                return Err(SignerError::Crypto(
                    "unsupported or invalid PKCS#8 PEM private key (expected Ed25519 or P-256)".to_string(),
                ));
            };
            encode_cose_jumbf_superbox(&claim_cbor, &cose_bytes)
        }
    };

    match format {
        MediaFormat::Jpeg => inject_jpeg_app11(raw_asset, &jumb_box),
        MediaFormat::Png => inject_png_cabx(raw_asset, &jumb_box),
        MediaFormat::Webp => inject_webp_c2pa(raw_asset, &jumb_box),
        MediaFormat::Avif => inject_avif_uuid(raw_asset, &jumb_box),
    }
}

fn inject_jpeg_app11(data: &[u8], jumb: &[u8]) -> Result<Vec<u8>, SignerError> {
    if data.len() < 4 {
        return Err(SignerError::Container(ContainerError::MalformedContainer(0)));
    }
    // APP11 segment payload: "JP"(2) + En(2) + Seq(4) + jumb_bytes
    let payload_len = 8 + jumb.len();
    let seg_len = 2 + payload_len;
    if seg_len > u16::MAX as usize {
        return Err(SignerError::Crypto("JUMBF payload exceeds single APP11 segment size".to_string()));
    }

    let mut out = Vec::with_capacity(data.len() + 2 + seg_len);
    out.extend_from_slice(&data[..2]); // Keep FF D8 SOI intact
    out.extend_from_slice(&JPEG_APP11_MARKER);
    out.extend_from_slice(&(seg_len as u16).to_be_bytes());
    out.extend_from_slice(&JPEG_JUMBF_IDENT);
    out.extend_from_slice(&1u16.to_be_bytes()); // Box instance En = 1
    out.extend_from_slice(&1u32.to_be_bytes()); // Packet sequence = 1
    out.extend_from_slice(jumb);
    out.extend_from_slice(&data[2..]); // Remaining segments & SOS untouched
    Ok(out)
}

fn inject_png_cabx(data: &[u8], jumb: &[u8]) -> Result<Vec<u8>, SignerError> {
    // Walk chunks to insert caBX immediately before IEND
    let mut pos = 8usize;
    let mut iend_offset = None;
    while pos + 12 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let ctype = &data[pos + 4..pos + 8];
        let next = pos.checked_add(12 + len).ok_or(ContainerError::MalformedContainer(pos))?;
        if next > data.len() {
            return Err(SignerError::Container(ContainerError::MalformedContainer(pos)));
        }
        if ctype == b"IEND" {
            iend_offset = Some(pos);
            break;
        }
        pos = next;
    }

    let split_at = iend_offset.ok_or(ContainerError::MalformedContainer(pos))?;
    let mut crc = crc32fast::Hasher::new();
    crc.update(&PNG_C2PA_CHUNK);
    crc.update(jumb);
    let checksum = crc.finalize();

    let mut out = Vec::with_capacity(data.len() + 12 + jumb.len());
    out.extend_from_slice(&data[..split_at]);
    out.extend_from_slice(&(jumb.len() as u32).to_be_bytes());
    out.extend_from_slice(&PNG_C2PA_CHUNK);
    out.extend_from_slice(jumb);
    out.extend_from_slice(&checksum.to_be_bytes());
    out.extend_from_slice(&data[split_at..]);
    Ok(out)
}

fn inject_webp_c2pa(data: &[u8], jumb: &[u8]) -> Result<Vec<u8>, SignerError> {
    if data.len() < 12 {
        return Err(SignerError::Container(ContainerError::MalformedContainer(0)));
    }
    let orig_riff_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let pad = jumb.len() % 2;
    let added_chunk_total = 8 + jumb.len() + pad;
    let new_riff_size = (orig_riff_size + added_chunk_total) as u32;

    let mut out = Vec::with_capacity(data.len() + added_chunk_total);
    out.extend_from_slice(&data[..4]); // "RIFF"
    out.extend_from_slice(&new_riff_size.to_le_bytes());
    out.extend_from_slice(&data[8..]); // "WEBP" + original chunks
    out.extend_from_slice(&WEBP_C2PA_CHUNK);
    out.extend_from_slice(&(jumb.len() as u32).to_le_bytes());
    out.extend_from_slice(jumb);
    if pad == 1 {
        out.push(0x00);
    }
    Ok(out)
}

fn inject_avif_uuid(data: &[u8], jumb: &[u8]) -> Result<Vec<u8>, SignerError> {
    // Append post-mdat top-level UUID box so all preceding ftyp/meta/iloc/mdat offsets remain valid
    let box_len = (8 + 16 + jumb.len()) as u32;
    let mut out = Vec::with_capacity(data.len() + box_len as usize);
    out.extend_from_slice(data);
    out.extend_from_slice(&box_len.to_be_bytes());
    out.extend_from_slice(b"uuid");
    out.extend_from_slice(&ISOBMFF_C2PA_UUID);
    out.extend_from_slice(jumb);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_creator_identity;
    use zero_origin_verify::verify_asset_bytes;

    #[test]
    fn test_roundtrip_signing_and_tamper_detection_all_formats() {
        let id = generate_creator_identity(SigningAlgorithm::Ed25519, "Atelier Test", "originzero.art")
            .expect("keygen succeeds");
        let params = SignParams {
            creator_name: "Atelier Test".into(),
            creator_url: "https://originzero.art".into(),
            title: Some("Study in Gold & Obsidian".into()),
            certificate_pem: Some(id.certificate_pem.clone()),
            ..Default::default()
        };

        // 1. Minimal synthetic valid-header JPEG
        let jpeg = [0xffu8, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x01, 0x02, 0xff, 0xda, 0xaa, 0xbb, 0xff, 0xd9];
        let signed_jpeg = sign_asset_bytes(&jpeg, &id.private_key_pem, &params).unwrap();
        let report_jpg = verify_asset_bytes(&signed_jpeg).expect("JPEG must verify cleanly");
        assert_eq!(report_jpg.format, "JPEG");
        assert_eq!(report_jpg.claim.creator_name, "Atelier Test");

        // Tamper final scan byte -> MUST FAIL content hash verification
        let mut tampered_jpeg = signed_jpeg.clone();
        let last_idx = tampered_jpeg.len() - 3;
        tampered_jpeg[last_idx] ^= 0xff;
        assert!(verify_asset_bytes(&tampered_jpeg).is_err());

        // 2. Minimal synthetic PNG (Header + IHDR + IEND)
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&[0u8; 13]);
        png.extend_from_slice(&[0u8; 4]); // dummy crc for fixture
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]);

        let signed_png = sign_asset_bytes(&png, &id.private_key_pem, &params).unwrap();
        let report_png = verify_asset_bytes(&signed_png).expect("PNG must verify cleanly");
        assert_eq!(report_png.format, "PNG");

        // 3. Minimal synthetic WebP (RIFF + size(12) + WEBP + VP8 chunk)
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&12u32.to_le_bytes()); // "WEBP" (4) + chunk header (8)
        webp.extend_from_slice(b"WEBP");
        webp.extend_from_slice(b"VP8 ");
        webp.extend_from_slice(&0u32.to_le_bytes());
        let signed_webp = sign_asset_bytes(&webp, &id.private_key_pem, &params).unwrap();
        let report_webp = verify_asset_bytes(&signed_webp).expect("WebP must verify cleanly");
        assert_eq!(report_webp.format, "WebP");

        // 4. Minimal synthetic AVIF (ftypavif + mdat)
        let mut avif = Vec::new();
        avif.extend_from_slice(&16u32.to_be_bytes());
        avif.extend_from_slice(b"ftypavif");
        avif.extend_from_slice(&[0u8; 4]);
        avif.extend_from_slice(&12u32.to_be_bytes());
        avif.extend_from_slice(b"mdat");
        avif.extend_from_slice(&[1, 2, 3, 4]);
        let signed_avif = sign_asset_bytes(&avif, &id.private_key_pem, &params).unwrap();
        let report_avif = verify_asset_bytes(&signed_avif).expect("AVIF must verify cleanly");
        assert_eq!(report_avif.format, "AVIF");
    }

    #[test]
    fn test_es256_ecdsa_signing_roundtrip() {
        let id = generate_creator_identity(SigningAlgorithm::Es256, "Sculptor ECDSA", "originzero.art")
            .expect("ECDSA keygen succeeds");
        let params = SignParams {
            certificate_pem: Some(id.certificate_pem.clone()),
            ..Default::default()
        };
        let jpeg = [0xffu8, 0xd8, 0xff, 0xd9];
        let signed = sign_asset_bytes(&jpeg, &id.private_key_pem, &params).unwrap();
        let report = verify_asset_bytes(&signed).expect("ECDSA ES256 verifies cleanly");
        assert_eq!(report.algorithm, SigningAlgorithm::Es256);
    }

    #[test]
    fn test_cose_sign1_x5chain_ed25519_and_es256_roundtrip_and_tamper() {
        let ed_id = generate_creator_identity(SigningAlgorithm::Ed25519, "COSE Ed25519", "757.originzero.art")
            .expect("ed25519 keygen");
        let ec_id = generate_creator_identity(SigningAlgorithm::Es256, "COSE ES256", "spartan.originzero.art")
            .expect("es256 keygen");

        // PNG + Ed25519 COSE_Sign1 + x5chain
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&[0u8; 13]);
        png.extend_from_slice(&[0u8; 4]);
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]);

        let ed_params = SignParams {
            creator_name: "COSE Ed25519".into(),
            creator_url: "https://757.originzero.art".into(),
            title: Some("COSE Provenance Test".into()),
            certificate_pem: Some(ed_id.certificate_pem.clone()),
            manifest_format: ManifestFormat::Cose,
            ..Default::default()
        };
        let signed_png = sign_asset_bytes(&png, &ed_id.private_key_pem, &ed_params).unwrap();
        let rep = verify_asset_bytes(&signed_png).expect("COSE Ed25519 PNG must verify");
        assert_eq!(rep.algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(rep.format, "PNG");
        assert_eq!(rep.claim.creator_name, "COSE Ed25519");

        // AVIF + ES256 COSE_Sign1 + x5chain
        let mut avif = Vec::new();
        avif.extend_from_slice(&16u32.to_be_bytes());
        avif.extend_from_slice(b"ftypavif");
        avif.extend_from_slice(&[0u8; 4]);
        avif.extend_from_slice(&12u32.to_be_bytes());
        avif.extend_from_slice(b"mdat");
        avif.extend_from_slice(&[9, 8, 7, 6]);
        let ec_params = SignParams {
            creator_name: "COSE ES256".into(),
            creator_url: "https://spartan.originzero.art".into(),
            certificate_pem: Some(ec_id.certificate_pem.clone()),
            manifest_format: ManifestFormat::Cose,
            ..Default::default()
        };
        let signed_avif = sign_asset_bytes(&avif, &ec_id.private_key_pem, &ec_params).unwrap();
        let rep_ec = verify_asset_bytes(&signed_avif).expect("COSE ES256 AVIF must verify");
        assert_eq!(rep_ec.algorithm, SigningAlgorithm::Es256);
        assert_eq!(rep_ec.format, "AVIF");

        // Tamper 1 bit of AVIF pixel payload -> MUST FAIL content hash
        let mut tampered_avif = signed_avif.clone();
        tampered_avif[26] ^= 0x01;
        assert!(verify_asset_bytes(&tampered_avif).is_err());
    }

    #[test]
    fn test_mismatched_certificate_spki_rejected() {
        let real_id = generate_creator_identity(SigningAlgorithm::Ed25519, "Real", "757.originzero.art").unwrap();
        let rogue_id = generate_creator_identity(SigningAlgorithm::Ed25519, "Impersonator", "fake.example").unwrap();
        let params = SignParams {
            creator_name: "Impersonator".into(),
            certificate_pem: Some(rogue_id.certificate_pem.clone()), // mismatched cert!
            ..Default::default()
        };
        let jpeg = [0xffu8, 0xd8, 0xff, 0xd9];
        let forged = sign_asset_bytes(&jpeg, &real_id.private_key_pem, &params).unwrap();
        assert!(verify_asset_bytes(&forged).is_err(), "mismatched cert SPKI must fail verification");
    }
}
