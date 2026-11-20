// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! `zero-origin-verify` (Apache-2.0): Offline & HTTP client verification SDK.
//! Verifies embedded JUMBF/C2PA manifests (JSON envelope and CBOR/COSE_Sign1)
//! in JPEG, PNG, WebP, and AVIF media, plus HTTP response TDM Reservation,
//! IETF AIPREF `Content-Usage`, and RFC 8288 rights declarations.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zero_origin_common::container::{extract_jumbf, ContainerError, MediaFormat};
use zero_origin_common::provenance::{
    verify_jumbf_superbox_any, OriginManifestClaim, ProvenanceError, SigningAlgorithm,
};

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("container error: {0}")]
    Container(#[from] ContainerError),
    #[error("provenance error: {0}")]
    Provenance(#[from] ProvenanceError),
}

/// Unified human-readable & JSON verification result for creators and galleries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetVerifyReport {
    pub valid: bool,
    pub format: String,
    pub algorithm: SigningAlgorithm,
    pub content_sha256: String,
    pub claim: OriginManifestClaim,
    pub manifest_offset_start: usize,
    pub manifest_offset_end: usize,
}

/// Summary report when inspecting an HTTP URL's TDM headers & asset provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpRightsAuditReport {
    pub tdm_reservation: Option<String>,
    pub tdm_policy: Option<String>,
    pub content_usage: Option<String>,
    pub rfc8288_license_link: Option<String>,
    pub x_robots_tag: Option<String>,
    pub rights_enforced: bool,
}

/// Verifies an asset buffer completely offline with zero external network calls.
pub fn verify_asset_bytes(data: &[u8]) -> Result<AssetVerifyReport, VerifyError> {
    let extracted = extract_jumbf(data)?;
    let (algorithm, claim) =
        verify_jumbf_superbox_any(&extracted.jumb_bytes, &extracted.content_sha256_hex)?;

    let format_str = match extracted.format {
        MediaFormat::Jpeg => "JPEG",
        MediaFormat::Png => "PNG",
        MediaFormat::Webp => "WebP",
        MediaFormat::Avif => "AVIF",
    }
    .to_string();

    Ok(AssetVerifyReport {
        valid: true,
        format: format_str,
        algorithm,
        content_sha256: extracted.content_sha256_hex,
        claim,
        manifest_offset_start: extracted.manifest_span.0,
        manifest_offset_end: extracted.manifest_span.1,
    })
}

/// Evaluates HTTP response header key-value pairs for originZero.Art TDM opt-out compliance.
pub fn audit_http_rights_headers<'a, I>(headers: I) -> HttpRightsAuditReport
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut tdm_reservation = None;
    let mut tdm_policy = None;
    let mut content_usage = None;
    let mut rfc8288_license_link = None;
    let mut x_robots_tag = None;

    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        match lower.as_str() {
            "tdm-reservation" => tdm_reservation = Some(v.trim().to_string()),
            "tdm-policy" => tdm_policy = Some(v.trim().to_string()),
            "content-usage" => content_usage = Some(v.trim().to_string()),
            "link" if v.contains("rel=\"license\"") || v.contains("rel='license'") => {
                rfc8288_license_link = Some(v.trim().to_string());
            }
            "x-robots-tag" => x_robots_tag = Some(v.trim().to_string()),
            _ => {}
        }
    }

    let rights_enforced =
        tdm_reservation.as_deref() == Some("1") && rfc8288_license_link.is_some();

    HttpRightsAuditReport {
        tdm_reservation,
        tdm_policy,
        content_usage,
        rfc8288_license_link,
        x_robots_tag,
        rights_enforced,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_http_rights_headers_valid() {
        let hdrs = [
            ("TDM-Reservation", "1"),
            ("TDM-Policy", "https://originzero.art/license/tdm-reservation"),
            ("Content-Usage", "train-ai=n, search=y"),
            ("Link", "<https://originzero.art/license/tdm-reservation>; rel=\"license\""),
            ("X-Robots-Tag", "noai, noimageai"),
        ];
        let audit = audit_http_rights_headers(hdrs);
        assert!(audit.rights_enforced);
        assert_eq!(audit.tdm_reservation.as_deref(), Some("1"));
        assert_eq!(audit.content_usage.as_deref(), Some("train-ai=n, search=y"));
    }

    #[test]
    fn test_audit_http_rights_headers_missing_reservation() {
        let hdrs = [("Content-Type", "image/jpeg")];
        let audit = audit_http_rights_headers(hdrs);
        assert!(!audit.rights_enforced);
    }
}
