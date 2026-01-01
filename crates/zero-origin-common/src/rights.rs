// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Sovereign Creator Rights Protocol: EU DSM Directive 2019/790 Art. 4
//! TDM Reservations, RFC 8288 Web Linking headers, `/ai.txt`, and
//! `/.well-known/tdmrep.json`.

use serde::{Deserialize, Serialize};

/// Canonical creator rights policy attached to edge-proxied responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginRightsPolicy {
    /// Protected public domain (e.g. "originzero.art" or creator subdomain).
    pub domain: String,
    /// Human creator or collective display name.
    pub creator: String,
    /// Official contact email or URL for explicit commercial licensing inquiries.
    pub contact: String,
    /// Canonical TDM license URI emitted in RFC 8288 Link and TDM-Policy headers.
    pub license_uri: String,
    /// Enforce EU DSM Directive 2019/790 Art. 4 Text and Data Mining opt-out.
    pub tdm_reservation: bool,
    /// Disallow automated AI image / generative model training crawlers.
    pub forbid_ai_training: bool,
    /// Preserve standard web search engine indexing (Googlebot, Bingbot, etc.).
    pub allow_search_indexing: bool,
}

impl Default for OriginRightsPolicy {
    fn default() -> Self {
        Self {
            domain: "originzero.art".to_string(),
            creator: "originZero.Art Independent Creators".to_string(),
            contact: "mailto:contact@originzero.art".to_string(),
            license_uri: crate::DEFAULT_TDM_LICENSE_URI.to_string(),
            tdm_reservation: true,
            forbid_ai_training: true,
            allow_search_indexing: true,
        }
    }
}

/// W3C TDM Reservation Protocol JSON representation served at `/.well-known/tdmrep.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TdmRepDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub location: String,
    #[serde(rename = "tdm-reservation")]
    pub tdm_reservation: u8,
    #[serde(rename = "tdm-policy")]
    pub tdm_policy: String,
    pub creator: String,
    pub contact: String,
    pub directives: Vec<String>,
}

impl OriginRightsPolicy {
    /// Emits IETF AIPREF `Content-Usage` header token (`draft-ietf-aipref-vocab` / `attach`).
    pub fn content_usage_header(&self) -> String {
        let train = if self.forbid_ai_training { "n" } else { "y" };
        let search = if self.allow_search_indexing { "y" } else { "n" };
        format!("train-ai={}, search={}", train, search)
    }

    /// Emits HTTP headers enforcing RFC 8288 linking, EU TDM Art. 4 opt-out,
    /// IETF AIPREF `Content-Usage`, and crawler opt-out signaling.
    pub fn response_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::with_capacity(6);

        // RFC 8288 Web Linking to machine-readable license declaration
        headers.push(("Link", format!("<{}>; rel=\"license\"", self.license_uri)));

        // EU Directive 2019/790 Article 4 explicit Text & Data Mining reservation
        if self.tdm_reservation {
            headers.push(("TDM-Reservation", "1".to_string()));
            headers.push(("TDM-Policy", self.license_uri.clone()));
        } else {
            headers.push(("TDM-Reservation", "0".to_string()));
        }

        // IETF AI Preferences Working Group standardized Content-Usage preference
        headers.push(("Content-Usage", self.content_usage_header()));

        // Standard crawler restriction header
        if self.forbid_ai_training {
            headers.push(("X-Robots-Tag", "noai, noimageai".to_string()));
        }

        headers.push(("X-Zero-Origin-Rights", "enforced".to_string()));
        headers
    }

    /// Renders deterministic `/ai.txt` policy document.
    pub fn render_ai_txt(&self) -> String {
        let mut out = String::new();
        out.push_str("# SPDX-License-Identifier: Apache-2.0\n");
        out.push_str("# originZero.Art // Machine-Readable Creator Autonomy Protocol (ai.txt v1.0)\n");
        out.push_str(&format!("# Domain: {}\n", self.domain));
        out.push_str(&format!("# Creator: {}\n", self.creator));
        out.push_str(&format!("# Contact: {}\n", self.contact));
        out.push_str(&format!("# Policy: {}\n\n", self.license_uri));

        out.push_str("User-Agent: *\n");
        out.push_str(&format!("Content-Usage: {}\n", self.content_usage_header()));
        if self.forbid_ai_training {
            out.push_str("Disallow-AI-Training: /\n");
            out.push_str("Disallow-Synthetic-Ingestion: /\n");
            out.push_str(&format!(
                "TDM-Reservation: {}\n",
                if self.tdm_reservation { 1 } else { 0 }
            ));
            out.push_str(&format!("TDM-Policy: {}\n", self.license_uri));
            out.push_str("Provenance-Standard: C2PA-JUMBF\n");
            out.push_str("\n# Explicitly named autonomous scraper fleets\n");
            for bot in [
                "GPTBot",
                "ChatGPT-User",
                "OAI-SearchBot",
                "ClaudeBot",
                "Claude-Web",
                "anthropic-ai",
                "Bytespider",
                "CCBot",
                "Google-Extended",
                "Meta-ExternalAgent",
                "FacebookBot",
                "PerplexityBot",
                "Diffbot",
                "Cohere-ai",
                "Applebot-Extended",
                "Amazonbot",
            ] {
                out.push_str(&format!("User-Agent: {}\nDisallow: /\n", bot));
            }
        }

        if self.allow_search_indexing {
            out.push_str("\n# Verified human search discoverability remains permitted (index-only, no TDM)\n");
            out.push_str("Allow-Search-Index: Googlebot, Bingbot, DuckDuckBot\n");
        }

        out
    }

    /// Renders structured `/.well-known/tdmrep.json` payload compliant with W3C TDMRep.
    pub fn render_tdmrep_json(&self) -> Result<String, serde_json::Error> {
        let doc = vec![TdmRepDocument {
            schema: "https://originzero.art/schemas/tdmrep.schema.json".to_string(),
            location: "/".to_string(),
            tdm_reservation: if self.tdm_reservation { 1 } else { 0 },
            tdm_policy: self.license_uri.clone(),
            creator: self.creator.clone(),
            contact: self.contact.clone(),
            directives: vec![
                "EU-Directive-2019-790-Article-4-Reserved".to_string(),
                if self.forbid_ai_training {
                    "No-Automated-Model-Training".to_string()
                } else {
                    "Permissive-With-Attribution".to_string()
                },
                "Human-Authorship-C2PA-Protected".to_string(),
            ],
        }];
        serde_json::to_string_pretty(&doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tdm_headers() {
        let policy = OriginRightsPolicy::default();
        let headers = policy.response_headers();

        assert!(headers.contains(&(
            "Link",
            "<https://originzero.art/license/tdm-reservation>; rel=\"license\"".to_string()
        )));
        assert!(headers.contains(&("TDM-Reservation", "1".to_string())));
        assert!(headers.contains(&("Content-Usage", "train-ai=n, search=y".to_string())));
        assert!(headers.contains(&("X-Robots-Tag", "noai, noimageai".to_string())));
    }

    #[test]
    fn test_ai_txt_and_tdmrep_render() {
        let policy = OriginRightsPolicy::default();
        let ai_txt = policy.render_ai_txt();
        assert!(ai_txt.contains("Content-Usage: train-ai=n, search=y"));
        assert!(ai_txt.contains("Disallow-AI-Training: /"));
        assert!(ai_txt.contains("GPTBot"));
        assert!(ai_txt.contains("TDM-Reservation: 1"));

        let tdm_json = policy.render_tdmrep_json().expect("valid JSON");
        assert!(tdm_json.contains("\"tdm-reservation\": 1"));
        assert!(tdm_json.contains("originzero.art"));
    }
}
