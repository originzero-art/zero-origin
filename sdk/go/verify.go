// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

// Package verify provides a permissive Apache-2.0 reference interface for
// auditing originZero.Art EU TDM headers and JUMBF provenance claims in Go.
package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
)

type HttpRightsAudit struct {
	TDMReservation     string `json:"tdm_reservation"`
	TDMPolicy          string `json:"tdm_policy"`
	ContentUsage       string `json:"content_usage"`
	RFC8288LicenseLink string `json:"rfc8288_license_link"`
	XRobotsTag         string `json:"x_robots_tag"`
	RightsEnforced     bool   `json:"rights_enforced"`
}

type SignedEnvelope struct {
	Alg          string `json:"alg"`
	PublicKeyPEM string `json:"public_key_pem"`
	ClaimJSON    string `json:"claim_json"`
	SignatureB64 string `json:"signature_b64"`
}

func AuditHTTPHeaders(h http.Header) HttpRightsAudit {
	tdm := strings.TrimSpace(h.Get("TDM-Reservation"))
	policy := strings.TrimSpace(h.Get("TDM-Policy"))
	usage := strings.TrimSpace(h.Get("Content-Usage"))
	link := strings.TrimSpace(h.Get("Link"))
	robots := strings.TrimSpace(h.Get("X-Robots-Tag"))

	hasLicenseRel := strings.Contains(link, `rel="license"`) || strings.Contains(link, `rel='license'`)
	if !hasLicenseRel {
		link = ""
	}

	return HttpRightsAudit{
		TDMReservation:     tdm,
		TDMPolicy:          policy,
		ContentUsage:       usage,
		RFC8288LicenseLink: link,
		XRobotsTag:         robots,
		RightsEnforced:     tdm == "1" && link != "",
	}
}

func VerifyEd25519Envelope(env SignedEnvelope) error {
	if env.Alg != "ed25519" {
		return errors.New("unsupported algorithm")
	}
	block, _ := pem.Decode([]byte(env.PublicKeyPEM))
	if block == nil {
		return errors.New("invalid PEM public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return errors.New("not an Ed25519 key")
	}
	sig, err := base64.StdEncoding.DecodeString(env.SignatureB64)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, []byte(env.ClaimJSON), sig) {
		return errors.New("ed25519 signature invalid")
	}
	var js map[string]any
	return json.Unmarshal([]byte(env.ClaimJSON), &js)
}
