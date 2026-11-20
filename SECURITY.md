<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>
-->

# Security Policy

`zero-origin` is a critical defense layer protecting creative infrastructure. We take security vulnerabilities seriously and adhere to coordinated, responsible disclosure.

---

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` (Development / Roadmap) | :white_check_mark: |

---

## Reporting a Vulnerability

If you discover a security vulnerability in `zero-origin`, including:
- Proxy bypasses or transport-layer evasion vectors
- TLS / JA4 fingerprint spoofing flaws
- C2PA manifest tampering or signature stripping vulnerabilities
- Denial-of-service / memory corruption flaws in ingress parsers

Please **DO NOT** open a public issue.

Instead, submit your report privately to our security team:
- **Email:** [contact@originzero.art](mailto:contact@originzero.art)
- **Subject:** `[SECURITY] zero-origin Vulnerability Report`

### What to Include in Your Report
1. Detailed description of the vulnerability and affected component (`proxy`, `signer`, `specs`).
2. Minimal Proof-of-Concept (PoC) script or packet capture reproducing the issue.
3. Potential impact assessment and recommended mitigation steps.

### Our Response SLA
- **Initial Acknowledgment:** Within **24 to 48 hours**.
- **Triage & Reproduction:** Within **5 business days**.
- **Patch & Coordinated Disclosure:** We work collaboratively with reporters to release a patched version before public disclosure.
