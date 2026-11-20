<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>
-->

# zero-origin // Engineering Roadmap & Grant Milestones

> Prepared for institutional technical review: **NLnet Foundation (NGI Zero Commons Fund)**, **Open Collective Europe**, and **Mozilla Trustworthy AI**.

This roadmap outlines the four auditable technical milestones required to bring `zero-origin` from prototype to production-grade self-hosted deployment.

---

## Milestone 1: Deterministic L7 Edge Shield & AI Crawler Ruleset Engine

**Target Focus:** Transport-layer and application-layer mitigation of automated AI training crawlers.  
**Deliverables:**
- Asynchronous Layer-7 reverse-proxy engine (written in Rust/Go) supporting HTTP/1.1, HTTP/2, and TLS 1.3.
- Ingress TLS inspection module calculating client JA4 transport fingerprints before handshake finalization.
- Multi-tiered crawler classification database (Layer A: User-Agent/header signatures; Layer B: TLS/JA4 fingerprints; Layer C: Datacenter ASN reputation).
- Deterministic connection severing logic (immediate 403 Forbidden / 429 Too Many Requests drop without asset buffering).
- Reverse-DNS validation module for legitimate search engines (Googlebot, Bingbot) to prevent accidental de-indexing.

**Auditable Verification Criteria:**
- Unit test suite verifying 100% detection rate against simulated test crawler fleet (GPTBot, ClaudeBot, Bytespider, CCBot, headless Puppeteer).
- Benchmarking suite verifying p99 added latency < 2.0ms on 10,000 concurrent connections.
- Egress bandwidth conservation test showing 0 bytes of asset payload streamed to blocked crawlers.

---

## Milestone 2: C2PA-Compatible Cryptographic Provenance & Human Authorship Signer

**Target Focus:** Local, self-hosted cryptographic provenance and authorship manifest embedding.  
**Deliverables:**
- Self-hosted C2PA manifest builder and signer CLI (`zero-origin sign`) supporting Ed25519 and ECDSA P-256 keys.
- JUMBF box serialization engine embedding manifests into JPEG (`APP11`), PNG (`caBX`/`eXIf`), WebP (`EXIF`/`XMP`), and AVIF (`iloc`/`infe`).
- Zero-recompression guarantee ensuring original pixel data and color spaces remain bit-exact.
- Local certificate and key management supporting on-disk keys and self-hosted PKI without SaaS dependencies.

**Auditable Verification Criteria:**
- 100% manifest validation parity verified against the official `c2pa-rs` toolchain.
- Test suite verifying that altered images trigger cryptographic hash mismatch errors.
- Signing benchmark demonstrating < 30ms latency for 4K raster assets on standard single-core compute.

---

## Milestone 3: Machine-Readable Creator Autonomy Protocol (TDM & Rights Headers)

**Target Focus:** Standardized, machine-readable legal opt-out declarations and client verification libraries.  
**Deliverables:**
- Formal specification for EU Directive 2019/790 Article 4 TDM reservations (`TDM-Reservation: 1`).
- RFC 8288 Link header injection module linking served assets to creator license declarations.
- Formal grammar and JSON Schema for `ai.txt` domain and repository declarations.
- Client verification libraries published under Apache License 2.0:
  - `@originzero/verify` (TypeScript/JavaScript for web apps and browser extensions).
  - `pkg/client` (Go library for backend integration).
  - `zero-origin-verify` (Python package for creative workflows).
- Standalone CLI inspection tool: `zero-origin verify <asset.jpg>`.

**Auditable Verification Criteria:**
- RFC 8288 and HTTP/1.1 compliance verified through automated HTTP header conformance suites.
- JSON Schema validation test suite covering all permissive and restrictive licensing variants.
- End-to-end client verification test reading headers and C2PA manifests across web browsers.

---

## Milestone 4: Reproducible Builds, Security Audit & Pilot Verification

**Target Focus:** Cryptographic build reproducibility, adversarial security verification, and live validation with founding creators.  
**Deliverables:**
- Statically linked, single-binary distribution (Linux x86_64 and aarch64) with deterministic lockfile builds.
- Comprehensive adversarial red-team security test suite covering HTTP request smuggling, header spoofing, and signature tampering.
- Multi-language client verification parity across Rust, TypeScript, Python, and Go.
- Live pilot verification protecting the founding human artist cohort on `originZero.Art`.

**Auditable Verification Criteria:**
- Independent security audit report published with 0 unresolved critical/high vulnerabilities.
- Successful reproducible build verification matching deterministic release checksums.
- Documented live pilot feedback from founding painters and visual identity designers confirming zero delivery disruption and effective crawler blocking.
