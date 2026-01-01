<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>
-->

# Open Specification: EU TDM Reservation & HTTP Header Injection (v1.0)

This specification defines deterministic HTTP response headers emitted by `zero-origin` on proxied assets and downstream pages under **Apache License 2.0**.

## 1. Normative HTTP Headers

| Header | Normative Value | Standard Reference |
| :--- | :--- | :--- |
| `TDM-Reservation` | `1` | W3C TDMRep & EU Directive 2019/790 Art. 4 |
| `TDM-Policy` | `https://originzero.art/license/tdm-reservation` | Machine-readable creator opt-out URI |
| `Content-Usage` | `train-ai=n, search=y` | IETF AI Preferences (`aipref` / attach) |
| `Link` | `<https://originzero.art/license/tdm-reservation>; rel="license"` | IETF RFC 8288 Web Linking |
| `X-Robots-Tag` | `noai, noimageai` | Non-training crawler directive |
| `X-Zero-Origin-Rights` | `enforced` | Diagnostic assertion header |

## 2. Discovery Endpoint: `/.well-known/tdmrep.json`

Every protected origin MUST serve an HTTP `200 OK` JSON array at `/.well-known/tdmrep.json` validated against [schemas/tdmrep.schema.json](../schemas/tdmrep.schema.json).
