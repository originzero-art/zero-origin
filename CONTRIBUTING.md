<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>
-->

# Contributing to zero-origin

Thank you for your interest in contributing to `zero-origin`. We welcome first-principles engineering contributions, security audits, crawler signature updates, and client library implementations.

---

## 1. Code of Conduct & Contribution Standards

- **First-Principles Engineering:** All contributions must be deterministic, reproducible, and verifiable. Avoid speculative features or unnecessary external dependencies.
- **Tone & Communication:** We communicate with precision, mutual respect, and technical rigor.
- **Zero AI Slop:** All code, documentation, and PR descriptions must be written with deliberate human intent. Automated boilerplate or hallucinated APIs will be closed without review.

---

## 2. Developer Certificate of Origin (DCO)

To ensure clean intellectual property and open-source provenance, all commits must include a Developer Certificate of Origin (DCO) sign-off line:

```text
Signed-off-by: Your Name <your.email@example.com>
```

You can automatically add this line to your commits using `git commit -s`.

---

## 3. License Boundary Enforcement

When contributing, ensure your work respects the project's dual-license architecture:
- Contributions to `src/proxy/`, `src/daemon/`, or `src/signer/` are licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.
- Contributions to `specs/`, `schemas/`, `sdk/`, or `pkg/client/` are licensed under the **Apache License 2.0**.

---

## 4. Development Workflow

1. Fork the repository on GitHub (`github.com/originzero-art/zero-origin`).
2. Create a focused feature branch (`git checkout -b feature/crawler-signature-update`).
3. Implement your changes, accompanied by unit tests and benchmark assertions.
4. Ensure all linters and tests pass locally.
5. Submit a concise Pull Request with a clear architectural explanation.
