<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>
-->

# Open Specification: `ai.txt` Creator Autonomy Protocol (v1.0)

`ai.txt` is an open, human- and machine-readable root declaration served at `https://<domain>/ai.txt` allowing artists and publishers to forbid unconsented automated training ingestion while preserving legitimate search indexing.

## 1. Grammar (ABNF-aligned)

```text
ai-txt-file    = *( comment / blank-line / record )
comment        = "#" *VCHAR LF
record         = user-agent-line 1*( directive-line )
user-agent-line = "User-Agent:" SP identifier LF
directive-line = ( "Content-Usage:"
                 / "Disallow-AI-Training:"
                 / "Disallow-Synthetic-Ingestion:"
                 / "Disallow:"
                 / "TDM-Reservation:"
                 / "TDM-Policy:"
                 / "Provenance-Standard:"
                 / "Allow-Search-Index:" ) SP value LF
```

## 2. Semantics

- `Disallow-AI-Training: /`: Unconditionally withholds consent for dataset scraping and foundation model training across the origin path prefix.
- `TDM-Reservation: 1`: Asserts legal reservation under EU DSM Directive 2019/790 Article 4(3).
- `Provenance-Standard: C2PA-JUMBF`: Signals that served raster assets contain embedded JUMBF cryptographic human-authorship proofs.
- `Allow-Search-Index`: Clarifies that standard navigational search indexers remain welcome without implying dataset training rights.
