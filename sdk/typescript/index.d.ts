// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

export type SigningAlgorithm = "ed25519" | "es256";

export interface OriginManifestClaim {
  spec_version: string;
  claim_generator: string;
  creator_name: string;
  creator_url: string;
  title: string | null;
  actions: string[];
  tdm_reservation: boolean;
  tdm_policy: string;
  asset_sha256: string;
  created_utc: string;
}

export interface AssetVerifyReport {
  valid: boolean;
  format: "JPEG" | "PNG" | "WebP" | "AVIF";
  algorithm: SigningAlgorithm;
  content_sha256: string;
  claim: OriginManifestClaim;
}

export interface HttpRightsAudit {
  tdm_reservation: string | null;
  tdm_policy: string | null;
  content_usage: string | null;
  rfc8288_license_link: string | null;
  x_robots_tag: string | null;
  rights_enforced: boolean;
}

export function verifyAssetBytes(buffer: Uint8Array): AssetVerifyReport;
export function auditHttpRightsHeaders(headers: Record<string, string | string[] | undefined>): HttpRightsAudit;
