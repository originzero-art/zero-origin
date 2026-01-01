// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

"use strict";

const assert = require("node:assert");
const crypto = require("node:crypto");
const { verifyAssetBytes, auditHttpRightsHeaders } = require("./index.js");

function buildJumbfBox(envelope) {
  const jsonBytes = Buffer.from(JSON.stringify(envelope), "utf8");
  const uuid = Buffer.from("6332706100110010800000aa00389b71", "hex");
  const label = Buffer.from("c2pa\0", "ascii");
  const jumd = Buffer.alloc(8 + 16 + 1 + label.length);
  jumd.writeUInt32BE(jumd.length, 0);
  jumd.write("jumd", 4, "ascii");
  uuid.copy(jumd, 8);
  jumd[24] = 0x03;
  label.copy(jumd, 25);

  const jsonBox = Buffer.alloc(8 + jsonBytes.length);
  jsonBox.writeUInt32BE(jsonBox.length, 0);
  jsonBox.write("json", 4, "ascii");
  jsonBytes.copy(jsonBox, 8);

  const superbox = Buffer.alloc(8 + jumd.length + jsonBox.length);
  superbox.writeUInt32BE(superbox.length, 0);
  superbox.write("jumb", 4, "ascii");
  jumd.copy(superbox, 8);
  jsonBox.copy(superbox, 8 + jumd.length);
  return superbox;
}

// 1. Test HTTP Rights Audit
const okAudit = auditHttpRightsHeaders({
  "TDM-Reservation": "1",
  "TDM-Policy": "https://originzero.art/license/tdm-reservation",
  "Content-Usage": "train-ai=n, search=y",
  Link: '<https://originzero.art/license/tdm-reservation>; rel="license"',
  "X-Robots-Tag": "noai, noimageai",
});
assert.strictEqual(okAudit.rights_enforced, true);
assert.strictEqual(okAudit.content_usage, "train-ai=n, search=y");

const failAudit = auditHttpRightsHeaders({ "Content-Type": "image/jpeg" });
assert.strictEqual(failAudit.rights_enforced, false);

// 2. Test Cryptographic Ed25519 Signed JPEG Roundtrip & Tamper Failure
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const pubPem = publicKey.export({ type: "spki", format: "pem" });

const rawJpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x11, 0x22, 0xff, 0xda, 0x55, 0x66, 0xff, 0xd9]);
const rawHash = crypto.createHash("sha256").update(rawJpeg).digest("hex");

const claimJson = JSON.stringify({
  spec_version: "1.0-c2pa-compatible",
  claim_generator: "zero-origin/0.1.0-mvp",
  creator_name: "757 Painter",
  creator_url: "https://757.originzero.art",
  title: "Nocturne",
  actions: ["c2pa.created"],
  tdm_reservation: true,
  tdm_policy: "https://originzero.art/license/tdm-reservation",
  asset_sha256: rawHash,
  created_utc: "2026-11-16T12:00:00Z",
});

const sig = crypto.sign(null, Buffer.from(claimJson, "utf8"), privateKey);
const jumb = buildJumbfBox({
  alg: "ed25519",
  public_key_pem: pubPem,
  certificate_pem: null,
  claim_json: claimJson,
  signature_b64: sig.toString("base64"),
});

// Embed in APP11 ("JP" + En(1) + Seq(1) + jumb)
const segPayload = Buffer.concat([Buffer.from("JP"), Buffer.from([0, 1, 0, 0, 0, 1]), jumb]);
const app11 = Buffer.alloc(4 + segPayload.length);
app11[0] = 0xff;
app11[1] = 0xeb;
app11.writeUInt16BE(2 + segPayload.length, 2);
segPayload.copy(app11, 4);

const signedJpeg = Buffer.concat([rawJpeg.subarray(0, 2), app11, rawJpeg.subarray(2)]);

const report = verifyAssetBytes(signedJpeg);
assert.strictEqual(report.valid, true);
assert.strictEqual(report.format, "JPEG");
assert.strictEqual(report.claim.creator_name, "757 Painter");

// Modify single pixel byte -> MUST THROW hash mismatch
const tampered = Buffer.from(signedJpeg);
tampered[tampered.length - 3] ^= 0xff;
assert.throws(() => verifyAssetBytes(tampered), /Content hash mismatch/);

console.log("[PASS] @originzero/verify TypeScript/Node SDK tests succeeded.");
