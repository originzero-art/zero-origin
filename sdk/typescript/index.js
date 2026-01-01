// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

"use strict";

const crypto = require("node:crypto");

const C2PA_JUMBF_UUID = Buffer.from("6332706100110010800000aa00389b71", "hex");
const ISOBMFF_C2PA_UUID = Buffer.from("d8fec3d61b0e483c92975828877ec481", "hex");

function sha256Excluded(buf, start, end) {
  const h = crypto.createHash("sha256");
  h.update(buf.subarray(0, start));
  h.update(buf.subarray(end));
  return h.digest("hex");
}

function detectFormat(buf) {
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "JPEG";
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "PNG";
  if (buf.length >= 12 && buf.subarray(0, 4).toString("ascii") === "RIFF" && buf.subarray(8, 12).toString("ascii") === "WEBP") return "WebP";
  if (buf.length >= 12 && buf.subarray(4, 8).toString("ascii") === "ftyp") {
    const brand = buf.subarray(8, 12).toString("ascii");
    if (["avif", "avis", "mif1", "heic"].includes(brand)) return "AVIF";
  }
  throw new Error("Unsupported or unrecognized media format");
}

function extractJumbf(buf) {
  const fmt = detectFormat(buf);

  if (fmt === "JPEG") {
    let pos = 2;
    while (pos + 4 <= buf.length) {
      if (buf[pos] !== 0xff) throw new Error(`Malformed JPEG at ${pos}`);
      while (pos < buf.length && buf[pos] === 0xff) pos++;
      if (pos >= buf.length) break;
      const marker = buf[pos];
      const segStart = pos - 1;
      pos++;
      if (marker === 0xd9 || marker === 0xda) break;
      if ((marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) continue;
      const segLen = buf.readUInt16BE(pos);
      const segEnd = pos + segLen;
      if (segLen < 2 || segEnd > buf.length) throw new Error(`Malformed JPEG segment at ${pos}`);
      const payload = buf.subarray(pos + 2, segEnd);
      if (marker === 0xeb && payload.length >= 8 && payload.subarray(0, 2).toString("ascii") === "JP") {
        return {
          format: "JPEG",
          jumb: payload.subarray(8),
          contentSha256: sha256Excluded(buf, segStart, segEnd),
        };
      }
      pos = segEnd;
    }
    throw new Error("JUMBF APP11 manifest not found in JPEG");
  }

  if (fmt === "PNG") {
    let pos = 8;
    while (pos + 12 <= buf.length) {
      const len = buf.readUInt32BE(pos);
      const ctype = buf.subarray(pos + 4, pos + 8).toString("ascii");
      const dataStart = pos + 8;
      const dataEnd = dataStart + len;
      const chunkEnd = dataEnd + 4;
      if (chunkEnd > buf.length) throw new Error(`Malformed PNG chunk at ${pos}`);
      if (ctype === "caBX") {
        return {
          format: "PNG",
          jumb: buf.subarray(dataStart, dataEnd),
          contentSha256: sha256Excluded(buf, pos, chunkEnd),
        };
      }
      if (ctype === "IEND") break;
      pos = chunkEnd;
    }
    throw new Error("caBX manifest chunk not found in PNG");
  }

  if (fmt === "WebP") {
    const currentRiffSize = buf.readUInt32LE(4);
    let pos = 12;
    while (pos + 8 <= buf.length) {
      const fourcc = buf.subarray(pos, pos + 4).toString("ascii");
      const chunkLen = buf.readUInt32LE(pos + 4);
      const dataStart = pos + 8;
      const dataEnd = dataStart + chunkLen;
      const pad = chunkLen % 2;
      const chunkEnd = dataEnd + pad;
      if (chunkEnd > buf.length) throw new Error(`Malformed WebP chunk at ${pos}`);
      if (fourcc === "C2PA") {
        const origRiff = Buffer.alloc(4);
        origRiff.writeUInt32LE(Math.max(0, currentRiffSize - (chunkEnd - pos)), 0);
        const h = crypto.createHash("sha256");
        h.update(buf.subarray(0, 4));
        h.update(origRiff);
        h.update(buf.subarray(8, pos));
        h.update(buf.subarray(chunkEnd));
        return {
          format: "WebP",
          jumb: buf.subarray(dataStart, dataEnd),
          contentSha256: h.digest("hex"),
        };
      }
      pos = chunkEnd;
    }
    throw new Error("C2PA chunk not found in WebP");
  }

  // AVIF ISOBMFF
  let pos = 0;
  while (pos + 8 <= buf.length) {
    let boxSize = buf.readUInt32BE(pos);
    const boxType = buf.subarray(pos + 4, pos + 8).toString("ascii");
    let hdrLen = 8;
    if (boxSize === 1 && pos + 16 <= buf.length) {
      boxSize = Number(buf.readBigUInt64BE(pos + 8));
      hdrLen = 16;
    } else if (boxSize === 0) {
      boxSize = buf.length - pos;
    }
    if (boxSize < hdrLen || pos + boxSize > buf.length) throw new Error(`Malformed ISOBMFF box at ${pos}`);
    if (boxType === "uuid" && boxSize >= hdrLen + 16) {
      if (buf.subarray(pos + hdrLen, pos + hdrLen + 16).equals(ISOBMFF_C2PA_UUID)) {
        return {
          format: "AVIF",
          jumb: buf.subarray(pos + hdrLen + 16, pos + boxSize),
          contentSha256: sha256Excluded(buf, pos, pos + boxSize),
        };
      }
    }
    pos += boxSize;
  }
  throw new Error("C2PA UUID box not found in AVIF");
}

function decodeJumbfEnvelope(jumb) {
  if (jumb.length < 8 || jumb.subarray(4, 8).toString("ascii") !== "jumb") {
    throw new Error("Invalid JUMBF superbox header");
  }
  const declaredLen = jumb.readUInt32BE(0);
  if (declaredLen > jumb.length) throw new Error("Truncated JUMBF superbox");
  let pos = 8;
  let uuidMatched = false;
  let jsonPayload = null;
  while (pos + 8 <= declaredLen) {
    const len = jumb.readUInt32BE(pos);
    const btype = jumb.subarray(pos + 4, pos + 8).toString("ascii");
    if (len < 8 || pos + len > declaredLen) throw new Error("Invalid child JUMBF box");
    const body = jumb.subarray(pos + 8, pos + len);
    if (btype === "jumd" && body.length >= 16 && body.subarray(0, 16).equals(C2PA_JUMBF_UUID)) {
      uuidMatched = true;
    } else if (btype === "json") {
      jsonPayload = body.toString("utf8");
    }
    pos += len;
  }
  if (!uuidMatched || !jsonPayload) throw new Error("Missing C2PA UUID or JSON claim box");
  return JSON.parse(jsonPayload);
}

function verifyAssetBytes(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const extracted = extractJumbf(buf);
  const envelope = decodeJumbfEnvelope(extracted.jumb);
  const claim = JSON.parse(envelope.claim_json);

  const pubKey = crypto.createPublicKey(envelope.public_key_pem);
  const sig = Buffer.from(envelope.signature_b64, "base64");
  const alg = envelope.alg === "es256" ? "sha256" : null;

  const isSigValid = crypto.verify(
    alg,
    Buffer.from(envelope.claim_json, "utf8"),
    pubKey,
    sig
  );
  if (!isSigValid) {
    throw new Error("Cryptographic signature invalid");
  }
  if (claim.asset_sha256 !== extracted.contentSha256) {
    throw new Error(`Content hash mismatch: expected ${claim.asset_sha256}, computed ${extracted.contentSha256}`);
  }

  return {
    valid: true,
    format: extracted.format,
    algorithm: envelope.alg,
    content_sha256: extracted.contentSha256,
    claim,
  };
}

function auditHttpRightsHeaders(headers) {
  const norm = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (v !== undefined) {
      norm[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
    }
  }
  const tdmReservation = norm["tdm-reservation"] ? norm["tdm-reservation"].trim() : null;
  const tdmPolicy = norm["tdm-policy"] ? norm["tdm-policy"].trim() : null;
  const contentUsage = norm["content-usage"] ? norm["content-usage"].trim() : null;
  const linkHdr = norm["link"] && (norm["link"].includes('rel="license"') || norm["link"].includes("rel='license'"))
    ? norm["link"].trim()
    : null;
  const xRobotsTag = norm["x-robots-tag"] ? norm["x-robots-tag"].trim() : null;

  return {
    tdm_reservation: tdmReservation,
    tdm_policy: tdmPolicy,
    content_usage: contentUsage,
    rfc8288_license_link: linkHdr,
    x_robots_tag: xRobotsTag,
    rights_enforced: tdmReservation === "1" && linkHdr !== null,
  };
}

module.exports = {
  verifyAssetBytes,
  auditHttpRightsHeaders,
  extractJumbf,
};
