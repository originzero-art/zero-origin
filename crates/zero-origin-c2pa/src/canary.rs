// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Deterministic Mathematical Canary Benchmark PNG Generator.
//! Synthesizes a pure geometric Coordinate `(0,0)` benchmark asset (~1.84 MB at 800x768)
//! using strictly the 4-color originZero.Art palette (Black, White, Silver, Gold).
//! Zero AI-generated art, zero external C libraries, bit-exact across platforms.

use crc32fast::Hasher as Crc32Hasher;

const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

fn write_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let mut crc = Crc32Hasher::new();
    crc.update(chunk_type);
    crc.update(data);
    out.extend_from_slice(&crc.finalize().to_be_bytes());
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for chunk in data.chunks(5552) {
        for &b in chunk {
            s1 += u32::from(b);
            s2 += s1;
        }
        s1 %= MOD_ADLER;
        s2 %= MOD_ADLER;
    }
    (s2 << 16) | s1
}

fn zlib_store_encode(raw: &[u8]) -> Vec<u8> {
    let blocks = (raw.len() / 65_535) + 1;
    let mut z = Vec::with_capacity(2 + raw.len() + blocks * 5 + 4);
    // RFC 1950 header: CM=8, CINFO=7 (0x78), FCHECK=1 (0x01) -> 30721 % 31 == 0
    z.extend_from_slice(&[0x78, 0x01]);

    if raw.is_empty() {
        z.push(0x01);
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&(!0u16).to_le_bytes());
    } else {
        let chunks: Vec<&[u8]> = raw.chunks(65_535).collect();
        let last_idx = chunks.len() - 1;
        for (idx, block) in chunks.into_iter().enumerate() {
            let bfinal = if idx == last_idx { 0x01u8 } else { 0x00u8 };
            z.push(bfinal);
            let len = block.len() as u16;
            z.extend_from_slice(&len.to_le_bytes());
            z.extend_from_slice(&(!len).to_le_bytes());
            z.extend_from_slice(block);
        }
    }

    z.extend_from_slice(&adler32(raw).to_be_bytes());
    z
}

/// Generates a deterministic 24-bit RGB PNG image of `(width x height)` pixels.
/// Default production benchmark dimensions `(800, 768)` yield ~1.84 MB (`1,844,180` bytes).
pub fn generate_deterministic_canary_png(width: u32, height: u32) -> Vec<u8> {
    let w = width.max(16);
    let h = height.max(16);
    let stride = (w as usize) * 3 + 1;
    let mut scanlines = Vec::with_capacity(stride * (h as usize));

    let cx = (w / 2) as i64;
    let cy = (h / 2) as i64;

    // Strict 4-color luxury palette: Obsidian Black, Noble Gold, Liquid Silver, Crisp White
    const OBSIDIAN: [u8; 3] = [0x05, 0x05, 0x05];
    const GOLD: [u8; 3] = [0xD4, 0xAF, 0x37];
    const SILVER: [u8; 3] = [0xC0, 0xC0, 0xC0];
    const WHITE: [u8; 3] = [0xF8, 0xFA, 0xFC];

    for y in 0..h {
        scanlines.push(0x00); // Filter 0 (None)
        let dy = (y as i64) - cy;
        for x in 0..w {
            let dx = (x as i64) - cx;
            let dist_sq = dx * dx + dy * dy;

            let rgb = if dist_sq <= 64 {
                // Inner singularity core
                WHITE
            } else if dist_sq <= 324 {
                // Golden Root Dot (Coordinate 0,0)
                GOLD
            } else if (dist_sq >= 8000 && dist_sq <= 8280)
                || (dist_sq >= 32200 && dist_sq <= 32600)
                || (dist_sq >= 72600 && dist_sq <= 73200)
            {
                // Harmonic concentric provenance rings
                GOLD
            } else if dx == 0 || dy == 0 {
                // Primary Cartesian origin axes
                SILVER
            } else if (x % 64 == 0 && (y % 4 == 0)) || (y % 64 == 0 && (x % 4 == 0)) {
                // Dotted silver coordinate lattice
                SILVER
            } else {
                OBSIDIAN
            };
            scanlines.extend_from_slice(&rgb);
        }
    }

    let idat_payload = zlib_store_encode(&scanlines);
    let mut png = Vec::with_capacity(64 + idat_payload.len());
    png.extend_from_slice(&PNG_SIG);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(2); // color type 2 = truecolor RGB (opaque, zero alpha)
    ihdr.push(0); // compression
    ihdr.push(0); // filter
    ihdr.push(0); // interlace
    write_png_chunk(&mut png, b"IHDR", &ihdr);
    write_png_chunk(&mut png, b"IDAT", &idat_payload);
    write_png_chunk(&mut png, b"IEND", &[]);
    png
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_creator_identity;
    use crate::signer::{sign_asset_bytes, SignParams};
    use zero_origin_common::provenance::{ManifestFormat, SigningAlgorithm};
    use zero_origin_verify::verify_asset_bytes;

    #[test]
    fn test_deterministic_canary_png_unsigned_vs_c2pa_signed() {
        let unsigned = generate_deterministic_canary_png(800, 768);
        assert!(unsigned.len() > 1_800_000, "canary must represent ~1.8 MB payload");
        assert!(verify_asset_bytes(&unsigned).is_err(), "unsigned canary must fail C2PA verify");

        let id = generate_creator_identity(
            SigningAlgorithm::Ed25519,
            "Sebastian Paul Banszky",
            "originzero.art",
        )
        .unwrap();
        let params = SignParams {
            creator_name: "Sebastian Paul Banszky".to_string(),
            creator_url: "https://originzero.art".to_string(),
            title: Some("originZero.Art Coordinate (0,0) Benchmark Canary".to_string()),
            certificate_pem: Some(id.certificate_pem.clone()),
            manifest_format: ManifestFormat::Cose,
            ..Default::default()
        };
        let signed = sign_asset_bytes(&unsigned, &id.private_key_pem, &params).unwrap();
        let verified = verify_asset_bytes(&signed).expect("signed canary must pass C2PA verify");
        assert!(verified.valid);
        assert_eq!(verified.format, "PNG");
        assert_eq!(verified.algorithm, SigningAlgorithm::Ed25519);
    }
}
