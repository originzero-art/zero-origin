// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Lossless Media Container Parser & C2PA JUMBF Box Extractor (Apache-2.0).
//! Implements bounds-checked readers for JPEG (`APP11`), PNG (`caBX`),
//! WebP (`RIFF`/`C2PA`), and AVIF (`ISOBMFF` `uuid`) containers.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// ISO/IEC 19566-5 C2PA JUMBF Manifest Store UUID: `63327061-0011-0010-8000-00AA00389B71`
pub const C2PA_JUMBF_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// ISOBMFF Top-Level UUID Type for C2PA JUMBF container (`D8FEC3D6-1B0E-483C-9297-5828877EC481`)
pub const ISOBMFF_C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

/// PNG C2PA Chunk FourCC (`caBX` per C2PA Specification)
pub const PNG_C2PA_CHUNK: [u8; 4] = *b"caBX";

/// WebP RIFF C2PA Chunk FourCC
pub const WEBP_C2PA_CHUNK: [u8; 4] = *b"C2PA";

/// JPEG APP11 marker prefix (`0xFFEB` + `"JP"`)
pub const JPEG_APP11_MARKER: [u8; 2] = [0xff, 0xeb];
pub const JPEG_JUMBF_IDENT: [u8; 2] = *b"JP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFormat {
    Jpeg,
    Png,
    Webp,
    Avif,
}

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("unsupported or unrecognized media format")]
    UnsupportedFormat,
    #[error("malformed container structure at byte offset {0}")]
    MalformedContainer(usize),
    #[error("JUMBF manifest box not found in container")]
    ManifestNotFound,
    #[error("invalid PNG CRC-32 checksum")]
    InvalidPngCrc,
}

/// Result of extracting an embedded JUMBF superbox along with the exact
/// SHA-256 content-binding hash computed over all non-manifest asset bytes.
#[derive(Debug, Clone)]
pub struct ExtractedManifest {
    pub format: MediaFormat,
    pub jumb_bytes: Vec<u8>,
    pub content_sha256_hex: String,
    pub manifest_span: (usize, usize),
}

/// Detects media container format purely from magic header bytes.
pub fn detect_format(data: &[u8]) -> Result<MediaFormat, ContainerError> {
    if data.len() >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
        return Ok(MediaFormat::Jpeg);
    }
    if data.len() >= 8 && &data[..8] == b"\x89PNG\r\n\x1a\n" {
        return Ok(MediaFormat::Png);
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Ok(MediaFormat::Webp);
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        let brand = &data[8..12];
        if brand == b"avif" || brand == b"avis" || brand == b"mif1" || brand == b"heic" {
            return Ok(MediaFormat::Avif);
        }
    }
    Err(ContainerError::UnsupportedFormat)
}

/// Computes SHA-256 over `data` excluding a specific byte range `[excl_start, excl_end)`.
pub fn compute_excluded_sha256_hex(data: &[u8], excl_start: usize, excl_end: usize) -> String {
    let mut hasher = Sha256::new();
    if excl_start <= excl_end && excl_end <= data.len() {
        hasher.update(&data[..excl_start]);
        hasher.update(&data[excl_end..]);
    } else {
        hasher.update(data);
    }
    hex::encode(hasher.finalize())
}

/// Computes standard SHA-256 hex digest of an unsigned original media file.
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Extracts an embedded JUMBF superbox and computes its exact content-binding hash.
pub fn extract_jumbf(data: &[u8]) -> Result<ExtractedManifest, ContainerError> {
    let fmt = detect_format(data)?;
    match fmt {
        MediaFormat::Jpeg => extract_jpeg_app11(data),
        MediaFormat::Png => extract_png_cabx(data),
        MediaFormat::Webp => extract_webp_c2pa(data),
        MediaFormat::Avif => extract_avif_uuid(data),
    }
}

fn extract_jpeg_app11(data: &[u8]) -> Result<ExtractedManifest, ContainerError> {
    let mut pos = 2usize; // Skip FF D8
    while pos + 4 <= data.len() {
        if data[pos] != 0xff {
            return Err(ContainerError::MalformedContainer(pos));
        }
        // Skip padding 0xFF bytes
        while pos < data.len() && data[pos] == 0xff {
            pos += 1;
        }
        if pos >= data.len() {
            break;
        }
        let marker = data[pos];
        let seg_start = pos - 1;
        pos += 1;

        // EOI (0xD9) or SOS (0xDA) ends metadata segment headers
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        // Standalone markers (RSTn, TEM)
        if (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            continue;
        }

        if pos + 2 > data.len() {
            return Err(ContainerError::MalformedContainer(pos));
        }
        let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        if seg_len < 2 || pos + seg_len > data.len() {
            return Err(ContainerError::MalformedContainer(pos));
        }
        let seg_end = pos + seg_len;
        let payload = &data[pos + 2..seg_end];

        // Check APP11 (0xEB) with JP header ("JP", En: 2 bytes, Seq: 4 bytes)
        if marker == 0xeb && payload.len() >= 8 && payload[0..2] == JPEG_JUMBF_IDENT {
            let jumb_bytes = payload[8..].to_vec();
            let content_sha256_hex = compute_excluded_sha256_hex(data, seg_start, seg_end);
            return Ok(ExtractedManifest {
                format: MediaFormat::Jpeg,
                jumb_bytes,
                content_sha256_hex,
                manifest_span: (seg_start, seg_end),
            });
        }
        pos = seg_end;
    }
    Err(ContainerError::ManifestNotFound)
}

fn extract_png_cabx(data: &[u8]) -> Result<ExtractedManifest, ContainerError> {
    let mut pos = 8usize; // Skip PNG magic
    while pos + 12 <= data.len() {
        let chunk_start = pos;
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let chunk_type = [data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]];
        let data_start = pos + 8;
        let data_end = data_start
            .checked_add(len)
            .ok_or(ContainerError::MalformedContainer(pos))?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(ContainerError::MalformedContainer(pos))?;
        if chunk_end > data.len() {
            return Err(ContainerError::MalformedContainer(pos));
        }

        if chunk_type == PNG_C2PA_CHUNK {
            let expected_crc = u32::from_be_bytes([
                data[data_end],
                data[data_end + 1],
                data[data_end + 2],
                data[data_end + 3],
            ]);
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&data[pos + 4..data_end]);
            if hasher.finalize() != expected_crc {
                return Err(ContainerError::InvalidPngCrc);
            }
            let content_sha256_hex = compute_excluded_sha256_hex(data, chunk_start, chunk_end);
            return Ok(ExtractedManifest {
                format: MediaFormat::Png,
                jumb_bytes: data[data_start..data_end].to_vec(),
                content_sha256_hex,
                manifest_span: (chunk_start, chunk_end),
            });
        }

        if &chunk_type == b"IEND" {
            break;
        }
        pos = chunk_end;
    }
    Err(ContainerError::ManifestNotFound)
}

fn extract_webp_c2pa(data: &[u8]) -> Result<ExtractedManifest, ContainerError> {
    if data.len() < 12 {
        return Err(ContainerError::MalformedContainer(0));
    }
    let current_riff_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let mut pos = 12usize; // Skip "RIFF" + size + "WEBP"
    while pos + 8 <= data.len() {
        let chunk_start = pos;
        let fourcc = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
        let chunk_len = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
        let data_start = pos + 8;
        let data_end = data_start
            .checked_add(chunk_len)
            .ok_or(ContainerError::MalformedContainer(pos))?;
        let pad = chunk_len % 2;
        let chunk_end = data_end
            .checked_add(pad)
            .ok_or(ContainerError::MalformedContainer(pos))?;
        if chunk_end > data.len() {
            return Err(ContainerError::MalformedContainer(pos));
        }

        if fourcc == WEBP_C2PA_CHUNK {
            let chunk_total_bytes = chunk_end - chunk_start;
            let orig_riff_size = current_riff_size.saturating_sub(chunk_total_bytes) as u32;
            // Reconstruct byte-exact original pre-signing buffer digest for verification
            let mut hasher = Sha256::new();
            hasher.update(&data[..4]);
            hasher.update(orig_riff_size.to_le_bytes());
            hasher.update(&data[8..chunk_start]);
            hasher.update(&data[chunk_end..]);
            let content_sha256_hex = hex::encode(hasher.finalize());

            return Ok(ExtractedManifest {
                format: MediaFormat::Webp,
                jumb_bytes: data[data_start..data_end].to_vec(),
                content_sha256_hex,
                manifest_span: (chunk_start, chunk_end),
            });
        }
        pos = chunk_end;
    }
    Err(ContainerError::ManifestNotFound)
}

fn extract_avif_uuid(data: &[u8]) -> Result<ExtractedManifest, ContainerError> {
    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let box_start = pos;
        let size_u32 = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let box_type = [data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]];

        let (box_size, header_len) = if size_u32 == 1 {
            if pos + 16 > data.len() {
                return Err(ContainerError::MalformedContainer(pos));
            }
            let largesize = u64::from_be_bytes([
                data[pos + 8],
                data[pos + 9],
                data[pos + 10],
                data[pos + 11],
                data[pos + 12],
                data[pos + 13],
                data[pos + 14],
                data[pos + 15],
            ]) as usize;
            (largesize, 16usize)
        } else if size_u32 == 0 {
            (data.len() - pos, 8usize)
        } else {
            (size_u32 as usize, 8usize)
        };

        if box_size < header_len || pos + box_size > data.len() {
            return Err(ContainerError::MalformedContainer(pos));
        }
        let box_end = pos + box_size;

        if &box_type == b"uuid" && box_size >= header_len + 16 {
            let uuid_start = pos + header_len;
            if data[uuid_start..uuid_start + 16] == ISOBMFF_C2PA_UUID {
                let payload_start = uuid_start + 16;
                let content_sha256_hex = compute_excluded_sha256_hex(data, box_start, box_end);
                return Ok(ExtractedManifest {
                    format: MediaFormat::Avif,
                    jumb_bytes: data[payload_start..box_end].to_vec(),
                    content_sha256_hex,
                    manifest_span: (box_start, box_end),
                });
            }
        }
        pos = box_end;
    }
    Err(ContainerError::ManifestNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_magic_formats() {
        assert_eq!(detect_format(&[0xff, 0xd8, 0xff, 0xe0]).unwrap(), MediaFormat::Jpeg);
        assert_eq!(detect_format(b"\x89PNG\r\n\x1a\nxxxx").unwrap(), MediaFormat::Png);
        assert_eq!(detect_format(b"RIFF\x10\x00\x00\x00WEBP").unwrap(), MediaFormat::Webp);
        assert_eq!(detect_format(b"\x00\x00\x00\x18ftypavif").unwrap(), MediaFormat::Avif);
        assert!(detect_format(b"GARBAGE").is_err());
    }

    #[test]
    fn test_malformed_truncated_jpeg_safe_error() {
        let malformed = [0xff, 0xd8, 0xff, 0xeb, 0x00, 0x50];
        assert!(matches!(
            extract_jumbf(&malformed),
            Err(ContainerError::MalformedContainer(_))
        ));
    }
}
