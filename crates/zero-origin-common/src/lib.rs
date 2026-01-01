// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! `zero-origin-common`: Permissively licensed (Apache-2.0) core types,
//! EU TDM rights specifications, lossless container JUMBF readers, and
//! cryptographic verification primitives for the originZero.Art ecosystem.

pub mod cbor_cose;
pub mod container;
pub mod provenance;
pub mod rights;

/// Canonical originZero.Art brand identifier.
pub const BRAND_NAME: &str = "originZero.Art";

/// Default TDM Reservation License URI served in RFC 8288 Link headers.
pub const DEFAULT_TDM_LICENSE_URI: &str = "https://originzero.art/license/tdm-reservation";

/// Official security & licensing contact address.
pub const OFFICIAL_CONTACT: &str = "contact@originzero.art";
