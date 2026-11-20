// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

//! Offline/self-hosted Ed25519 & ECDSA P-256 keypair and X.509 certificate generation.

use std::fs;
use std::path::Path;

use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey as EdSigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::LineEnding;
use rand_core::OsRng;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair as RcgenKeyPair, KeyUsagePurpose,
};
use thiserror::Error;
use zeroize::Zeroize;

use zero_origin_common::provenance::SigningAlgorithm;

#[derive(Debug, Error)]
pub enum KeygenError {
    #[error("cryptographic encoding failure: {0}")]
    Crypto(String),
    #[error("filesystem I/O failure: {0}")]
    Io(#[from] std::io::Error),
}

pub struct GeneratedIdentity {
    pub algorithm: SigningAlgorithm,
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub certificate_pem: String,
}

impl Drop for GeneratedIdentity {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

/// Generates an offline creator keypair and self-hosted X.509 certificate.
pub fn generate_creator_identity(
    algorithm: SigningAlgorithm,
    creator_name: &str,
    domain: &str,
) -> Result<GeneratedIdentity, KeygenError> {
    let (private_key_pem, public_key_pem) = match algorithm {
        SigningAlgorithm::Ed25519 => {
            let sk = EdSigningKey::generate(&mut OsRng);
            let priv_pem = sk
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| KeygenError::Crypto(e.to_string()))?
                .to_string();
            let pub_pem = sk
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| KeygenError::Crypto(e.to_string()))?;
            (priv_pem, pub_pem)
        }
        SigningAlgorithm::Es256 => {
            let sk = P256SigningKey::random(&mut OsRng);
            let priv_pem = sk
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .map_err(|e| KeygenError::Crypto(e.to_string()))?
                .to_string();
            let pub_pem = sk
                .verifying_key()
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .map_err(|e| KeygenError::Crypto(e.to_string()))?;
            (priv_pem, pub_pem)
        }
    };

    // Build self-hosted X.509 provenance certificate wrapping the identical PKCS#8 private key
    let rcgen_key = RcgenKeyPair::from_pem(&private_key_pem)
        .map_err(|e| KeygenError::Crypto(format!("rcgen key parse: {}", e)))?;
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| KeygenError::Crypto(e.to_string()))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, creator_name);
    dn.push(DnType::OrganizationName, "originZero.Art Sovereign Creator");
    params.distinguished_name = dn;
    let cert = params
        .self_signed(&rcgen_key)
        .map_err(|e| KeygenError::Crypto(e.to_string()))?;

    Ok(GeneratedIdentity {
        algorithm,
        private_key_pem,
        public_key_pem,
        certificate_pem: cert.pem(),
    })
}

pub struct GeneratedTlsPki {
    pub ca_cert_pem: String,
    pub server_fullchain_pem: String,
    pub server_key_pem: String,
}

impl Drop for GeneratedTlsPki {
    fn drop(&mut self) {
        self.server_key_pem.zeroize();
    }
}

/// Generates an RFC 5280 compliant ephemeral Root CA (`CA:TRUE`, `keyCertSign`) and
/// multi-SAN ECDSA P-256 leaf server certificate (`CA:FALSE`, `serverAuth` EKU)
/// for strict X.509 verification across OpenSSL/LibreSSL (`curl --cacert`) and `rustls`.
pub fn generate_tls_san_pki(sans: &[String], common_name: &str) -> Result<GeneratedTlsPki, KeygenError> {
    // 1. Ephemeral Root CA
    let ca_sk = P256SigningKey::random(&mut OsRng);
    let ca_priv_pem = ca_sk
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| KeygenError::Crypto(e.to_string()))?
        .to_string();
    let ca_rcgen_key = RcgenKeyPair::from_pem(&ca_priv_pem)
        .map_err(|e| KeygenError::Crypto(format!("rcgen CA key parse: {}", e)))?;

    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| KeygenError::Crypto(e.to_string()))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "originZero.Art Local Triad Root CA");
    ca_dn.push(DnType::OrganizationName, "originZero.Art Sovereign PKI");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params
        .self_signed(&ca_rcgen_key)
        .map_err(|e| KeygenError::Crypto(e.to_string()))?;

    // 2. Multi-SAN Server Leaf Certificate signed by Root CA
    let leaf_sk = P256SigningKey::random(&mut OsRng);
    let server_key_pem = leaf_sk
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| KeygenError::Crypto(e.to_string()))?
        .to_string();
    let leaf_rcgen_key = RcgenKeyPair::from_pem(&server_key_pem)
        .map_err(|e| KeygenError::Crypto(format!("rcgen leaf key parse: {}", e)))?;

    let mut leaf_params = CertificateParams::new(sans.to_vec())
        .map_err(|e| KeygenError::Crypto(e.to_string()))?;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, common_name);
    leaf_dn.push(DnType::OrganizationName, "originZero.Art Sovereign TLS");
    leaf_params.distinguished_name = leaf_dn;

    let leaf_cert = leaf_params
        .signed_by(&leaf_rcgen_key, &ca_cert, &ca_rcgen_key)
        .map_err(|e| KeygenError::Crypto(e.to_string()))?;

    let ca_cert_pem = ca_cert.pem();
    let server_fullchain_pem = format!("{}{}", leaf_cert.pem(), ca_cert_pem);

    Ok(GeneratedTlsPki {
        ca_cert_pem,
        server_fullchain_pem,
        server_key_pem,
    })
}

pub fn write_tls_pki_files(pki: &GeneratedTlsPki, out_dir: &Path, prefix: &str) -> Result<(), KeygenError> {
    fs::create_dir_all(out_dir)?;
    let ca_path = out_dir.join(format!("{}-ca.cert.pem", prefix));
    let cert_path = out_dir.join(format!("{}.cert.pem", prefix));
    let key_path = out_dir.join(format!("{}.key.pem", prefix));

    fs::write(&ca_path, &pki.ca_cert_pem)?;
    fs::write(&cert_path, &pki.server_fullchain_pem)?;
    fs::write(&key_path, &pki.server_key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Persists keypair & cert to directory with strict `0600` private key permissions on Unix.
pub fn write_identity_files(identity: &GeneratedIdentity, out_dir: &Path, prefix: &str) -> Result<(), KeygenError> {
    fs::create_dir_all(out_dir)?;
    let priv_path = out_dir.join(format!("{}.key.pem", prefix));
    let pub_path = out_dir.join(format!("{}.pub.pem", prefix));
    let cert_path = out_dir.join(format!("{}.cert.pem", prefix));

    fs::write(&priv_path, &identity.private_key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600))?;
    }

    fs::write(&pub_path, &identity.public_key_pem)?;
    fs::write(&cert_path, &identity.certificate_pem)?;
    Ok(())
}
