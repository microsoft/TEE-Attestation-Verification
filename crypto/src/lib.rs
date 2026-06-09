// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic backend for certificate and signature verification.
//!
//! Supports crypto backends via feature flags:
//! - `crypto_openssl` - OpenSSL-based (not available on WASM)
//! - `crypto_pure_rust` - Pure Rust
//! - `crypto_webcrypto` - WebCrypto-based async verification for WASM

use std::time::Duration;

mod x509_policy;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod signature;

pub use signature::{
    DigestAlgorithm, EcSignatureKeyAlgorithm, RsaPssSignatureKeyAlgorithm, SignatureKeyAlgorithm,
};

pub trait SignatureBackend: Sized {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self>;
    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self>;
}

pub trait KeyBackend: Sized {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self>;
}

pub trait AsyncKeyBackend: Sized {
    fn from_spki_der(
        spki_der: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> impl std::future::Future<Output = Result<Self>>;
}

impl<K> AsyncKeyBackend for K
where
    K: KeyBackend,
{
    async fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        <K as KeyBackend>::from_spki_der(spki_der, algorithm)
    }
}

/// API for the certificate types of the backend
pub trait CertificateBackend {
    type Certificate: Clone;

    /// Parse a certificate from PEM-encoded data.
    fn from_pem(pem: &[u8]) -> Result<Self::Certificate>;

    /// Parse a bundle of PEM-encoded certificates, preserving input order.
    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>>;

    /// Parse a certificate from DER-encoded data.
    fn from_der(der: &[u8]) -> Result<Self::Certificate>;

    /// Encode a certificate as DER.
    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>>;

    /// Encode a certificate as PEM for debug logging.
    fn to_pem(cert: &Self::Certificate) -> Result<String>;

    /// Extract the SubjectPublicKeyInfo (DER-encoded) from the certificate.
    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>>;

    /// Return a stable identifier for the subject public key algorithm.
    fn public_key_algorithm(cert: &Self::Certificate) -> Result<String>;

    /// Extract an extension value by dotted-decimal OID.
    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>>;

    /// Return the certificate subject distinguished name for diagnostics.
    fn subject_name(cert: &Self::Certificate) -> String;

    /// Return the certificate issuer distinguished name for diagnostics.
    fn issuer_name(cert: &Self::Certificate) -> String;

    /// Return whether `cert`'s issuer name matches `issuer`'s subject name.
    fn issuer_name_matches_subject(
        cert: &Self::Certificate,
        issuer: &Self::Certificate,
    ) -> Result<bool>;

    /// Return whether the certificate validity interval includes `unix_time`.
    fn is_valid_at(cert: &Self::Certificate, unix_time: Duration) -> Result<bool>;

    /// Return the zero-based X.509 version number: 0 = v1, 1 = v2, 2 = v3.
    fn version(cert: &Self::Certificate) -> Result<u8>;

    /// Return the criticality of an extension by dotted-decimal OID if present.
    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>>;

    /// Return dotted-decimal OIDs for critical extensions in the certificate.
    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String>;

    /// Return whether the certificate is self-issued.
    fn is_self_issued(cert: &Self::Certificate) -> Result<bool> {
        Self::issuer_name_matches_subject(cert, cert)
    }
}

/// Synchronous API for a cryptographic backend
pub trait CryptoBackend: CertificateBackend {
    type Key: KeyBackend;
    type Signature: SignatureBackend;

    /// Verify a signature over `signed_bytes` with `key`.
    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()>;

    /// Verify a certificate chain from `trusted_cert` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_cert: &<Self as CertificateBackend>::Certificate,
        untrusted_chain: &[&<Self as CertificateBackend>::Certificate],
        leaf: &<Self as CertificateBackend>::Certificate,
    ) -> Result<()>;
}

/// Asynchronous API for a cryptographic backend
pub trait AsyncCryptoBackend: CertificateBackend {
    type Key: AsyncKeyBackend;
    type Signature: SignatureBackend;

    /// Verify a signature over `signed_bytes` with `key`.
    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> impl std::future::Future<Output = Result<()>>;

    /// Verify a certificate chain from `trusted_cert` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_cert: &<Self as CertificateBackend>::Certificate,
        untrusted_chain: &[&<Self as CertificateBackend>::Certificate],
        leaf: &<Self as CertificateBackend>::Certificate,
    ) -> impl std::future::Future<Output = Result<()>>;
}

/// Any synchronous `CryptoBackend` also implements `AsyncCryptoBackend` by blocking on the synchronous verification.
impl<C> AsyncCryptoBackend for C
where
    C: CryptoBackend,
    <C as CryptoBackend>::Key: AsyncKeyBackend,
{
    type Key = <C as CryptoBackend>::Key;
    type Signature = <C as CryptoBackend>::Signature;

    async fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        <C as CryptoBackend>::verify_signature(key, signature, signed_bytes)
    }

    async fn verify_chain(
        trusted_cert: &<Self as CertificateBackend>::Certificate,
        untrusted_chain: &[&<Self as CertificateBackend>::Certificate],
        leaf: &<Self as CertificateBackend>::Certificate,
    ) -> Result<()> {
        <C as CryptoBackend>::verify_chain(trusted_cert, untrusted_chain, leaf)
    }
}

#[cfg(crypto_backend = "crypto_openssl")]
pub(crate) mod crypto_openssl;
#[cfg(crypto_backend = "crypto_pure_rust")]
pub(crate) mod crypto_pure_rust;
#[cfg(crypto_backend = "crypto_webcrypto")]
pub(crate) mod crypto_webcrypto;
#[cfg(any(
    crypto_backend = "crypto_pure_rust",
    crypto_backend = "crypto_webcrypto"
))]
mod x509_certificate;

#[cfg(crypto_backend = "crypto_openssl")]
pub type Crypto = crypto_openssl::Crypto;
#[cfg(crypto_backend = "crypto_pure_rust")]
pub type Crypto = crypto_pure_rust::Crypto;
#[cfg(crypto_backend = "crypto_webcrypto")]
pub type Crypto = crypto_webcrypto::Crypto;

/// The certificate type for the active crypto backend.
pub type Key = <Crypto as AsyncCryptoBackend>::Key;
/// The signature type for the active crypto backend.
pub type Signature = <Crypto as AsyncCryptoBackend>::Signature;
/// The certificate type for the active crypto backend.
pub type Certificate = <Crypto as CertificateBackend>::Certificate;

#[cfg(test)]
mod tests;
