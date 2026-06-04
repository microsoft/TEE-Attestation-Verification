// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic backend for certificate and signature verification.
//!
//! Supports crypto backends via feature flags:
//! - `crypto_openssl` - OpenSSL-based (not available on WASM)
//! - `crypto_pure_rust` - Pure Rust
//! - `crypto_webcrypto` - WebCrypto-based async verification for WASM

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod signature;
pub use signature::{
    DigestAlgorithm, EcSignatureKeyAlgorithm, RsaPssSignatureKeyAlgorithm, SignatureEncoding,
    SignatureKeyAlgorithm,
};

/// API for the key and signature types of the backend
pub trait SignatureBackend {
    type Key;
    type Signature<'a>;

    fn key_from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self::Key>;

    fn verify_signature(
        key: &Self::Key,
        signed_bytes: &[u8],
        signature: &Self::Signature<'_>,
    ) -> Result<()>;
}

pub trait AsyncSignatureBackend {
    type Key;
    type Signature<'a>;

    fn key_from_spki_der(
        spki_der: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> impl std::future::Future<Output = Result<Self::Key>>;

    fn verify_signature(
        key: &Self::Key,
        signed_bytes: &[u8],
        signature: &Self::Signature<'_>,
    ) -> impl std::future::Future<Output = Result<()>>;
}

impl<T> AsyncSignatureBackend for T
where
    T: SignatureBackend,
{
    type Key = <T as SignatureBackend>::Key;
    type Signature<'a> = <T as SignatureBackend>::Signature<'a>;

    async fn key_from_spki_der(
        spki_der: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Self::Key> {
        <T as SignatureBackend>::key_from_spki_der(spki_der, algorithm)
    }

    async fn verify_signature(
        key: &Self::Key,
        signed_bytes: &[u8],
        signature: &Self::Signature<'_>,
    ) -> Result<()> {
        <T as SignatureBackend>::verify_signature(key, signed_bytes, signature)
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

    /// Extract an extension value by dotted-decimal OID.
    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>>;
}

/// Synchronous API for a cryptographic backend
pub trait CryptoBackend: CertificateBackend + SignatureBackend {
    /// Verify a certificate chain from `trusted_cert` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_cert: &<Self as CertificateBackend>::Certificate,
        untrusted_chain: &[&<Self as CertificateBackend>::Certificate],
        leaf: &<Self as CertificateBackend>::Certificate,
    ) -> Result<()>;
}

/// Asynchronous API for a cryptographic backend
pub trait AsyncCryptoBackend: CertificateBackend + AsyncSignatureBackend {
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
{
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
pub type Certificate = <Crypto as CertificateBackend>::Certificate;

/// The key type for the active crypto backend.
pub type Key = <Crypto as AsyncSignatureBackend>::Key;

/// The signature type for the active crypto backend.
pub type Signature<'a> = <Crypto as AsyncSignatureBackend>::Signature<'a>;

#[cfg(test)]
mod tests;
