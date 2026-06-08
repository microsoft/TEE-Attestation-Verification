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

pub mod verifier {
    use super::Result;

    /// Verifies that data was signed by the implementor's private key.
    pub trait Sync<T> {
        fn verify(&self, data: &T) -> Result<()>;
    }

    /// Asynchronously verifies that data was signed by the implementor's private key.
    pub trait Async<T> {
        fn verify(&self, data: &T) -> impl std::future::Future<Output = Result<()>>;
    }
}

/// Backend-internal trait for certificate parsing, encoding, and inspection.
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

/// Backend-internal trait for certificate verification operations.
pub trait CryptoBackend: CertificateBackend
where
    <Self as CertificateBackend>::Certificate:
        verifier::Sync<<Self as CertificateBackend>::Certificate>,
{
    /// Verify a certificate chain from `trusted_certs` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_certs: &[&<Self as CertificateBackend>::Certificate],
        untrusted_chain: &[&<Self as CertificateBackend>::Certificate],
        leaf: &<Self as CertificateBackend>::Certificate,
    ) -> Result<()>;
}

/// Backend-internal trait for asynchronous certificate verification operations.
pub trait AsyncCryptoBackend {
    type Certificate: Clone + verifier::Async<Self::Certificate>;

    /// Verify a certificate chain from `trusted_certs` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_certs: &[&Self::Certificate],
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
    ) -> impl std::future::Future<Output = Result<()>>;
}

impl<C> AsyncCryptoBackend for C
where
    C: CryptoBackend,
    <C as CertificateBackend>::Certificate: verifier::Sync<<C as CertificateBackend>::Certificate>
        + verifier::Async<<C as CertificateBackend>::Certificate>,
{
    type Certificate = <C as CertificateBackend>::Certificate;

    async fn verify_chain(
        trusted_certs: &[&Self::Certificate],
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
    ) -> Result<()> {
        <C as CryptoBackend>::verify_chain(trusted_certs, untrusted_chain, leaf)
    }
}

/// Backend operation for verifying SEV-SNP report ECDSA P-384/SHA-384 signatures.
pub trait ReportSignatureVerifier: CertificateBackend {
    fn verify_ecdsa_p384_sha384_signature(
        cert: &Self::Certificate,
        signed_bytes: &[u8],
        r: [u8; 72],
        s: [u8; 72],
    ) -> Result<()>;
}

/// Asynchronous backend operation for verifying SEV-SNP report ECDSA P-384/SHA-384 signatures.
pub trait AsyncReportSignatureVerifier: CertificateBackend {
    fn verify_ecdsa_p384_sha384_signature(
        cert: &Self::Certificate,
        signed_bytes: &[u8],
        r: [u8; 72],
        s: [u8; 72],
    ) -> impl std::future::Future<Output = Result<()>>;
}

impl<C> AsyncReportSignatureVerifier for C
where
    C: ReportSignatureVerifier,
{
    async fn verify_ecdsa_p384_sha384_signature(
        cert: &Self::Certificate,
        signed_bytes: &[u8],
        r: [u8; 72],
        s: [u8; 72],
    ) -> Result<()> {
        <C as ReportSignatureVerifier>::verify_ecdsa_p384_sha384_signature(cert, signed_bytes, r, s)
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

#[cfg(test)]
mod test {
    use super::Crypto;
    use super::*;

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
    fn cert(pem: &[u8]) -> Certificate {
        Crypto::from_pem(pem).unwrap()
    }

    #[test]
    fn certificate_parse_and_encode_wrappers_round_trip() {
        let pem_chain = [MILAN_ASK, b"\n", MILAN_ARK].concat();
        let chain = Crypto::from_pem_chain(&pem_chain).expect("PEM chain should parse");
        assert_eq!(chain.len(), 2);

        let cert = cert(MILAN_VCEK);
        let der = Crypto::to_der(&cert).expect("DER encoding should succeed");
        let from_der = Crypto::from_der(&der).expect("DER parsing should succeed");
        assert_eq!(
            Crypto::to_der(&from_der).expect("Reparsed DER should encode"),
            der
        );

        let pem = Crypto::to_pem(&cert).expect("PEM encoding should succeed");
        let from_pem = Crypto::from_pem(pem.as_bytes()).expect("PEM parsing should succeed");
        assert_eq!(
            Crypto::to_der(&from_pem).expect("Reparsed PEM should encode as DER"),
            der
        );
    }

    #[test]
    fn certificate_parse_wrappers_reject_invalid_input() {
        let malformed_pem = b"-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n";

        Crypto::from_pem(b"not a pem").expect_err("Invalid PEM should fail");
        Crypto::from_pem_chain(malformed_pem).expect_err("Invalid PEM chain should fail");
        Crypto::from_der(b"not der").expect_err("Invalid DER should fail");
    }

    #[test]
    fn extension_lookup_rejects_malformed_oid() {
        let cert = cert(MILAN_VCEK);

        Crypto::get_extension_value_by_oid(&cert, "not-an-oid")
            .expect_err("Malformed OID should fail");
    }

    #[cfg(sync_crypto)]
    mod sync_tests {
        use super::super::verifier::Sync as Verifier;
        use super::*;

        #[test]
        fn full_chain_verifies() {
            <Crypto as CryptoBackend>::verify_chain(
                &[&cert(MILAN_ARK)],
                &[&cert(MILAN_ASK)],
                &cert(MILAN_VCEK),
            )
            .unwrap();
        }

        #[test]
        fn empty_trust_store_fails() {
            <Crypto as CryptoBackend>::verify_chain(&[], &[], &cert(MILAN_VCEK))
                .expect_err("Should fail with no trusted certs");
        }

        #[test]
        fn untrusted_intermediates_are_required() {
            <Crypto as CryptoBackend>::verify_chain(&[&cert(MILAN_ARK)], &[], &cert(MILAN_VCEK))
                .expect_err("VCEK should not verify without ASK intermediate");
        }

        #[test]
        fn self_signed_certificates() {
            <Crypto as CryptoBackend>::verify_chain(&[&cert(MILAN_ARK)], &[], &cert(MILAN_ARK))
                .unwrap();
        }

        #[test]
        fn verifier_trait_impl() {
            let ark = cert(MILAN_ARK);
            let ask = cert(MILAN_ASK);

            ark.verify(&ark).unwrap();
            ark.verify(&ask).unwrap();
        }
    }

    #[cfg(async_crypto)]
    mod async_tests {
        use super::super::verifier::Async as Verifier;
        use super::super::AsyncCryptoBackend;
        use super::*;

        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test;

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn full_chain_verifies() {
            <Crypto as AsyncCryptoBackend>::verify_chain(
                &[&cert(MILAN_ARK)],
                &[&cert(MILAN_ASK)],
                &cert(MILAN_VCEK),
            )
            .await
            .unwrap();
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn empty_trust_store_fails() {
            <Crypto as AsyncCryptoBackend>::verify_chain(&[], &[], &cert(MILAN_VCEK))
                .await
                .expect_err("Should fail with no trusted certs");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn untrusted_intermediates_are_required() {
            <Crypto as AsyncCryptoBackend>::verify_chain(
                &[&cert(MILAN_ARK)],
                &[],
                &cert(MILAN_VCEK),
            )
            .await
            .expect_err("VCEK should not verify without ASK intermediate");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn self_signed_certificates() {
            <Crypto as AsyncCryptoBackend>::verify_chain(
                &[&cert(MILAN_ARK)],
                &[],
                &cert(MILAN_ARK),
            )
            .await
            .unwrap();
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn verifier_trait_impl() {
            let ark = cert(MILAN_ARK);
            let ask = cert(MILAN_ASK);

            ark.verify(&ark).await.unwrap();
            ark.verify(&ask).await.unwrap();
        }
    }
}
