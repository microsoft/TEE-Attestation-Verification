// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic backend for certificate and attestation verification.
//!
//! Supports crypto backends via feature flags:
//! - `crypto_openssl` - OpenSSL-based (not available on WASM)
//! - `crypto_pure_rust` - Pure Rust
//! - `crypto_webcrypto` - WebCrypto-based async verification for WASM

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use crate::snp::report::AttestationReport;

pub mod verifier {
    use super::Result;

    /// Verifies that data was signed by the implementor's private key.
    pub(crate) trait Sync<T> {
        fn verify(&self, data: &T) -> Result<()>;
    }

    /// Asynchronously verifies that data was signed by the implementor's private key.
    pub(crate) trait Async<T> {
        fn verify(&self, data: &T) -> impl std::future::Future<Output = Result<()>>;
    }

    impl<V, T> Async<T> for V
    where
        V: Sync<T>,
    {
        async fn verify(&self, data: &T) -> Result<()> {
            Sync::verify(self, data)
        }
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

    /// Extract an extension value by dotted-decimal OID.
    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>>;
}

/// Backend-internal trait for certificate verification operations.
pub trait CryptoBackend: CertificateBackend
where
    <Self as CertificateBackend>::Certificate: verifier::Sync<<Self as CertificateBackend>::Certificate>
        + verifier::Sync<AttestationReport>,
{
    /// Verify a certificate chain from `trusted_certs` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_certs: &[&<Self as CertificateBackend>::Certificate],
        untrusted_chain: &[&<Self as CertificateBackend>::Certificate],
        leaf: &<Self as CertificateBackend>::Certificate,
    ) -> Result<()>;
}

/// Backend-internal trait for asynchronous certificate verification operations.
pub(crate) trait AsyncCryptoBackend {
    type Certificate: Clone
        + verifier::Async<Self::Certificate>
        + verifier::Async<AttestationReport>;

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
        + verifier::Sync<AttestationReport>
        + verifier::Async<<C as CertificateBackend>::Certificate>
        + verifier::Async<AttestationReport>,
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
    use crate::AttestationReport;
    use zerocopy::{IntoBytes, TryFromBytes};

    use super::Crypto;
    use super::*;

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
    const MILAN_REPORT: &[u8] = include_bytes!("test_data/milan_attestation_report.bin");
    const GENOA_VCEK: &[u8] = include_bytes!("test_data/genoa_vcek.pem");

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

        #[test]
        fn attestation_report_signature_verifies() {
            let vcek = cert(MILAN_VCEK);
            let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
                .expect("Failed to parse attestation report")
                .clone();
            vcek.verify(&report).unwrap();
        }

        #[test]
        fn corrupted_report_fails_to_verify() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            let report_bytes = report.as_mut_bytes();
            report_bytes[100] ^= 0xFF;

            vcek.verify(&report)
                .expect_err("Corrupted report should not verify");
        }

        #[test]
        fn corrupt_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            report.signature.r[0] ^= 0xFF;

            vcek.verify(&report)
                .expect_err("Corrupt signature should not verify");
        }

        #[test]
        fn zeroed_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            report.signature.r.fill(0);
            report.signature.s.fill(0);

            vcek.verify(&report)
                .expect_err("Zeroed signature should not verify");
        }

        #[cfg(crypto_backend = "crypto_pure_rust")]
        #[test]
        fn nonzero_r_scalar_padding_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            report.signature.r[48] = 1;

            let err = vcek
                .verify(&report)
                .expect_err("Nonzero r scalar padding should not verify");
            assert!(
                err.to_string().contains("Invalid r scalar padding"),
                "expected r scalar padding error, got: {err}"
            );
        }

        #[cfg(crypto_backend = "crypto_pure_rust")]
        #[test]
        fn nonzero_s_scalar_padding_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            report.signature.s[48] = 1;

            let err = vcek
                .verify(&report)
                .expect_err("Nonzero s scalar padding should not verify");
            assert!(
                err.to_string().contains("Invalid s scalar padding"),
                "expected s scalar padding error, got: {err}"
            );
        }

        #[test]
        fn wrong_cert_rejects_signature() {
            let vcek = cert(GENOA_VCEK);
            let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
                .expect("Failed to parse attestation report")
                .clone();

            vcek.verify(&report)
                .expect_err("Wrong cert should not verify report");
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

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn attestation_report_signature_verifies() {
            let vcek = cert(MILAN_VCEK);
            let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
                .expect("Failed to parse attestation report")
                .clone();
            vcek.verify(&report).await.unwrap();
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn corrupted_report_fails_to_verify() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            let report_bytes = report.as_mut_bytes();
            report_bytes[100] ^= 0xFF;

            vcek.verify(&report)
                .await
                .expect_err("Corrupted report should not verify");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn corrupt_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            report.signature.r[0] ^= 0xFF;

            vcek.verify(&report)
                .await
                .expect_err("Corrupt signature should not verify");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn zeroed_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report: AttestationReport =
                AttestationReport::try_read_from_bytes(MILAN_REPORT)
                    .expect("Failed to parse attestation report")
                    .clone();

            report.signature.r.fill(0);
            report.signature.s.fill(0);

            vcek.verify(&report)
                .await
                .expect_err("Zeroed signature should not verify");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn wrong_cert_rejects_signature() {
            let vcek = cert(GENOA_VCEK);
            let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
                .expect("Failed to parse attestation report")
                .clone();

            vcek.verify(&report)
                .await
                .expect_err("Wrong cert should not verify report");
        }
    }
}
