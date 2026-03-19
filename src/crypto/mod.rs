// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic backend for certificate and attestation verification.
//!
//! Supports two backends via feature flags:
//! - `crypto_openssl` - OpenSSL-based (not available on WASM)
//! - `crypto_pure_rust` - Pure Rust (required for WASM)
//!
//! If both are enabled, `crypto_pure_rust` takes precedence.

#[cfg(not(any(feature = "crypto_openssl", feature = "crypto_pure_rust")))]
compile_error!("Either `crypto_openssl` or `crypto_pure_rust` feature must be enabled.");
#[cfg(all(target_arch = "wasm32", feature = "crypto_openssl"))]
compile_error!(
    "`crypto_openssl` is not supported on wasm32 targets. Use `crypto_pure_rust` instead."
);
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use crate::snp::report::AttestationReport;

/// Verifies that data was signed by the implementor's private key.
pub trait Verifier<T> {
    fn verify(&self, data: &T) -> Result<()>;
}

/// Crypto backend trait for certificate parsing and chain verification.
pub trait CryptoBackend {
    type Certificate: Verifier<Self::Certificate> + Verifier<AttestationReport>;

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

    /// Verify a certificate chain from `trusted_certs` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_certs: &[&Self::Certificate],
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
    ) -> Result<()>;

    /// Extract the SubjectPublicKeyInfo (DER-encoded) from the certificate.
    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>>;

    /// Extract an extension value by dotted-decimal OID.
    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>>;
}

#[cfg(feature = "crypto_openssl")]
mod crypto_openssl;
#[cfg(feature = "crypto_pure_rust")]
mod crypto_pure_rust;

// If both are enabled, prefer pure rust
#[cfg(all(feature = "crypto_openssl", not(feature = "crypto_pure_rust")))]
pub use crypto_openssl::Crypto;
#[cfg(feature = "crypto_pure_rust")]
pub use crypto_pure_rust::Crypto;

/// The certificate type for the active crypto backend.
pub type Certificate = <Crypto as CryptoBackend>::Certificate;

#[cfg(test)]
mod test {
    use zerocopy::{IntoBytes, TryFromBytes};
    use Crypto;

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
    fn full_chain_verifies() {
        Crypto::verify_chain(&[&cert(MILAN_ARK)], &[&cert(MILAN_ASK)], &cert(MILAN_VCEK)).unwrap();
    }

    #[test]
    fn empty_trust_store_fails() {
        Crypto::verify_chain(&[], &[], &cert(MILAN_VCEK))
            .expect_err("Should fail with no trusted certs");
    }

    #[test]
    fn untrusted_intermediates_are_required() {
        Crypto::verify_chain(&[&cert(MILAN_ARK)], &[], &cert(MILAN_VCEK))
            .expect_err("VCEK should not verify without ASK intermediate");
    }

    #[test]
    fn self_signed_certificates() {
        Crypto::verify_chain(&[&cert(MILAN_ARK)], &[], &cert(MILAN_ARK)).unwrap();
    }

    #[test]
    fn verifier_trait_impl() {
        let ark = cert(MILAN_ARK);
        let ask = cert(MILAN_ASK);

        // Self signed
        ark.verify(&ark).unwrap();
        // Signed by ARK
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
        let mut report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();

        // Corrupt a byte in the signed portion
        let report_bytes = report.as_mut_bytes();
        report_bytes[100] ^= 0xFF;

        vcek.verify(&report)
            .expect_err("Corrupted report should not verify");
    }

    #[test]
    fn corrupt_signature_fails() {
        let vcek = cert(MILAN_VCEK);
        let mut report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();

        // Flip a byte in the ECDSA r component
        report.signature.r[0] ^= 0xFF;

        vcek.verify(&report)
            .expect_err("Corrupt signature should not verify");
    }

    #[test]
    fn zeroed_signature_fails() {
        let vcek = cert(MILAN_VCEK);
        let mut report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();

        // Zero out both r and s
        report.signature.r.fill(0);
        report.signature.s.fill(0);

        vcek.verify(&report)
            .expect_err("Zeroed signature should not verify");
    }

    #[test]
    fn wrong_cert_rejects_signature() {
        // Genoa VCEK is not the correct signer for the Milan report
        let vcek = cert(GENOA_VCEK);
        let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();

        vcek.verify(&report)
            .expect_err("Wrong cert should not verify report");
    }

    #[test]
    fn extension_lookup_returns_expected_bootloader_value() {
        let vcek = cert(MILAN_VCEK);
        let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();
        let tcb = report.reported_tcb.as_milan_genoa();

        let bootloader = Crypto::get_extension_value_by_oid(&vcek, "1.3.6.1.4.1.3704.1.3.1")
            .expect("BootLoader OID lookup should succeed")
            .expect("BootLoader OID should be present in Milan VCEK");

        assert_eq!(bootloader, vec![0x02, 0x01, tcb.boot_loader]);
    }

    #[test]
    fn extension_lookup_returns_expected_hwid_value() {
        let vcek = cert(MILAN_VCEK);
        let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();

        let hwid = Crypto::get_extension_value_by_oid(&vcek, "1.3.6.1.4.1.3704.1.4")
            .expect("HWID OID lookup should succeed")
            .expect("HWID OID should be present in Milan VCEK");

        assert_eq!(hwid, report.chip_id.as_slice());
    }

    #[test]
    fn extension_lookup_returns_none_for_missing_oid() {
        let vcek = cert(MILAN_VCEK);

        let missing = Crypto::get_extension_value_by_oid(&vcek, "1.2.3.4.5.6.7.8.9")
            .expect("Missing OID lookup should not fail");

        assert!(missing.is_none());
    }

    #[test]
    fn extension_lookup_rejects_malformed_oid() {
        let vcek = cert(MILAN_VCEK);

        Crypto::get_extension_value_by_oid(&vcek, "not-an-oid")
            .expect_err("Malformed OID should fail");
    }

    #[test]
    fn pem_chain_parsing_preserves_input_order() {
        let mut pem_chain = Vec::new();
        pem_chain.extend_from_slice(MILAN_ASK);
        pem_chain.push(b'\n');
        pem_chain.extend_from_slice(MILAN_ARK);

        let chain = Crypto::from_pem_chain(&pem_chain).expect("PEM chain should parse");

        assert_eq!(chain.len(), 2);
        assert_eq!(
            Crypto::to_der(&chain[0]).expect("ASK DER should encode"),
            Crypto::to_der(&cert(MILAN_ASK)).expect("ASK fixture DER should encode")
        );
        assert_eq!(
            Crypto::to_der(&chain[1]).expect("ARK DER should encode"),
            Crypto::to_der(&cert(MILAN_ARK)).expect("ARK fixture DER should encode")
        );
    }

    #[test]
    fn pem_encoding_round_trips_through_from_pem() {
        let cert = cert(MILAN_VCEK);
        let pem = Crypto::to_pem(&cert).expect("PEM encoding should succeed");
        let reparsed = Crypto::from_pem(pem.as_bytes()).expect("PEM should parse");

        assert_eq!(
            Crypto::to_der(&reparsed).expect("Reparsed DER should encode"),
            Crypto::to_der(&cert).expect("Original DER should encode")
        );
    }
}
