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

    /// Parse a certificate from DER-encoded data.
    fn from_der(der: &[u8]) -> Result<Self::Certificate>;

    /// Encode a certificate as DER.
    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>>;

    /// Verify a certificate chain from `trusted_certs` through `untrusted_chain` to `leaf`.
    fn verify_chain(
        trusted_certs: Vec<Self::Certificate>,
        untrusted_chain: Vec<Self::Certificate>,
        leaf: Self::Certificate,
    ) -> Result<()>;
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

    fn cert(pem: &[u8]) -> Certificate {
        Crypto::from_pem(pem).unwrap()
    }

    #[test]
    fn full_chain_verifies() {
        Crypto::verify_chain(
            vec![cert(MILAN_ARK)],
            vec![cert(MILAN_ASK)],
            cert(MILAN_VCEK),
        )
        .unwrap();
    }

    #[test]
    fn empty_trust_store_fails() {
        Crypto::verify_chain(vec![], vec![], cert(MILAN_VCEK))
            .expect_err("Should fail with no trusted certs");
    }

    #[test]
    fn untrusted_intermediates_are_required() {
        Crypto::verify_chain(vec![cert(MILAN_ARK)], vec![], cert(MILAN_VCEK))
            .expect_err("VCEK should not verify without ASK intermediate");
    }

    #[test]
    fn self_signed_certificates() {
        Crypto::verify_chain(vec![cert(MILAN_ARK)], vec![], cert(MILAN_ARK)).unwrap();
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
}
