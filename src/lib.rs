// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable TEE attestation verification library.
//!
//! Supports SEV-SNP attestation verification with pluggable crypto backends
//! (`crypto_openssl`, `crypto_pure_rust`, `crypto_webcrypto`) and optional
//! online certificate fetching from AMD KDS (`kds` feature).

pub(crate) mod crypto;
pub mod pinned_arks;
pub mod snp;
pub mod utils;

use crypto::{CertificateBackend, Crypto};

pub use crypto::Certificate;
pub use snp::report::AttestationReport;

pub fn certificate_from_pem(pem: &[u8]) -> Result<Certificate, Box<dyn std::error::Error>> {
    Crypto::from_pem(pem)
}

pub fn certificate_from_der(der: &[u8]) -> Result<Certificate, Box<dyn std::error::Error>> {
    Crypto::from_der(der)
}

#[cfg(feature = "kds")]
mod certificate_chain;
#[cfg(feature = "kds")]
mod kds;
#[cfg(feature = "kds")]
pub mod sev_verification;
#[cfg(feature = "kds")]
pub use certificate_chain::AmdCertificates;
#[cfg(feature = "kds")]
pub use sev_verification::SevVerifier;

#[cfg(all(target_arch = "wasm32", feature = "kds"))]
pub mod wasm;

#[cfg(test)]
mod tests {
    use crate::crypto::CertificateBackend;

    const MILAN_VCEK: &[u8] = include_bytes!("crypto/test_data/milan_vcek.pem");

    #[test]
    fn certificate_from_der_parses_der_encoded_certificate() {
        let cert = crate::certificate_from_pem(MILAN_VCEK).expect("PEM certificate should parse");
        let der = crate::crypto::Crypto::to_der(&cert).expect("DER encoding should succeed");
        let reparsed = crate::certificate_from_der(&der).expect("DER certificate should parse");

        assert_eq!(
            crate::crypto::Crypto::to_der(&reparsed).expect("Reparsed DER should encode"),
            der
        );
    }
}
