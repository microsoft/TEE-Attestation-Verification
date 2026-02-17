// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tee_attestation_verification_lib::crypto::{Crypto, CryptoBackend};
use tee_attestation_verification_lib::snp::verify::SevVerificationError;
use tee_attestation_verification_lib::{AttestationReport, SevVerificationResult, SevVerifier};
use zerocopy::FromBytes;

// Attestation reports
pub const MILAN_ATTESTATION: &[u8] = include_bytes!("test_data/milan_attestation_report.bin");
pub const GENOA_ATTESTATION: &[u8] = include_bytes!("test_data/genoa_attestation_report.bin");
pub const TURIN_ATTESTATION: &[u8] = include_bytes!("test_data/turin_attestation_report.bin");

// ASK certificates
pub const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
pub const GENOA_ASK: &[u8] = include_bytes!("test_data/genoa_ask.pem");
pub const TURIN_ASK: &[u8] = include_bytes!("test_data/turin_ask.pem");

// VCEK certificates
pub const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
pub const GENOA_VCEK: &[u8] = include_bytes!("test_data/genoa_vcek.pem");
pub const TURIN_VCEK: &[u8] = include_bytes!("test_data/turin_vcek.pem");

pub fn verify_with_snp_verify(
    attestation_bytes: &[u8],
    ask_pem: &[u8],
    vcek_pem: &[u8],
) -> Result<(), SevVerificationError> {
    let attestation_report = AttestationReport::read_from_bytes(attestation_bytes)
        .map_err(|e| SevVerificationError::SignatureVerificationError(format!("{:?}", e)))?;

    let ask = Crypto::from_pem(ask_pem)
        .map_err(|e| SevVerificationError::CertificateChainError(e.to_string()))?;
    let vcek = Crypto::from_pem(vcek_pem)
        .map_err(|e| SevVerificationError::CertificateChainError(e.to_string()))?;

    tee_attestation_verification_lib::snp::verify::verify_attestation(
        &attestation_report,
        &vcek,
        Some(&ask),
        None,
    )
}

pub async fn verify_attestation_bytes(bytes: &[u8]) -> Result<SevVerificationResult, String> {
    let attestation_report = AttestationReport::read_from_bytes(bytes)
        .map_err(|e| format!("Failed to parse attestation report from bytes: {:?}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {e}"))?;

    verifier
        .verify_attestation(&attestation_report)
        .await
        .map_err(|e| format!("Verification call failed: {e}"))
}

pub async fn verify_milan_attestation() -> Result<SevVerificationResult, String> {
    verify_attestation_bytes(MILAN_ATTESTATION).await
}

pub async fn verify_genoa_attestation() -> Result<SevVerificationResult, String> {
    verify_attestation_bytes(GENOA_ATTESTATION).await
}

pub async fn verify_turin_attestation() -> Result<SevVerificationResult, String> {
    verify_attestation_bytes(TURIN_ATTESTATION).await
}
