// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tee_attestation_verification_lib::crypto::{Crypto, CryptoBackend};
use tee_attestation_verification_lib::{AttestationReport, SevVerificationResult, SevVerifier};
use zerocopy::FromBytes;

// Attestation reports
const MILAN_ATTESTATION: &[u8] = include_bytes!("test_data/milan_attestation_report.bin");
const GENOA_ATTESTATION: &[u8] = include_bytes!("test_data/genoa_attestation_report.bin");
const TURIN_ATTESTATION: &[u8] = include_bytes!("test_data/turin_attestation_report.bin");

// ASK certificates
const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
const GENOA_ASK: &[u8] = include_bytes!("test_data/genoa_ask.pem");
const TURIN_ASK: &[u8] = include_bytes!("test_data/turin_ask.pem");

// VCEK certificates
const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
const GENOA_VCEK: &[u8] = include_bytes!("test_data/genoa_vcek.pem");
const TURIN_VCEK: &[u8] = include_bytes!("test_data/turin_vcek.pem");

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

// Offline verification functions (synchronous, using pinned ARKs)

fn verify_offline(
    attestation_bytes: &[u8],
    ask_pem: &[u8],
    vcek_pem: &[u8],
) -> Result<SevVerificationResult, String> {
    let attestation_report = AttestationReport::read_from_bytes(attestation_bytes)
        .map_err(|e| format!("Failed to parse attestation report: {:?}", e))?;

    let ask =
        Crypto::from_pem(ask_pem).map_err(|e| format!("Failed to parse ASK certificate: {}", e))?;
    let vcek = Crypto::from_pem(vcek_pem)
        .map_err(|e| format!("Failed to parse VCEK certificate: {}", e))?;

    SevVerifier::verify_attestation_with_certs(&attestation_report, ask, vcek)
        .map_err(|e| format!("Offline verification failed: {}", e))
}

pub fn verify_milan_attestation_offline() -> Result<SevVerificationResult, String> {
    verify_offline(MILAN_ATTESTATION, MILAN_ASK, MILAN_VCEK)
}

pub fn verify_genoa_attestation_offline() -> Result<SevVerificationResult, String> {
    verify_offline(GENOA_ATTESTATION, GENOA_ASK, GENOA_VCEK)
}

pub fn verify_turin_attestation_offline() -> Result<SevVerificationResult, String> {
    verify_offline(TURIN_ATTESTATION, TURIN_ASK, TURIN_VCEK)
}
