// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tee_attestation_verification_lib::crypto::{Crypto, CryptoBackend};
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

pub fn test_verify_attestation_suite() {
    let tampered_milan_attestation = {
        let mut tampered = MILAN_ATTESTATION.to_vec();
        // Flip some bits in the attestation report to cause signature verification to fail
        tampered[100] ^= 0xFF;
        tampered
    };

    let tests = [
        (
            "genoa_ok_pinned",
            GENOA_ATTESTATION,
            GENOA_VCEK,
            Some(GENOA_ASK),
            None,
            Ok(()),
        ),
        (
            "turin_ok_pinned",
            TURIN_ATTESTATION,
            TURIN_VCEK,
            Some(TURIN_ASK),
            None,
            Ok(()),
        ),
        (
            "milan_ok_pinned",
            MILAN_ATTESTATION,
            MILAN_VCEK,
            Some(MILAN_ASK),
            None,
            Ok(()),
        ),
        (
            "milan_invalid_root_certificate",
            MILAN_ATTESTATION,
            MILAN_VCEK,
            Some(MILAN_ASK),
            Some(MILAN_ASK),
            Err("Invalid root certificate"),
        ),
        (
            "milan_genoa_ask",
            MILAN_ATTESTATION,
            MILAN_VCEK,
            Some(GENOA_ASK),
            None,
            Err("Certificate chain error"),
        ),
        (
            "tampered_attestation",
            &tampered_milan_attestation,
            MILAN_VCEK,
            None,
            None,
            Err("Signature verification error"),
        ),
    ];

    for (tag, att, vcek, ask_opt, ark_opt, expected) in tests {
        let report = AttestationReport::read_from_bytes(att).unwrap();
        let vcek = Crypto::from_pem(vcek).unwrap();
        let ask = ask_opt.map(|ask| Crypto::from_pem(ask).unwrap());
        let ark = ark_opt.map(|ark| Crypto::from_pem(ark).unwrap());

        let result = tee_attestation_verification_lib::snp::verify::verify_attestation(
            &report,
            &vcek,
            ask.as_ref(),
            ark.as_ref(),
        );

        if let Err(e_str) = expected {
            let err = result.expect_err(&format!("{}: Expected to fail with {}", tag, e_str));
            assert!(
                err.to_string().contains(e_str),
                "{}: Expected error to contain '{}', got: {:?}",
                tag,
                e_str,
                err
            );
        } else {
            result.expect(&format!("{}: Expected verification to succeed", tag))
        };
    }
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
