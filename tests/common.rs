// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tee_attestation_verification_lib::crypto::{Crypto, CryptoBackend};
use tee_attestation_verification_lib::snp::verify::{self, ChainVerification};
use tee_attestation_verification_lib::{AttestationReport, SevVerifier};
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
    let milan_ask = Crypto::from_pem(MILAN_ASK).unwrap();
    let genoa_ask = Crypto::from_pem(GENOA_ASK).unwrap();
    let turin_ask = Crypto::from_pem(TURIN_ASK).unwrap();

    let tests = [
        (
            "genoa_ok_pinned",
            GENOA_ATTESTATION,
            GENOA_VCEK,
            ChainVerification::WithPinnedArk { ask: &genoa_ask },
            Ok(()),
        ),
        (
            "turin_ok_pinned",
            TURIN_ATTESTATION,
            TURIN_VCEK,
            ChainVerification::WithPinnedArk { ask: &turin_ask },
            Ok(()),
        ),
        (
            "milan_ok_pinned",
            MILAN_ATTESTATION,
            MILAN_VCEK,
            ChainVerification::WithPinnedArk { ask: &milan_ask },
            Ok(()),
        ),
        (
            "milan_invalid_root_certificate",
            MILAN_ATTESTATION,
            MILAN_VCEK,
            ChainVerification::WithProvidedArk {
                ask: &milan_ask,
                ark: &milan_ask,
            },
            Err("Invalid root certificate"),
        ),
        (
            "milan_genoa_ask",
            MILAN_ATTESTATION,
            MILAN_VCEK,
            ChainVerification::WithPinnedArk { ask: &genoa_ask },
            Err("Certificate chain error"),
        ),
        (
            "tampered_attestation",
            &tampered_milan_attestation,
            MILAN_VCEK,
            ChainVerification::Skip,
            Err("Signature verification error"),
        ),
    ];

    for (tag, att, vcek, chain, expected) in tests {
        let report = AttestationReport::read_from_bytes(att).unwrap();
        let vcek = Crypto::from_pem(vcek).unwrap();
        let result = verify::verify_attestation(&report, &vcek, chain);

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

pub async fn verify_attestation_bytes(bytes: &[u8]) -> Result<(), String> {
    let attestation_report = AttestationReport::read_from_bytes(bytes)
        .map_err(|e| format!("Failed to read attestation report: {:?}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {:?}", e))?;

    verifier
        .verify_attestation(&attestation_report)
        .await
        .map_err(|e| format!("Verification call failed: {:?}", e))
}

pub async fn verify_milan_attestation() -> Result<(), String> {
    verify_attestation_bytes(MILAN_ATTESTATION).await
}

pub async fn verify_genoa_attestation() -> Result<(), String> {
    verify_attestation_bytes(GENOA_ATTESTATION).await
}

pub async fn verify_turin_attestation() -> Result<(), String> {
    verify_attestation_bytes(TURIN_ATTESTATION).await
}
