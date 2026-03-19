// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tee_attestation_verification_lib::snp::verify::{self, ChainVerification};
#[cfg(any(target_family = "wasm", feature = "online"))]
use tee_attestation_verification_lib::SevVerifier;
use tee_attestation_verification_lib::{
    certificate_extension_value_by_oid, certificate_from_pem, AttestationReport,
};
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
    let milan_vcek = certificate_from_pem(MILAN_VCEK).unwrap();
    let milan_report = AttestationReport::read_from_bytes(MILAN_ATTESTATION).unwrap();
    let milan_tcb = milan_report.reported_tcb.as_milan_genoa();
    let tampered_milan_attestation = {
        let mut tampered = MILAN_ATTESTATION.to_vec();
        // Flip some bits in the attestation report to cause signature verification to fail
        tampered[100] ^= 0xFF;
        tampered
    };
    let milan_ask = certificate_from_pem(MILAN_ASK).unwrap();
    let genoa_ask = certificate_from_pem(GENOA_ASK).unwrap();
    let turin_ask = certificate_from_pem(TURIN_ASK).unwrap();

    let milan_bootloader =
        certificate_extension_value_by_oid(&milan_vcek, "1.3.6.1.4.1.3704.1.3.1")
            .expect("BootLoader OID lookup should succeed")
            .expect("BootLoader OID should be present in Milan VCEK");
    assert_eq!(milan_bootloader, vec![0x02, 0x01, milan_tcb.boot_loader]);

    let milan_hwid = certificate_extension_value_by_oid(&milan_vcek, "1.3.6.1.4.1.3704.1.4")
        .expect("HWID OID lookup should succeed")
        .expect("HWID OID should be present in Milan VCEK");
    assert_eq!(milan_hwid, milan_report.chip_id.as_slice());

    assert!(
        certificate_extension_value_by_oid(&milan_vcek, "1.2.3.4.5.6.7.8.9")
            .expect("Missing OID lookup should not fail")
            .is_none()
    );
    certificate_extension_value_by_oid(&milan_vcek, "not-an-oid")
        .expect_err("Malformed OID should fail");

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
        let vcek = certificate_from_pem(vcek).unwrap();
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

#[cfg(any(target_family = "wasm", feature = "online"))]
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

#[cfg(any(target_family = "wasm", feature = "online"))]
pub async fn verify_milan_attestation() -> Result<(), String> {
    verify_attestation_bytes(MILAN_ATTESTATION).await
}

#[cfg(any(target_family = "wasm", feature = "online"))]
pub async fn verify_genoa_attestation() -> Result<(), String> {
    verify_attestation_bytes(GENOA_ATTESTATION).await
}

#[cfg(any(target_family = "wasm", feature = "online"))]
pub async fn verify_turin_attestation() -> Result<(), String> {
    verify_attestation_bytes(TURIN_ATTESTATION).await
}
