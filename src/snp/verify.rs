// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::crypto::{Certificate, Crypto, CryptoBackend, Verifier};
use crate::{snp, snp::utils::Oid, AttestationReport};
use std::collections::HashMap;

#[derive(Debug)]
pub enum VerificationError {
    UnsupportedProcessor(String),
    InvalidRootCertificate(String),
    CertificateChainError(String),
    SignatureVerificationError(String),
    TcbVerificationError(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProcessor(e) => write!(f, "Unsupported processor: {}", e),
            Self::InvalidRootCertificate(e) => write!(f, "Invalid root certificate: {}", e),
            Self::CertificateChainError(e) => write!(f, "Certificate chain error: {}", e),
            Self::SignatureVerificationError(e) => write!(f, "Signature verification error: {}", e),
            Self::TcbVerificationError(e) => write!(f, "TCB verification error: {}", e),
        }
    }
}

impl std::error::Error for VerificationError {}

pub enum ChainVerification<'a> {
    Skip,
    WithPinnedArk {
        ask: &'a Certificate,
    },
    WithProvidedArk {
        ask: &'a Certificate,
        ark: &'a Certificate,
    },
}

// Verifies the attestation report using the provided ARK, ASK, and VCEK certificates.
// If verification is successful, returns Ok(()). Otherwise, returns a VerificationError with details of the step which failed.
// - Use ChainVerification::Skip to skip chain verification and only verify report signature + TCB using VCEK.
// - Use ChainVerification::WithPinnedArk to verify chain with pinned ARK for the processor model.
// - Use ChainVerification::WithProvidedArk to verify chain with caller-provided ARK after validating its public key matches pinned ARK.
pub fn verify_attestation(
    attestation_report: &AttestationReport,
    vcek: &Certificate,
    chain_verification: ChainVerification<'_>,
) -> Result<(), VerificationError> {
    let generation = snp::model::Generation::from_family_and_model(
        attestation_report.cpuid_fam_id,
        attestation_report.cpuid_mod_id,
    )
    .map_err(|e| VerificationError::UnsupportedProcessor(format!("{:?}", e)))?;

    match chain_verification {
        ChainVerification::WithProvidedArk { ask, ark } => {
            // If ARK is provided, verify it matches the pinned ARK for this generation
            ark_matches_pinned(generation, ark)
                .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;

            // Verify the certificate chain: ARK -> ASK -> VCEK
            Crypto::verify_chain(&[ark], &[ask], vcek)
                .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
        }
        ChainVerification::WithPinnedArk { ask } => {
            // No ARK provided, use pinned ARK for chain verification
            let pinned_ark = crate::pinned_arks::get_ark(generation)
                .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;
            Crypto::verify_chain(&[&pinned_ark], &[ask], vcek)
                .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
        }
        ChainVerification::Skip => {
            // No ASK provided, skip chain verification
        }
    };

    // Verify the attestation report signature using the VCEK
    vcek.verify(attestation_report)
        .map_err(|e| VerificationError::SignatureVerificationError(format!("{:?}", e)))?;

    // Verify that the TCB values in the VCEK match those reported in the attestation report
    verify_tcb_values(vcek, attestation_report)
        .map_err(|e| VerificationError::TcbVerificationError(format!("{:?}", e)))?;

    Ok(())
}

pub(crate) fn ark_matches_pinned(
    generation: snp::model::Generation,
    ark: &Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    let pinned_ark = crate::pinned_arks::get_ark(generation)?;
    let pinned_key = Crypto::get_public_key(&pinned_ark)?;
    let provided_key = Crypto::get_public_key(ark)?;
    if pinned_key != provided_key {
        return Err(format!("Provided ARK does not match pinned ARK for {}", generation).into());
    }
    Ok(())
}

pub(crate) fn verify_tcb_values(
    vcek: &Certificate,
    attestation_report: &AttestationReport,
) -> Result<(), Box<dyn std::error::Error>> {
    use x509_cert::der::Decode;

    let vcek_der = Crypto::to_der(vcek)?;
    let vcek = x509_cert::Certificate::from_der(&vcek_der)
        .map_err(|e| format!("Failed to parse VCEK as x509-cert: {}", e))?;

    // Get extensions from VCEK certificate
    let extensions = vcek
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or("VCEK certificate has no extensions")?;

    // Build a HashMap of OID -> extension value for easy lookup
    let mut ext_map: HashMap<String, &[u8]> = HashMap::new();
    for ext in extensions.iter() {
        let oid_str = ext.extn_id.to_string();
        ext_map.insert(oid_str, ext.extn_value.as_bytes());
    }

    // Helper to check extension value (handles different ASN.1 wrapping)
    let check_ext = |ext_value: &[u8], expected: &[u8]| -> bool {
        // Try direct match
        if ext_value == expected {
            return true;
        }
        // prefix match
        if ext_value.len() < expected.len()
            && ext_value == &expected[..ext_value.len()]
            && expected[ext_value.len()..].iter().all(|e| *e == 0)
        {
            return true;
        }
        // Try with INTEGER tag (0x02) wrapper
        if ext_value.len() >= 2 && ext_value[0] == 0x02 {
            if let Some(&last) = ext_value.last() {
                if expected.len() == 1 && last == expected[0] {
                    return true;
                }
            }
        }
        // Try with OCTET STRING tag (0x04) wrapper
        if ext_value.len() >= 2 && ext_value[0] == 0x04 && ext_value.len() >= 2 {
            return &ext_value[2..] == expected;
        }
        false
    };

    let check_u8_ext = |oid: String, expected: u8| -> Result<(), Box<dyn std::error::Error>> {
        if let Some(&ext_value) = ext_map.get(&oid.to_string()) {
            let expected = [expected];
            if check_ext(ext_value, &expected) {
                return Ok(());
            }
            return Err(format!(
                "Mismatched value OID {} : {} != {}",
                oid,
                crate::utils::to_hex(ext_value),
                crate::utils::to_hex(&expected)
            )
            .into());
        }
        Err(format!("Extension OID {} not found in VCEK", oid).into())
    };

    let gen = snp::model::Generation::from_family_and_model(
        attestation_report.cpuid_fam_id,
        attestation_report.cpuid_mod_id,
    )?;
    match gen {
        snp::model::Generation::Milan | snp::model::Generation::Genoa => {
            let tcb = attestation_report.reported_tcb.as_milan_genoa();
            let bl_oid = Oid::BootLoader.oid().to_string();
            check_u8_ext(bl_oid, tcb.boot_loader)
                .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

            let tee_oid = Oid::Tee.oid().to_string();
            check_u8_ext(tee_oid, tcb.tee)
                .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

            let snp_oid = Oid::Snp.oid().to_string();
            check_u8_ext(snp_oid, tcb.snp)
                .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

            let ucode_oid = Oid::Ucode.oid().to_string();
            check_u8_ext(ucode_oid, tcb.microcode)
                .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;
        }
        snp::model::Generation::Turin => {
            let tcb = attestation_report.reported_tcb.as_turin();
            let bl_oid = Oid::BootLoader.oid().to_string();
            check_u8_ext(bl_oid, tcb.boot_loader)
                .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

            let tee_oid = Oid::Tee.oid().to_string();
            check_u8_ext(tee_oid, tcb.tee)
                .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

            let snp_oid = Oid::Snp.oid().to_string();
            check_u8_ext(snp_oid, tcb.snp)
                .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

            let ucode_oid = Oid::Ucode.oid().to_string();
            check_u8_ext(ucode_oid, tcb.microcode)
                .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;

            let fmc_oid = Oid::Fmc.oid().to_string();
            check_u8_ext(fmc_oid, tcb.fmc)
                .map_err(|e| format!("Error verifying TCB FMC: {}", e))?;
        }
    }

    let hwid_oid = Oid::HwId.oid().to_string();
    if let Some(&cert_hwid) = ext_map.get(&hwid_oid) {
        if !check_ext(cert_hwid, attestation_report.chip_id.as_slice()) {
            return Err("Report TCB ID and Certificate ID mismatch".into());
        }
    }

    Ok(())
}
