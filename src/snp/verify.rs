// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::crypto::{Certificate, CertificateBackend, Crypto};
use crate::{snp, snp::utils::Oid, AttestationReport};

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

//ChainVerification::Skip skips chain verification and only verifies report signature + TCB using VCEK.
//ChainVerification::WithPinnedArk verifies chain with pinned ARK for the processor model.
//ChainVerification::WithProvidedArk verifies chain with caller-provided ARK after validating its public key matches pinned ARK.
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

#[cfg(sync_crypto)]
pub mod sync {
    use crate::crypto::verifier::Sync as Verifier;
    use crate::crypto::{Certificate, Crypto, CryptoBackend};
    use crate::{snp, AttestationReport};

    use super::{ark_matches_pinned, verify_tcb_values, ChainVerification, VerificationError};

    pub fn verify_attestation(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
        chain_verification: &ChainVerification<'_>,
    ) -> Result<(), VerificationError> {
        let generation = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        )
        .map_err(|e| VerificationError::UnsupportedProcessor(format!("{:?}", e)))?;

        match chain_verification {
            ChainVerification::WithProvidedArk { ask, ark } => {
                ark_matches_pinned(generation, ark)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;

                Crypto::verify_chain(&[ark], &[ask], vcek)
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::WithPinnedArk { ask } => {
                let pinned_ark = crate::pinned_arks::get_ark(generation)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;
                Crypto::verify_chain(&[&pinned_ark], &[ask], vcek)
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::Skip => {}
        };

        vcek.verify(attestation_report)
            .map_err(|e| VerificationError::SignatureVerificationError(format!("{:?}", e)))?;

        verify_tcb_values(vcek, attestation_report)
            .map_err(|e| VerificationError::TcbVerificationError(format!("{:?}", e)))?;

        Ok(())
    }
}

#[cfg(async_crypto)]
pub mod asynchronous {
    use crate::crypto::verifier::Async as Verifier;
    use crate::crypto::{AsyncCryptoBackend, Certificate, Crypto};
    use crate::{snp, AttestationReport};

    use super::{ark_matches_pinned, verify_tcb_values, ChainVerification, VerificationError};

    pub async fn verify_attestation(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
        chain_verification: &ChainVerification<'_>,
    ) -> Result<(), VerificationError> {
        let generation = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        )
        .map_err(|e| VerificationError::UnsupportedProcessor(format!("{:?}", e)))?;

        match chain_verification {
            ChainVerification::WithProvidedArk { ask, ark } => {
                ark_matches_pinned(generation, ark)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;

                Crypto::verify_chain(&[ark], &[ask], vcek)
                    .await
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::WithPinnedArk { ask } => {
                let pinned_ark = crate::pinned_arks::get_ark(generation)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;
                Crypto::verify_chain(&[&pinned_ark], &[ask], vcek)
                    .await
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::Skip => {}
        };

        vcek.verify(attestation_report)
            .await
            .map_err(|e| VerificationError::SignatureVerificationError(format!("{:?}", e)))?;

        verify_tcb_values(vcek, attestation_report)
            .map_err(|e| VerificationError::TcbVerificationError(format!("{:?}", e)))?;

        Ok(())
    }
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

    let check_u8_ext = |oid: &str, expected: u8| -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ext_value) = Crypto::get_extension_value_by_oid(vcek, oid)? {
            let expected = [expected];
            if check_ext(&ext_value, &expected) {
                return Ok(());
            }
            return Err(format!(
                "Mismatched value OID {} : {} != {}",
                oid,
                crate::utils::to_hex(&ext_value),
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
            let bl_oid = Oid::BootLoader.as_str();
            check_u8_ext(bl_oid, tcb.boot_loader)
                .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

            let tee_oid = Oid::Tee.as_str();
            check_u8_ext(tee_oid, tcb.tee)
                .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

            let snp_oid = Oid::Snp.as_str();
            check_u8_ext(snp_oid, tcb.snp)
                .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

            let ucode_oid = Oid::Ucode.as_str();
            check_u8_ext(ucode_oid, tcb.microcode)
                .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;
        }
        snp::model::Generation::Turin => {
            let tcb = attestation_report.reported_tcb.as_turin();
            let bl_oid = Oid::BootLoader.as_str();
            check_u8_ext(bl_oid, tcb.boot_loader)
                .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

            let tee_oid = Oid::Tee.as_str();
            check_u8_ext(tee_oid, tcb.tee)
                .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

            let snp_oid = Oid::Snp.as_str();
            check_u8_ext(snp_oid, tcb.snp)
                .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

            let ucode_oid = Oid::Ucode.as_str();
            check_u8_ext(ucode_oid, tcb.microcode)
                .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;

            let fmc_oid = Oid::Fmc.as_str();
            check_u8_ext(fmc_oid, tcb.fmc)
                .map_err(|e| format!("Error verifying TCB FMC: {}", e))?;
        }
    }

    let hwid_oid = Oid::HwId.as_str();
    if let Some(cert_hwid) = Crypto::get_extension_value_by_oid(vcek, hwid_oid)? {
        if !check_ext(&cert_hwid, attestation_report.chip_id.as_slice()) {
            return Err("Report TCB ID and Certificate ID mismatch".into());
        }
    }

    Ok(())
}
