//! WASM-only AMD SEV-SNP Attestation Verification
//!
//! This implementation is designed to be compiled only for wasm32 and uses
//! wasm-bindgen for fetching KDS artifacts via an extension-provided JS bridge.
use crate::certificate_chain::AmdCertificates;
use crate::crypto::{Certificate, Crypto, CryptoBackend};
use crate::{snp, AttestationReport};

use asn1_rs::{oid, Oid};
use log::{error, info};
use std::collections::HashMap;

/// Result of AMD SEV-SNP attestation verification
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SevVerificationResult {
    /// Whether the attestation passed all verification checks
    pub is_valid: bool,
    /// Detailed verification status for each component
    pub details: SevVerificationDetails,
    /// Error messages if verification failed
    pub errors: Vec<String>,
}

/// Detailed verification results for AMD SEV-SNP attestation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SevVerificationDetails {
    /// Whether the processor model was identified successfully
    pub processor_identified: bool,
    /// Whether AMD certificates were fetched successfully  
    pub certificates_fetched: bool,
    /// Whether the certificate chain is valid (ARK -> ASK -> VCEK)
    pub certificate_chain_valid: bool,
    /// Whether the attestation signature is valid
    pub signature_valid: bool,
    /// Whether TCB values match certificate extensions
    pub tcb_valid: bool,
    /// Processor model identified from the attestation report
    pub processor_model: Option<String>,
}

/// SEV-SNP OID extensions for VCEK certificate verification
/// These OIDs are used to extract TCB values from X.509 certificate extensions
enum SnpOid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
    Fmc,
}

impl SnpOid {
    fn oid(&self) -> Oid<'_> {
        match self {
            SnpOid::BootLoader => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1),
            SnpOid::Tee => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2),
            SnpOid::Snp => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3),
            SnpOid::Ucode => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8),
            SnpOid::HwId => oid!(1.3.6 .1 .4 .1 .3704 .1 .4),
            SnpOid::Fmc => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .9),
        }
    }
}

/// WASM SEV verifier (only compiled for wasm32)
pub struct SevVerifier {
    amd_certificates: AmdCertificates,
}

impl SevVerifier {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_arch = "wasm32")]
        Self::init_wasm_logging();
        let amd_certificates = AmdCertificates::new().await?;
        Ok(Self { amd_certificates })
    }

    pub async fn with_cache() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_arch = "wasm32")]
        Self::init_wasm_logging();
        let amd_certificates = AmdCertificates::with_cache(true).await?;
        Ok(Self { amd_certificates })
    }

    #[cfg(target_arch = "wasm32")]
    /// Initialize wasm logging and panic hook once. Only available when the
    /// `wasm` feature is enabled. No-op on non-wasm builds or when the feature
    /// isn't enabled.
    fn init_wasm_logging() {
        {
            static INIT: std::sync::Once = std::sync::Once::new();
            INIT.call_once(|| {
                // Route panics to console.error
                console_error_panic_hook::set_once();
                // Initialize the wasm logger to forward `log` records to console.log
                wasm_logger::init(wasm_logger::Config::new(log::Level::Info));
            });
        }
    }

    pub async fn verify_attestation(
        &mut self,
        attestation_report: &AttestationReport,
    ) -> Result<SevVerificationResult, Box<dyn std::error::Error>> {
        let mut result = SevVerificationResult {
            is_valid: false,
            details: SevVerificationDetails {
                processor_identified: false,
                certificates_fetched: false,
                certificate_chain_valid: false,
                signature_valid: false,
                tcb_valid: false,
                processor_model: None,
            },
            errors: Vec::new(),
        };

        // Step 1: Identify processor model
        let processor_model = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        );
        if processor_model.is_err() {
            let error = format!(
                "Unsupported processor family/model: {} / {}",
                attestation_report.cpuid_fam_id, attestation_report.cpuid_mod_id
            );
            result.errors.push(error.clone());
            error!("{}", error);
            return Ok(result);
        }

        let processor_model = processor_model.unwrap();
        result.details.processor_identified = true;
        result.details.processor_model = Some(processor_model.to_string());

        // Step 2: Get VCEK certificate for this processor (includes chain verification)
        let vcek = match self
            .amd_certificates
            .get_vcek(processor_model, attestation_report)
            .await
        {
            Ok(cert) => {
                result.details.certificates_fetched = true;
                result.details.certificate_chain_valid = true;
                info!("VCEK certificate fetched and verified successfully");
                cert
            }
            Err(e) => {
                let msg = format!("Failed to fetch/verify VCEK certificate: {}", e);
                result.errors.push(msg.clone());
                error!("{}", msg);
                return Ok(result);
            }
        };

        // Step 3: Verify attestation signature
        if let Err(e) = Self::verify_attestation_signature(attestation_report, &vcek) {
            let msg = format!("Signature verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(result);
        }
        result.details.signature_valid = true;

        // Step 4: Verify TCB values
        if let Err(e) = Self::verify_tcb_values(&vcek, attestation_report) {
            let msg = format!("TCB verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(result);
        }
        result.details.tcb_valid = true;

        result.is_valid = true;
        if result.is_valid {
            info!("AMD SEV-SNP verification PASSED");
        } else {
            error!("AMD SEV-SNP verification FAILED: {:?}", result.errors);
        }
        Ok(result)
    }

    fn verify_attestation_signature(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::crypto::Verifier;
        vcek.verify(attestation_report)
            .map_err(|e| format!("Failed to verify attestation signature: {}", e).into())
    }

    fn verify_tcb_values(
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
                    hex::encode(ext_value),
                    hex::encode(&expected)
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
                let bl_oid = SnpOid::BootLoader.oid().to_string();
                check_u8_ext(bl_oid, tcb.boot_loader)
                    .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

                let tee_oid = SnpOid::Tee.oid().to_string();
                check_u8_ext(tee_oid, tcb.tee)
                    .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

                let snp_oid = SnpOid::Snp.oid().to_string();
                check_u8_ext(snp_oid, tcb.snp)
                    .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

                let ucode_oid = SnpOid::Ucode.oid().to_string();
                check_u8_ext(ucode_oid, tcb.microcode)
                    .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;
            }
            snp::model::Generation::Turin => {
                let tcb = attestation_report.reported_tcb.as_turin();
                let bl_oid = SnpOid::BootLoader.oid().to_string();
                check_u8_ext(bl_oid, tcb.boot_loader)
                    .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

                let tee_oid = SnpOid::Tee.oid().to_string();
                check_u8_ext(tee_oid, tcb.tee)
                    .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

                let snp_oid = SnpOid::Snp.oid().to_string();
                check_u8_ext(snp_oid, tcb.snp)
                    .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

                let ucode_oid = SnpOid::Ucode.oid().to_string();
                check_u8_ext(ucode_oid, tcb.microcode)
                    .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;

                let fmc_oid = SnpOid::Fmc.oid().to_string();
                check_u8_ext(fmc_oid, tcb.fmc)
                    .map_err(|e| format!("Error verifying TCB FMC: {}", e))?;
            }
        }

        let hwid_oid = SnpOid::HwId.oid().to_string();
        if let Some(&cert_hwid) = ext_map.get(&hwid_oid) {
            if !check_ext(cert_hwid, attestation_report.chip_id.as_slice()) {
                return Err("Report TCB ID and Certificate ID mismatch".into());
            }
        }

        Ok(())
    }
}
