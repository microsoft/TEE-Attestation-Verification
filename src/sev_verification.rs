// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WASM-only AMD SEV-SNP Attestation Verification
//!
//! This implementation is designed to be compiled only for wasm32 and uses
//! wasm-bindgen for fetching KDS artifacts via an extension-provided JS bridge.
use crate::certificate_chain::AmdCertificates;
use crate::crypto::Certificate;
use crate::snp::verify::verify_tcb_values;
use crate::{snp, AttestationReport};

use log::{error, info};

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
        let mut result = Self::new_result();

        // Step 1: Identify processor model
        let processor_model = match Self::identify_processor(attestation_report, &mut result) {
            Some(model) => model,
            None => return Ok(result),
        };

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

        // Step 3: Verify signature and TCB
        Self::verify_signature_and_tcb(attestation_report, vcek, &mut result)?;

        Ok(result)
    }

    /// Verify an attestation report using caller-provided certificates (synchronous).
    ///
    /// This method performs offline verification without network access:
    /// 1. Selects the pinned ARK based on the processor model in the report
    /// 2. Verifies the certificate chain: ARK -> ASK -> VCEK
    /// 3. Verifies that the attestation report signature is valid against the VCEK
    /// 4. Verifies TCB values match certificate extensions
    ///
    /// # Arguments
    /// * `attestation_report` - The attestation report to verify
    /// * `ask` - The AMD SEV Key certificate (ASK)
    /// * `vcek` - The Versioned Chip Endorsement Key certificate (VCEK)
    ///
    /// # Returns
    /// A `SevVerificationResult` containing the verification outcome and details.
    pub fn verify_attestation_with_certs(
        attestation_report: &AttestationReport,
        ask: Certificate,
        vcek: Certificate,
    ) -> Result<SevVerificationResult, Box<dyn std::error::Error>> {
        let mut result = Self::new_result();

        // Step 1: Identify processor model
        let processor_model = match Self::identify_processor(attestation_report, &mut result) {
            Some(model) => model,
            None => return Ok(result),
        };

        // Step 2: Create AmdCertificates from provided certs (verifies chain)
        let amd_certificates = match AmdCertificates::from_certs(attestation_report, ask, vcek) {
            Ok(certs) => {
                result.details.certificates_fetched = true;
                result.details.certificate_chain_valid = true;
                info!("Certificate chain verified successfully (offline mode)");
                certs
            }
            Err(e) => {
                let msg = format!("Certificate chain verification failed: {}", e);
                result.errors.push(msg.clone());
                error!("{}", msg);
                return Ok(result);
            }
        };

        // Step 3: Get the VCEK from the cache
        let vcek = match amd_certificates.get_vcek_sync(processor_model, attestation_report) {
            Ok(cert) => cert,
            Err(e) => {
                let msg = format!("Failed to retrieve VCEK: {}", e);
                result.errors.push(msg.clone());
                error!("{}", msg);
                return Ok(result);
            }
        };

        // Step 4: Verify signature and TCB
        Self::verify_signature_and_tcb(attestation_report, vcek, &mut result)?;

        Ok(result)
    }

    /// Create a new verification result with all fields initialized to false/empty.
    fn new_result() -> SevVerificationResult {
        SevVerificationResult {
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
        }
    }

    /// Identify processor model from attestation report.
    /// Returns Some(Generation) on success, None on failure (with error added to result).
    fn identify_processor(
        attestation_report: &AttestationReport,
        result: &mut SevVerificationResult,
    ) -> Option<snp::model::Generation> {
        match snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        ) {
            Ok(processor_model) => {
                result.details.processor_identified = true;
                result.details.processor_model = Some(processor_model.to_string());
                Some(processor_model)
            }
            Err(_) => {
                let error = format!(
                    "Unsupported processor family/model: {} / {}",
                    attestation_report.cpuid_fam_id, attestation_report.cpuid_mod_id
                );
                result.errors.push(error.clone());
                error!("{}", error);
                None
            }
        }
    }

    /// Verify attestation signature and TCB values.
    /// Updates result fields and logs appropriately.
    fn verify_signature_and_tcb(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
        result: &mut SevVerificationResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Verify attestation signature
        if let Err(e) = Self::verify_attestation_signature(attestation_report, vcek) {
            let msg = format!("Signature verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(());
        }
        result.details.signature_valid = true;

        // Verify TCB values
        if let Err(e) = verify_tcb_values(vcek, attestation_report) {
            let msg = format!("TCB verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(());
        }
        result.details.tcb_valid = true;

        result.is_valid = true;
        info!("AMD SEV-SNP verification PASSED");
        Ok(())
    }

    fn verify_attestation_signature(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::crypto::Verifier;
        vcek.verify(attestation_report)
            .map_err(|e| format!("Failed to verify attestation signature: {}", e).into())
    }
}
