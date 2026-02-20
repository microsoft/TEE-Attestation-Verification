// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WASM-only AMD SEV-SNP Attestation Verification
//!
//! This implementation is designed to be compiled only for wasm32 and uses
//! wasm-bindgen for fetching KDS artifacts via an extension-provided JS bridge.
use crate::certificate_chain::AmdCertificates;
use crate::{snp, AttestationReport};

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
    ) -> Result<(), snp::verify::VerificationError> {
        // Step 1: Identify processor model
        let processor_model = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        )
        .map_err(|e| snp::verify::VerificationError::UnsupportedProcessor(format!("{:?}", e)))?;

        // Step 2: Get VCEK certificate for this processor (includes chain verification)
        let vcek = self
            .amd_certificates
            .get_vcek(processor_model, attestation_report)
            .await
            .map_err(|e| {
                snp::verify::VerificationError::CertificateChainError(format!("{:?}", e))
            })?;

        // Step 3: Verify signature and TCB
        // Skip redundant certificate chain verification since we already verified the VCEK chain
        snp::verify::verify_attestation(
            attestation_report,
            vcek,
            snp::verify::ChainVerification::Skip,
        )
    }
}
