// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WASM-compatible helper crate for Patty
//!
//! This crate will host SEV-SNP verification code that can be compiled for both
//! native service usage and for browser/WASM relying parties. For now it re-exports
//! the `sev_verification` module which contains the verification engine.

pub mod crypto;
pub mod pinned_arks;
pub mod sev_verification;
pub mod snp;

mod certificate_chain;
mod kds;

pub use crypto::Certificate;
pub use snp::report::AttestationReport;

// Re-export the main types at crate root for convenient use (wasm only)
pub use certificate_chain::AmdCertificates;
pub use sev_verification::{SevVerificationDetails, SevVerificationResult, SevVerifier};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// Initialize the WASM module with panic hook and logging
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::default());
}

/// JavaScript-facing verification function
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn verify_attestation_report(attestation_report_json: &str) -> Result<String, String> {
    let attestation_report: AttestationReport = serde_json::from_str(attestation_report_json)
        .map_err(|e| format!("Failed to parse attestation report: {}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {}", e))?;
    match verifier.verify_attestation(&attestation_report).await {
        Ok(result) => {
            serde_json::to_string(&result).map_err(|e| format!("Failed to serialize result: {}", e))
        }
        Err(e) => {
            // Create an error result
            let error_result = SevVerificationResult {
                is_valid: false,
                details: SevVerificationDetails {
                    processor_identified: false,
                    certificates_fetched: false,
                    certificate_chain_valid: false,
                    signature_valid: false,
                    tcb_valid: false,
                    processor_model: None,
                },
                errors: vec![format!("{}", e)],
            };
            serde_json::to_string(&error_result)
                .map_err(|e| format!("Failed to serialize error result: {}", e))
        }
    }
}
