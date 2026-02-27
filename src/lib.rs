// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WASM-compatible helper crate for Patty
//!
//! This crate will host SEV-SNP verification code that can be compiled for both
//! native service usage and for browser/WASM relying parties. For now it re-exports
//! the `sev_verification` module which contains the verification engine.

pub mod crypto;
pub mod pinned_arks;
pub mod snp;
pub mod utils;

pub use crypto::Certificate;
pub use snp::report::AttestationReport;

#[cfg(any(feature = "online", target_arch = "wasm32"))]
mod certificate_chain;
#[cfg(any(feature = "online", target_arch = "wasm32"))]
mod kds;
#[cfg(any(feature = "online", target_arch = "wasm32"))]
pub mod sev_verification;
#[cfg(any(feature = "online", target_arch = "wasm32"))]
pub use certificate_chain::AmdCertificates;
#[cfg(any(feature = "online", target_arch = "wasm32"))]
pub use sev_verification::SevVerifier;

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
pub async fn verify_attestation_report(attestation_report_json: &str) -> Result<(), String> {
    let attestation_report: AttestationReport = serde_json::from_str(attestation_report_json)
        .map_err(|e| format!("Failed to parse attestation report: {}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {}", e))?;
    verifier
        .verify_attestation(&attestation_report)
        .await
        .map_err(|e| format!("Verification failed: {:?}", e))
}
