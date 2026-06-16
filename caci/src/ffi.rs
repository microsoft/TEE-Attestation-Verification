// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_family = "wasm")]
mod wasm {
    use cose::ffi::wasm::CborValue as WasmCborValue;
    use js_sys::{Array, Uint8Array};
    use std::collections::BTreeMap;
    use wasm_bindgen::{prelude::*, JsCast};

    use crate::{asynchronous, AciError, HOST_DATA_LEN};
    use attestation::snp::{ffi::wasm::SnpAttestationReport, report::TcbVersionRaw, Cpuid};
    use crypto::{CertificateBackend, Crypto};

    /// Split a PEM certificate bundle into individual PEM certificates.
    ///
    /// Parses the bundle with the active crypto backend and returns certificates
    /// in the same order they appeared in the input.
    #[wasm_bindgen]
    pub fn split_aci_certificate_bundle(pem_bundle: &str) -> Result<Array, String> {
        if pem_bundle.trim().is_empty() {
            return Err("Certificate bundle PEM is empty".into());
        }

        let certificates = Crypto::from_pem_chain(pem_bundle.as_bytes())
            .map_err(|e| format!("Failed to parse certificate bundle PEM: {e}"))?;

        let split = Array::new();
        for certificate in certificates {
            let pem = Crypto::to_pem(&certificate)
                .map_err(|e| format!("Failed to encode certificate PEM: {e}"))?;
            split.push(&JsValue::from_str(&pem));
        }

        Ok(split)
    }

    /// Verify an SEV-SNP attestation report with caller-provided endorsements.
    ///
    /// `amd_endorsements` must contain exactly three byte arrays ordered as
    /// `[vcek, ask, ark]`.
    #[wasm_bindgen]
    #[cfg(async_crypto)]
    pub async fn verify_attestation_with_cert_chain_async(
        attestation_report: Vec<u8>,
        amd_endorsements: Array,
    ) -> Result<SnpAttestationReport, String> {
        if amd_endorsements.length() != 3 {
            return Err(format!(
                "expected AMD endorsements [vcek, ask, ark], got {} certificate(s)",
                amd_endorsements.length()
            ));
        }
        let amd_endorsements = byte_array_values(amd_endorsements, "AMD endorsement")?;
        let endorsement_refs = [
            amd_endorsements[0].as_slice(),
            amd_endorsements[1].as_slice(),
            amd_endorsements[2].as_slice(),
        ];

        let attestation = asynchronous::verify_attestation(&attestation_report, &endorsement_refs)
            .await
            .map_err(wasm_error)?;

        Ok(SnpAttestationReport::from_verified_report(attestation))
    }

    /// Verify an ACI/UVM endorsement COSE blob with a caller-pinned did:x509 root.
    #[wasm_bindgen]
    #[cfg(async_crypto)]
    pub async fn verify_uvm_endorsement_async(
        uvm_endorsement: Vec<u8>,
        trusted_didx509: &str,
    ) -> Result<WasmCborValue, String> {
        let inner = asynchronous::verify_uvm_endorsement(&uvm_endorsement, trusted_didx509)
            .await
            .map_err(wasm_error)?;
        Ok(WasmCborValue::from_native(inner))
    }

    /// Verify Confidential CACI relying-party policy over staged verified artifacts.
    ///
    /// `minimum_tcb_json`, when non-empty, must be a JSON map from CPUID hex
    /// strings to TCB hex strings, for example `{ "00a10f11": "04000000000018db" }`.
    #[wasm_bindgen]
    pub async fn verify_c_aci_attestation(
        attestation: &SnpAttestationReport,
        minimum_tcb_json: &str,
        trusted_c_aci_policies: Array,
        uvm: &WasmCborValue,
        uvm_feed: &str,
        minimum_svn: u64,
    ) -> Result<Vec<u8>, String> {
        let minimum_tcb = parse_minimum_tcb_json(minimum_tcb_json)?;
        let trusted_c_aci_policies =
            byte_array_values(trusted_c_aci_policies, "trusted CACI policy")?
                .iter()
                .map(|policy| parse_host_data_policy(policy))
                .collect::<Result<Vec<_>, _>>()?;
        if trusted_c_aci_policies.is_empty() {
            return Err("at least one trusted CACI policy digest is required".to_string());
        }
        asynchronous::verify_c_aci_attestation(
            *attestation.report(),
            minimum_tcb,
            trusted_c_aci_policies,
            uvm.as_native().clone(),
            uvm_feed,
            minimum_svn,
        )
        .await
        .map(|report_data| report_data.to_vec())
        .map_err(wasm_error)
    }

    fn byte_array_values(values: Array, name: &str) -> Result<Vec<Vec<u8>>, String> {
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value
                    .dyn_into::<Uint8Array>()
                    .map(|bytes| bytes.to_vec())
                    .map_err(|_| format!("{name} at index {index} must be a Uint8Array"))
            })
            .collect()
    }

    fn parse_minimum_tcb_json(json: &str) -> Result<Vec<(Cpuid, TcbVersionRaw)>, String> {
        if json.trim().is_empty() {
            return Ok(Vec::new());
        }
        let map: BTreeMap<String, String> = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse minimum TCB JSON: {e}"))?;
        map.into_iter()
            .map(|(cpuid, tcb)| Ok((parse_cpuid_hex(&cpuid)?, parse_tcb_hex(&tcb)?)))
            .collect()
    }

    fn parse_cpuid_hex(hex: &str) -> Result<Cpuid, String> {
        if hex.len() != 8 {
            return Err(format!("CPUID must be 8 hex characters, got {}", hex.len()));
        }
        let bytes =
            crypto::hex::from_hex(hex).map_err(|e| format!("invalid CPUID hex {hex:?}: {e}"))?;
        let value = u32::from_be_bytes(bytes.try_into().expect("CPUID hex length already checked"));
        Ok(Cpuid::from(value))
    }

    fn parse_tcb_hex(hex: &str) -> Result<TcbVersionRaw, String> {
        let bytes = crypto::hex::from_hex(hex)?;
        let raw = bytes.try_into().map_err(|bytes: Vec<u8>| {
            format!("TCB version must be 8 bytes, got {}", bytes.len())
        })?;
        Ok(TcbVersionRaw { raw })
    }

    fn parse_host_data_policy(bytes: &[u8]) -> Result<[u8; HOST_DATA_LEN], String> {
        bytes.try_into().map_err(|_| {
            format!(
                "trusted CACI policy digest must be {HOST_DATA_LEN} bytes, got {}",
                bytes.len()
            )
        })
    }

    fn wasm_error(error: AciError) -> String {
        error.to_string()
    }
}
