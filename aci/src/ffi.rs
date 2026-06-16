// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_family = "wasm")]
mod wasm {
    use js_sys::{Array, Uint8Array};
    use std::collections::BTreeMap;
    use wasm_bindgen::{prelude::*, JsCast};

    use crate::{
        asynchronous, parse_aci_cose as parse_aci_cose_native, AciError, CaciUvmEndorsement,
        CaciUvmEndorsementV1, HOST_DATA_LEN,
    };
    use attestation::snp::{ffi::wasm::SnpAttestationReport, report::TcbVersionRaw, Cpuid};
    use crypto::{CertificateBackend, Crypto};

    #[wasm_bindgen]
    pub struct WasmCaciUvmEndorsement {
        inner: CaciUvmEndorsement,
    }

    #[wasm_bindgen]
    pub struct WasmCaciUvmEndorsementV1 {
        inner: CaciUvmEndorsementV1,
    }

    #[wasm_bindgen]
    impl WasmCaciUvmEndorsement {
        pub fn version(&self) -> u32 {
            match &self.inner {
                CaciUvmEndorsement::V1(_) => 1,
            }
        }

        pub fn v1(&self) -> Result<WasmCaciUvmEndorsementV1, String> {
            match &self.inner {
                CaciUvmEndorsement::V1(v1) => Ok(WasmCaciUvmEndorsementV1 { inner: v1.clone() }),
            }
        }
    }

    #[wasm_bindgen]
    impl WasmCaciUvmEndorsementV1 {
        pub fn protected(&self) -> Vec<u8> {
            self.inner.protected.clone()
        }

        pub fn payload(&self) -> Vec<u8> {
            self.inner.payload.clone()
        }

        pub fn signature(&self) -> Vec<u8> {
            self.inner.signature.clone()
        }

        pub fn alg(&self) -> Result<i32, String> {
            self.inner
                .alg
                .try_into()
                .map_err(|_| format!("COSE alg {} does not fit i32", self.inner.alg))
        }

        pub fn content_type(&self) -> String {
            self.inner.content_type.clone()
        }

        pub fn x5chain(&self) -> Array {
            let chain = Array::new();
            for cert in &self.inner.x5chain {
                chain.push(&Uint8Array::from(cert.as_slice()));
            }
            chain
        }

        pub fn issuer(&self) -> String {
            self.inner.issuer.clone()
        }

        pub fn feed(&self) -> Option<String> {
            self.inner.feed.clone()
        }

        pub fn svn(&self) -> Option<String> {
            self.inner.svn.clone()
        }

        pub fn signing_time_seconds(&self) -> Option<f64> {
            self.inner
                .signing_time
                .map(|signing_time| signing_time.as_secs() as f64)
        }
    }

    /// Parse an ACI/UVM endorsement COSE blob without verifying it.
    #[wasm_bindgen]
    pub fn parse_aci_cose(aci_cose: Vec<u8>) -> Result<WasmCaciUvmEndorsement, String> {
        parse_aci_cose_native(&aci_cose)
            .map(|inner| WasmCaciUvmEndorsement { inner })
            .map_err(wasm_error)
    }

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
    ) -> Result<WasmCaciUvmEndorsement, String> {
        let inner = asynchronous::verify_uvm_endorsement(&uvm_endorsement, trusted_didx509)
            .await
            .map_err(wasm_error)?;
        Ok(WasmCaciUvmEndorsement { inner })
    }

    /// Verify Confidential ACI relying-party policy over staged verified artifacts.
    ///
    /// `minimum_tcb_json`, when non-empty, must be a JSON map from CPUID hex
    /// strings to TCB hex strings, for example `{ "00a10f11": "04000000000018db" }`.
    #[wasm_bindgen]
    pub async fn verify_c_aci_attestation(
        attestation: &SnpAttestationReport,
        minimum_tcb_json: &str,
        trusted_c_aci_policies: Array,
        uvm: &WasmCaciUvmEndorsement,
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
            uvm.inner.clone(),
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
