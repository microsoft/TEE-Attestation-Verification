// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{AciError, CborValue};
use attestation::snp::{report::TcbVersionRaw, Cpuid};

pub(crate) const CONTENT_TYPE: &str = "application/vnd.tcb-reference-info.v1+cose";

/// An AMD SEV-SNP minimum TCB entry from a verified TCB info manifest.
#[derive(Debug, Clone)]
pub struct AmdSevSnpWatermark {
    /// Processor CPUID, converted from the manifest's big-endian encoding.
    pub cpuid: Cpuid,
    /// Human-readable processor description.
    pub description: String,
    /// Minimum TCB version in raw SNP report field order.
    pub tcb: TcbVersionRaw,
}

pub(crate) fn parse_manifest(payload: &[u8]) -> Result<Vec<AmdSevSnpWatermark>, AciError> {
    let manifest = CborValue::parse_nondet(payload).map_err(invalid_manifest)?;
    let CborValue::Map(tees) = manifest else {
        return Err(invalid_manifest("expected a map"));
    };
    let mut watermarks = Vec::new();
    for (tee_id, entries) in tees {
        match tee_id {
            CborValue::Int(1) => {
                let CborValue::Map(entries) = entries else {
                    return Err(invalid_manifest("expected an AMD SEV-SNP map"));
                };
                watermarks.reserve(entries.len());
                for (cpuid, watermark) in entries {
                    let cpuid = Cpuid::from(u32::from_be_bytes(fixed_bstr(&cpuid, "CPUID")?));
                    if !matches!(&watermark, CborValue::Map(fields) if fields.len() == 2) {
                        return Err(invalid_manifest("expected exactly two watermark fields"));
                    }
                    let description = match watermark.map_at_int(1).map_err(invalid_manifest)? {
                        CborValue::TextString(description) => description.to_string(),
                        _ => return Err(invalid_manifest("description must be a text string")),
                    };
                    let raw = fixed_bstr(
                        watermark.map_at_int(2).map_err(invalid_manifest)?,
                        "TCB version",
                    )?;
                    watermarks.push(AmdSevSnpWatermark {
                        cpuid,
                        description,
                        tcb: TcbVersionRaw { raw },
                    });
                }
            }
            CborValue::Int(2..) => {}
            _ => {
                return Err(invalid_manifest(
                    "TEE ID must be an integer greater than zero",
                ))
            }
        }
    }
    Ok(watermarks)
}

fn fixed_bstr<const N: usize>(value: &CborValue<'_>, name: &str) -> Result<[u8; N], AciError> {
    if let CborValue::ByteString(bytes) = value {
        if let Ok(bytes) = bytes.as_ref().try_into() {
            return Ok(bytes);
        }
    }
    Err(invalid_manifest(format!(
        "{name} must be a {N}-byte string"
    )))
}

fn invalid_manifest(message: impl std::fmt::Display) -> AciError {
    AciError::Cose(format!("invalid TCB info manifest: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn permits_absent_snp_entries_and_ignores_future_tees() {
        for manifest in [&[0xa0][..], &[0xa1, 1, 0xa0], &[0xa1, 2, 0x81, 0xf6]] {
            assert!(parse_manifest(manifest).unwrap().is_empty());
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn rejects_invalid_manifest_shapes() {
        let valid_cpuid = CborValue::bytes([0x00, 0xa0, 0x0f, 0x11].as_slice());
        let description = (CborValue::Int(1), CborValue::text("Milan"));
        let tcb = (CborValue::Int(2), CborValue::bytes([0; 8].as_slice()));
        for (cpuid, fields) in [
            (
                CborValue::bytes([0; 3].as_slice()),
                vec![description.clone(), tcb.clone()],
            ),
            (valid_cpuid.clone(), vec![tcb.clone()]),
            (
                valid_cpuid.clone(),
                vec![(CborValue::Int(1), CborValue::Int(0)), tcb.clone()],
            ),
            (
                valid_cpuid.clone(),
                vec![
                    description.clone(),
                    (CborValue::Int(2), CborValue::bytes([0; 7].as_slice())),
                ],
            ),
            (
                valid_cpuid,
                vec![description, tcb, (CborValue::Int(3), CborValue::Int(0))],
            ),
        ] {
            let manifest = CborValue::Map(vec![(
                CborValue::Int(1),
                CborValue::Map(vec![(cpuid, CborValue::Map(fields))]),
            )]);
            assert!(parse_manifest(&manifest.to_bytes_det().unwrap()).is_err());
        }
        for manifest in [
            &[0x80][..],               // non-map manifest
            &[0xa1, 0, 0xf6],          // reserved TEE ID
            &[0xa1, 1, 0xf6],          // non-map SNP entries
            &[0xa2, 1, 0xa0, 1, 0xa0], // duplicate SNP section
        ] {
            assert!(parse_manifest(manifest).is_err());
        }
    }
}
