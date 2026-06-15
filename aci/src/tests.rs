// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

use crate::didx509::parse_didx509_prefix;
use crate::parse::hex_to_bytes;
#[cfg(sync_crypto)]
use crate::parse::ReferenceInfoPayload;

const MILAN_ATTESTATION: &[u8] =
    include_bytes!("../../attestation/tests/test_data/milan_attestation_report.bin");
const MILAN_ARK: &[u8] = include_bytes!("../../attestation/src/pinned_arks/milan_ark.pem");
const MILAN_ASK: &[u8] = include_bytes!("../../attestation/tests/test_data/milan_ask.pem");
const MILAN_VCEK: &[u8] = include_bytes!("../../attestation/tests/test_data/milan_vcek.pem");
const HOST_AMD_CERT_BASE64: &str = include_str!("../tests/fixtures/host-amd-cert.base64");
#[cfg(any(sync_crypto, async_crypto))]
const REFERENCE_INFO_BASE64: &str = include_str!("../tests/fixtures/reference-info.base64");
const REPORT_HEX: &str = include_str!("../tests/fixtures/report.hex");
#[cfg(any(sync_crypto, async_crypto))]
const TRUSTED_ACI_DIDX509: &str =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
#[cfg(all(async_crypto, sync_crypto))]
fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("native crypto futures should complete immediately"),
    }
}

fn endorsements_from_host_amd_cert_fixture(
    host_amd_cert_base64: &str,
) -> Result<[Vec<u8>; 3], AciError> {
    let host_amd_cert_base64 = host_amd_cert_base64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    let host_amd_cert =
        base64_standard_decode(&host_amd_cert_base64).map_err(AciError::InvalidAmdEndorsements)?;
    let host_amd_cert: serde_json::Value = serde_json::from_slice(&host_amd_cert)
        .map_err(|e| AciError::InvalidAmdEndorsements(e.to_string()))?;
    let vcek = required_json_string(&host_amd_cert, "vcekCert")?;
    let certificate_chain = required_json_string(&host_amd_cert, "certificateChain")?;
    let chain = split_pem_chain(certificate_chain)?;
    if chain.len() != 2 {
        return Err(AciError::InvalidAmdEndorsements(format!(
            "expected certificateChain to contain ASK and ARK, got {} certificate(s)",
            chain.len()
        )));
    }

    Ok([vcek.as_bytes().to_vec(), chain[0].clone(), chain[1].clone()])
}

fn required_json_string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, AciError> {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            AciError::InvalidAmdEndorsements(format!(
                "host AMD cert JSON missing string field {key}"
            ))
        })
}

fn split_pem_chain(pem_chain: &str) -> Result<Vec<Vec<u8>>, AciError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut certs = Vec::new();
    let mut remaining = pem_chain;
    while let Some(begin) = remaining.find(BEGIN) {
        let after_begin = &remaining[begin..];
        let end = after_begin.find(END).ok_or_else(|| {
            AciError::InvalidAmdEndorsements("certificateChain has unterminated PEM".to_string())
        })?;
        let end = end + END.len();
        let mut cert = after_begin[..end].to_string();
        cert.push('\n');
        certs.push(cert.into_bytes());
        remaining = &after_begin[end..];
    }

    if certs.is_empty() {
        return Err(AciError::InvalidAmdEndorsements(
            "certificateChain contains no PEM certificates".to_string(),
        ));
    }

    Ok(certs)
}

#[test]
fn parses_didx509_prefix_and_ignores_policy_suffix() {
    let did = "did:x509:0:sha256:abc123::eku:1.2.3";
    let parsed = parse_didx509_prefix(did).unwrap();

    assert_eq!(parsed.prefix, "did:x509:0:sha256:abc123");
    assert_eq!(parsed.fingerprint, "abc123");
}

#[test]
fn rejects_wrong_amd_endorsement_count() {
    let err = parse_amd_endorsements(&[MILAN_VCEK, MILAN_ASK]).unwrap_err();

    assert!(err.to_string().contains("expected [vcek, ask, ark]"));
}

#[test]
fn test_helper_splits_host_amd_cert_base64_into_vcek_ask_ark() {
    let host_amd_cert = serde_json::json!({
        "vcekCert": "-----BEGIN CERTIFICATE-----\nvcek\n-----END CERTIFICATE-----\n",
        "certificateChain": "-----BEGIN CERTIFICATE-----\nask\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nark\n-----END CERTIFICATE-----\n",
    });
    let encoded = base64_standard_encode(host_amd_cert.to_string().as_bytes());

    let [vcek, ask, ark] = endorsements_from_host_amd_cert_fixture(&encoded).unwrap();

    assert!(String::from_utf8(vcek).unwrap().contains("vcek"));
    assert!(String::from_utf8(ask).unwrap().contains("ask"));
    assert!(String::from_utf8(ark).unwrap().contains("ark"));
}

#[test]
fn splits_real_host_amd_cert_fixture_into_parseable_vcek_ask_ark() {
    let endorsements = endorsements_from_host_amd_cert_fixture(HOST_AMD_CERT_BASE64).unwrap();
    assert!(String::from_utf8_lossy(&endorsements[0]).contains("BEGIN CERTIFICATE"));
    assert!(String::from_utf8_lossy(&endorsements[1]).contains("BEGIN CERTIFICATE"));
    assert!(String::from_utf8_lossy(&endorsements[2]).contains("BEGIN CERTIFICATE"));

    let endorsement_refs = [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ];
    parse_amd_endorsements(&endorsement_refs).unwrap();
}

#[test]
#[cfg(sync_crypto)]
fn verifies_real_aci_report_with_host_amd_cert_fixture() {
    let attestation = hex_to_bytes(REPORT_HEX.trim()).unwrap();
    let report = parse_attestation(&attestation).unwrap();
    let endorsements = endorsements_from_host_amd_cert_fixture(HOST_AMD_CERT_BASE64).unwrap();
    let endorsement_refs = [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ];

    let verified = sync::verify_attestation(&attestation, &endorsement_refs).unwrap();

    assert_eq!(verified.measurement, report.measurement);
}

#[test]
#[cfg(sync_crypto)]
fn verifies_real_aci_reference_info_fixture_end_to_end() {
    let attestation = hex_to_bytes(REPORT_HEX.trim()).unwrap();
    let endorsements = endorsements_from_host_amd_cert_fixture(HOST_AMD_CERT_BASE64).unwrap();
    let endorsement_refs = [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ];
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);

    let report = sync::verify_attestation(&attestation, &endorsement_refs).unwrap();
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();

    let uvm_v1 = endorsement_v1(&uvm);
    assert_eq!(uvm_v1.issuer, TRUSTED_ACI_DIDX509);
    assert_eq!(uvm_v1.feed.as_deref(), Some("ContainerPlat-AMD-UVM"));
    assert_eq!(
        endorsement_payload(&uvm).measurement,
        parse_attestation(&attestation).unwrap().measurement
    );
    assert_eq!(endorsement_svn(&uvm).as_deref(), Some("104"));
    assert_eq!(endorsement_payload(&uvm).measurement, report.measurement);
}

#[cfg(any(sync_crypto, async_crypto))]
fn decode_base64_fixture(encoded: &str) -> Vec<u8> {
    let encoded = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    base64_standard_decode(&encoded).unwrap()
}

#[cfg(sync_crypto)]
fn endorsement_v1(endorsement: &CaciUvmEndorsement) -> &CaciUvmEndorsementV1 {
    match endorsement {
        CaciUvmEndorsement::V1(v1) => v1,
        #[allow(unreachable_patterns)]
        _ => panic!("expected CACI UVM endorsement V1"),
    }
}

#[cfg(sync_crypto)]
fn endorsement_payload(endorsement: &CaciUvmEndorsement) -> ReferenceInfoPayload {
    let v1 = endorsement_v1(endorsement);
    measurement_from_payload(&v1.payload, &v1.content_type).unwrap()
}

#[cfg(sync_crypto)]
fn endorsement_svn(endorsement: &CaciUvmEndorsement) -> Option<String> {
    let v1 = endorsement_v1(endorsement);
    endorsement_payload(endorsement).svn.or(v1.svn.clone())
}

fn base64_standard_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let indexes = base64_indexes(chunk);
        encoded.push(ALPHABET[indexes[0] as usize] as char);
        encoded.push(ALPHABET[indexes[1] as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[indexes[2] as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[indexes[3] as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
}

fn base64_standard_decode(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.len() % 4 != 0 {
        return Err("base64 input length must be a multiple of 4".to_string());
    }

    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3);
    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let first = base64_standard_value(chunk[0])
            .ok_or_else(|| format!("invalid base64 byte at offset {}", chunk_index * 4))?;
        let second = base64_standard_value(chunk[1])
            .ok_or_else(|| format!("invalid base64 byte at offset {}", chunk_index * 4 + 1))?;
        let third =
            if chunk[2] == b'=' {
                None
            } else {
                Some(base64_standard_value(chunk[2]).ok_or_else(|| {
                    format!("invalid base64 byte at offset {}", chunk_index * 4 + 2)
                })?)
            };
        let fourth =
            if chunk[3] == b'=' {
                None
            } else {
                Some(base64_standard_value(chunk[3]).ok_or_else(|| {
                    format!("invalid base64 byte at offset {}", chunk_index * 4 + 3)
                })?)
            };

        if third.is_none() && fourth.is_some() {
            return Err("invalid base64 padding".to_string());
        }
        if chunk_index + 1 != encoded.len() / 4 && (third.is_none() || fourth.is_none()) {
            return Err("base64 padding is only allowed in the final chunk".to_string());
        }

        let indexes = [first, second, third.unwrap_or(0), fourth.unwrap_or(0)];
        let block = bytes_from_base64_indexes(indexes);
        decoded.push(block[0]);
        if third.is_some() {
            decoded.push(block[1]);
            if fourth.is_some() {
                decoded.push(block[2]);
            }
        }
    }
    Ok(decoded)
}

fn base64_indexes(chunk: &[u8]) -> [u8; 4] {
    let mut block = [0u8; 3];
    block[..chunk.len()].copy_from_slice(chunk);
    // Base64 treats each 3-byte block as one 24-bit integer, then emits four
    // 6-bit indexes into the selected alphabet. Short final chunks are padded
    // with zero bits here; the caller decides whether to emit padding chars.
    let packed = u32::from_be_bytes([0, block[0], block[1], block[2]]);
    [
        ((packed >> 18) & 0x3f) as u8,
        ((packed >> 12) & 0x3f) as u8,
        ((packed >> 6) & 0x3f) as u8,
        (packed & 0x3f) as u8,
    ]
}

fn bytes_from_base64_indexes(indexes: [u8; 4]) -> [u8; 3] {
    // Decoding reverses the packing above: four 6-bit alphabet indexes are
    // reassembled into a 24-bit integer, which yields up to three bytes.
    let packed = (u32::from(indexes[0]) << 18)
        | (u32::from(indexes[1]) << 12)
        | (u32::from(indexes[2]) << 6)
        | u32::from(indexes[3]);
    let bytes = packed.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

fn base64_standard_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[test]
fn local_base64_standard_helpers_match_known_vectors() {
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_standard_encode(plain.as_bytes()), encoded);
        assert_eq!(base64_standard_decode(encoded).unwrap(), plain.as_bytes());
    }
}

#[test]
fn parses_single_certificate_x5chain_without_intermediates() {
    let cert = crypto::Crypto::from_pem(MILAN_ARK).unwrap();
    let cert_der = crypto::Crypto::to_der(&cert).unwrap();

    let (root, intermediates, leaf) =
        crate::parse::parse_x5chain_certs(&[cert_der.clone()]).unwrap();

    assert!(intermediates.is_empty());
    assert_eq!(crypto::Crypto::to_der(&root).unwrap(), cert_der);
    assert_eq!(crypto::Crypto::to_der(&leaf).unwrap(), cert_der);
}

#[test]
fn parses_reference_info_json_payload() {
    let report = parse_attestation(MILAN_ATTESTATION).unwrap();
    let payload = format!(
        r#"{{
            "x-ms-sevsnpvm-launchmeasurement": "{}",
            "x-ms-sevsnpvm-guestsvn": "104",
            "x-ms-sevsnpvm-guestsvn-int": 104,
            "future-field": true
        }}"#,
        report
            .measurement
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    let reference_info = measurement_from_payload(payload.as_bytes(), "application/json").unwrap();

    assert_eq!(reference_info.measurement, report.measurement);
    assert_eq!(reference_info.svn.as_deref(), Some("104"));
}

#[test]
fn rejects_reference_info_json_missing_guestsvn_int() {
    let report = parse_attestation(MILAN_ATTESTATION).unwrap();
    let payload = format!(
        r#"{{
            "x-ms-sevsnpvm-launchmeasurement": "{}",
            "x-ms-sevsnpvm-guestsvn": "104"
        }}"#,
        report
            .measurement
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    let err = measurement_from_payload(payload.as_bytes(), "application/json").unwrap_err();

    assert!(err.to_string().contains("x-ms-sevsnpvm-guestsvn-int"));
}

#[test]
fn rejects_reference_info_json_uppercase_measurement() {
    let report = parse_attestation(MILAN_ATTESTATION).unwrap();
    let payload = format!(
        r#"{{
            "x-ms-sevsnpvm-launchmeasurement": "{}",
            "x-ms-sevsnpvm-guestsvn": "104",
            "x-ms-sevsnpvm-guestsvn-int": 104
        }}"#,
        report
            .measurement
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    );

    let err = measurement_from_payload(payload.as_bytes(), "application/json").unwrap_err();

    assert!(err.to_string().contains("^[0-9a-f]+$"));
}

#[test]
#[cfg(sync_crypto)]
fn verifies_attestation_with_ordered_amd_endorsements() {
    let report = parse_attestation(MILAN_ATTESTATION).unwrap();
    let endorsements = [MILAN_VCEK, MILAN_ASK, MILAN_ARK];

    let verified = sync::verify_attestation(MILAN_ATTESTATION, &endorsements).unwrap();

    assert_eq!(verified.measurement, report.measurement);
}

#[test]
#[cfg(sync_crypto)]
fn verifies_aci_cose_against_attestation_and_didx509_root() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);
    let report = verified_reference_attestation();
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();

    let uvm_v1 = endorsement_v1(&uvm);
    assert_eq!(endorsement_payload(&uvm).measurement, report.measurement);
    assert_eq!(uvm_v1.issuer, TRUSTED_ACI_DIDX509);
    assert_eq!(uvm_v1.feed.as_deref(), Some("ContainerPlat-AMD-UVM"));
    assert_eq!(endorsement_svn(&uvm).as_deref(), Some("104"));
    assert!(uvm_v1.x5chain.len() >= 2);
    assert_eq!(endorsement_payload(&uvm).measurement, report.measurement);
}

#[test]
#[cfg(sync_crypto)]
fn verifies_caci_policy_against_attestation_and_uvm() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);
    let report = verified_reference_attestation();
    let expected_report_data = report.report_data;
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();

    let report_data = verify_c_aci_attestation(
        report,
        Vec::new(),
        vec![report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap();

    assert_eq!(report_data, expected_report_data);
}

#[test]
#[cfg(sync_crypto)]
fn rejects_caci_policy_mismatches() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);
    let report = verified_reference_attestation();
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();

    let err = verify_c_aci_attestation(
        report,
        Vec::new(),
        vec![report.host_data],
        uvm.clone(),
        "ContainerPlat-AMD-UVM",
        105,
    )
    .unwrap_err();
    assert!(err.to_string().contains("UVM SVN 104 is below"));

    let mut policy = report.host_data;
    policy[0] ^= 1;
    let err = verify_c_aci_attestation(
        report,
        Vec::new(),
        vec![policy],
        uvm.clone(),
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap_err();
    assert!(err.to_string().contains("HOST_DATA"));

    let mut uvm = uvm;
    let uvm_v1 = match &mut uvm {
        CaciUvmEndorsement::V1(v1) => v1,
        #[allow(unreachable_patterns)]
        _ => panic!("expected CACI UVM endorsement V1"),
    };
    uvm_v1.feed = Some("not-confidential-aci".to_string());
    let err = verify_c_aci_attestation(
        report,
        Vec::new(),
        vec![report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap_err();
    assert!(err.to_string().contains("UVM feed"));
}

#[test]
#[cfg(sync_crypto)]
fn rejects_caci_minimum_tcb_mismatch() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);
    let report = verified_reference_attestation();
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();
    let matching_cpuid = snp::Cpuid::from(0x00A00F11);
    let mut minimum_tcb = report.reported_tcb;
    minimum_tcb.raw[0] = minimum_tcb.raw[0].saturating_add(1);

    let err = verify_c_aci_attestation(
        report,
        vec![(matching_cpuid, minimum_tcb)],
        vec![report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap_err();

    assert!(err.to_string().contains("reported TCB"));
}

#[test]
#[cfg(sync_crypto)]
fn rejects_debug_and_host_generated_reports() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);

    let debug_report = verified_attestation_from_reference_fixture(|bytes| {
        let mut policy = u64::from_le_bytes(bytes[0x008..0x010].try_into().unwrap());
        policy |= 1 << 19;
        bytes[0x008..0x010].copy_from_slice(&policy.to_le_bytes());
    });
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();
    let err = verify_c_aci_attestation(
        debug_report,
        Vec::new(),
        vec![debug_report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap_err();
    assert!(err.to_string().contains("debug mode"));

    let invalid_vmpl_report = verified_attestation_from_reference_fixture(|bytes| {
        bytes[0x030..0x034].copy_from_slice(&4_u32.to_le_bytes());
    });
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();
    let err = verify_c_aci_attestation(
        invalid_vmpl_report,
        Vec::new(),
        vec![invalid_vmpl_report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap_err();
    assert!(err.to_string().contains("outside the guest range"));

    let host_report = verified_attestation_from_reference_fixture(|bytes| {
        bytes[0x030..0x034].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    });
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();
    let err = verify_c_aci_attestation(
        host_report,
        Vec::new(),
        vec![host_report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap_err();
    assert!(err.to_string().contains("outside the guest range"));
}

#[test]
#[cfg(sync_crypto)]
fn staged_api_verifies_uvm_before_binding_to_attestation() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);

    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();

    let report = verified_reference_attestation();
    assert_eq!(endorsement_payload(&uvm).measurement, report.measurement);
}

#[test]
#[cfg(sync_crypto)]
fn rejects_aci_measurement_mismatch() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);
    let endorsements = [MILAN_VCEK, MILAN_ASK, MILAN_ARK];

    let report = sync::verify_attestation(MILAN_ATTESTATION, &endorsements).unwrap();
    let uvm = sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();
    let err = verify_c_aci_attestation(
        report,
        Vec::new(),
        vec![report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap_err();

    assert!(err
        .to_string()
        .contains("ACI payload measurement does not match"));
}

#[test]
#[cfg(all(async_crypto, sync_crypto))]
fn async_staged_api_verifies_aci_cose_against_attestation_and_didx509_root() {
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);
    let attestation = hex_to_bytes(REPORT_HEX.trim()).unwrap();
    let endorsements = endorsements_from_host_amd_cert_fixture(HOST_AMD_CERT_BASE64).unwrap();
    let endorsement_refs = [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ];

    let report = block_on_ready(asynchronous::verify_attestation(
        &attestation,
        &endorsement_refs,
    ));
    let uvm = block_on_ready(asynchronous::verify_uvm_endorsement(
        &reference_info,
        TRUSTED_ACI_DIDX509,
    ));
    let report = report.unwrap();
    let uvm = uvm.unwrap();

    let uvm_v1 = endorsement_v1(&uvm);
    assert_eq!(endorsement_payload(&uvm).measurement, report.measurement);
    assert_eq!(uvm_v1.issuer, TRUSTED_ACI_DIDX509);
    assert_eq!(endorsement_payload(&uvm).measurement, report.measurement);
}

#[cfg(all(async_crypto, target_family = "wasm"))]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn wasm_webcrypto_verifies_real_aci_reference_info_fixture_end_to_end() {
    let attestation = hex_to_bytes(REPORT_HEX.trim()).unwrap();
    let endorsements = endorsements_from_host_amd_cert_fixture(HOST_AMD_CERT_BASE64).unwrap();
    let endorsement_refs = [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ];
    let reference_info = decode_base64_fixture(REFERENCE_INFO_BASE64);

    let report = asynchronous::verify_attestation(&attestation, &endorsement_refs)
        .await
        .unwrap();
    let uvm = asynchronous::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509)
        .await
        .unwrap();
    let expected_report_data = report.report_data;

    let report_data = verify_c_aci_attestation(
        report,
        Vec::new(),
        vec![report.host_data],
        uvm,
        "ContainerPlat-AMD-UVM",
        104,
    )
    .unwrap();

    assert_eq!(report_data, expected_report_data);
}

#[cfg(sync_crypto)]
fn verified_reference_attestation() -> AttestationReport {
    let attestation = hex_to_bytes(REPORT_HEX.trim()).unwrap();
    let endorsements = endorsements_from_host_amd_cert_fixture(HOST_AMD_CERT_BASE64).unwrap();
    let endorsement_refs = [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ];
    sync::verify_attestation(&attestation, &endorsement_refs).unwrap()
}

#[cfg(sync_crypto)]
fn verified_attestation_from_reference_fixture(
    mutate: impl FnOnce(&mut [u8]),
) -> AttestationReport {
    let mut report = hex_to_bytes(REPORT_HEX.trim()).unwrap();
    mutate(&mut report);
    parse_attestation(&report).unwrap()
}
