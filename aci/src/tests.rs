// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

use crate::{
    base64::base64_standard_decode,
    parse::{hex_to_bytes, ReferenceInfoPayload},
};

const HOST_AMD_CERT_BASE64: &str = include_str!("../tests/fixtures/host-amd-cert.base64");
const REFERENCE_INFO_BASE64: &str = include_str!("../tests/fixtures/reference-info.base64");
const REPORT_HEX: &str = include_str!("../tests/fixtures/report.hex");
const TRUSTED_ACI_DIDX509: &str =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
const ACI_FEED: &str = "ContainerPlat-AMD-UVM";
const ACI_SVN: u64 = 104;
const MILAN_CPUID: u32 = 0x00A00F11;

#[cfg(sync_crypto)]
mod sync {
    use super::*;

    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn verifies_caci_attestation_end_to_end() {
        let attestation = attestation_fixture();
        let endorsements = amd_endorsement_fixture();
        let endorsement_refs = endorsement_refs(&endorsements);
        let reference_info = reference_info_fixture();

        let report = crate::sync::verify_attestation(&attestation, &endorsement_refs).unwrap();
        let uvm =
            crate::sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();

        let report_data = verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uvm,
            ACI_FEED,
            ACI_SVN,
        )
        .unwrap();

        assert_eq!(report_data, report.report_data);
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn step1_attestation_verification_works_and_rejects_invalid_inputs() {
        let attestation = attestation_fixture();
        let endorsements = amd_endorsement_fixture();
        let endorsement_refs = endorsement_refs(&endorsements);

        let report = crate::sync::verify_attestation(&attestation, &endorsement_refs).unwrap();
        assert_verified_attestation_matches_fixture(report);

        match crate::sync::verify_attestation(&attestation, &endorsement_refs[..2]) {
            Err(AciError::InvalidAmdEndorsements(actual)) => {
                assert_eq!(actual, "expected [vcek, ask, ark], got 2 certificate(s)")
            }
            other => panic!("expected InvalidAmdEndorsements, got {other:?}"),
        }

        let truncated = &attestation[..64];
        match crate::sync::verify_attestation(truncated, &endorsement_refs) {
            Err(AciError::InvalidAttestation(actual)) => assert_contains(&actual, "SizeError"),
            other => panic!("expected InvalidAttestation, got {other:?}"),
        }

        let mut tampered = attestation.clone();
        tampered[100] ^= 0xff;
        match crate::sync::verify_attestation(&tampered, &endorsement_refs) {
            Err(AciError::AttestationVerification(
                attestation::snp::verify::VerificationError::SignatureVerificationError(actual),
            )) => assert_contains(
                &actual.to_ascii_lowercase(),
                "signature verification failed",
            ),
            other => panic!("expected attestation signature verification error, got {other:?}"),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn step2_uvm_endorsement_verification_works_and_rejects_invalid_inputs() {
        let reference_info = reference_info_fixture();
        let expected_report = parse_attestation(&attestation_fixture()).unwrap();

        let uvm =
            crate::sync::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509).unwrap();
        assert_verified_uvm_matches_fixture(&uvm, expected_report);

        match crate::sync::verify_uvm_endorsement(b"not cose", TRUSTED_ACI_DIDX509) {
            Err(AciError::Cose(actual)) => assert_eq!(actual, "Failed to parse CBOR bytes"),
            other => panic!("expected Cose error, got {other:?}"),
        }

        match crate::sync::verify_uvm_endorsement(&reference_info, "not-a-did") {
            Err(AciError::DidX509(actual)) => {
                assert_eq!(actual, "expected did:x509:0:sha256:<fingerprint>")
            }
            other => panic!("expected DidX509 error, got {other:?}"),
        }

        match crate::sync::verify_uvm_endorsement(&reference_info, "did:x509:0:sha256:wrong") {
            Err(AciError::DidX509(actual)) => assert_eq!(
                actual,
                "issuer DID prefix did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s does not match trusted DID prefix did:x509:0:sha256:wrong"
            ),
            other => panic!("expected DidX509 error, got {other:?}"),
        }

        let mut tampered_signature = reference_info;
        *tampered_signature.last_mut().unwrap() ^= 1;
        match crate::sync::verify_uvm_endorsement(&tampered_signature, TRUSTED_ACI_DIDX509) {
            Err(AciError::Signature(actual)) => assert_contains(
                &actual.to_ascii_lowercase(),
                "signature verification failed",
            ),
            other => panic!("expected Signature error, got {other:?}"),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn step3_policy_binding_works_and_rejects_invalid_inputs() {
        let attestation = attestation_fixture();
        let endorsements = amd_endorsement_fixture();
        let endorsement_refs = endorsement_refs(&endorsements);
        let report = crate::sync::verify_attestation(&attestation, &endorsement_refs).unwrap();
        let uvm =
            crate::sync::verify_uvm_endorsement(&reference_info_fixture(), TRUSTED_ACI_DIDX509)
                .unwrap();

        let report_data = verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        )
        .unwrap();
        assert_eq!(report_data, report.report_data);

        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN + 1,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "UVM SVN 104 is below trusted minimum 105")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut policy = report.host_data;
        policy[0] ^= 1;
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![policy],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "SNP HOST_DATA does not match trusted policy")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut wrong_feed = uvm.clone();
        endorsement_v1_mut(&mut wrong_feed).feed = Some("not-confidential-aci".to_string());
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            wrong_feed,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => assert_eq!(
                actual,
                "UVM feed Some(\"not-confidential-aci\") does not match trusted feed ContainerPlat-AMD-UVM"
            ),
            other => panic!("expected Policy error, got {other:?}"),
        }

        let matching_cpuid = snp::Cpuid::from(MILAN_CPUID);
        let mut minimum_tcb = report.reported_tcb;
        minimum_tcb.raw[0] = minimum_tcb.raw[0].saturating_add(1);
        match verify_c_aci_attestation(
            report,
            vec![(matching_cpuid, minimum_tcb)],
            vec![report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => assert_contains(&actual, "SNP reported TCB"),
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut wrong_measurement = report;
        wrong_measurement.measurement[0] ^= 1;
        match verify_c_aci_attestation(
            wrong_measurement,
            Vec::new(),
            vec![wrong_measurement.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => assert_eq!(
                actual,
                "ACI payload measurement does not match attestation measurement"
            ),
            other => panic!("expected Measurement error, got {other:?}"),
        }

        let debug_report = report_with_debug_enabled();
        match verify_c_aci_attestation(
            debug_report,
            Vec::new(),
            vec![debug_report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "SNP guest policy allows debug mode")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let host_report = report_with_vmpl(4);
        match verify_c_aci_attestation(
            host_report,
            Vec::new(),
            vec![host_report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "SNP report VMPL is outside the guest range")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut missing_svn_int = uvm.clone();
        endorsement_v1_mut(&mut missing_svn_int).payload =
            reference_payload_without_guestsvn_int(report);
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            missing_svn_int,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => {
                assert_eq!(actual, "x-ms-sevsnpvm-guestsvn-int must be a JSON integer")
            }
            other => panic!("expected Measurement error, got {other:?}"),
        }

        let mut uppercase_measurement = uvm;
        endorsement_v1_mut(&mut uppercase_measurement).payload =
            reference_payload_with_uppercase_measurement(report);
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uppercase_measurement,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => assert_eq!(
                actual,
                "x-ms-sevsnpvm-launchmeasurement must match ^[0-9a-f]+$"
            ),
            other => panic!("expected Measurement error, got {other:?}"),
        }
    }
}

#[cfg(async_crypto)]
mod r#async {
    use super::*;

    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn verifies_caci_attestation_end_to_end() {
        let attestation = attestation_fixture();
        let endorsements = amd_endorsement_fixture();
        let endorsement_refs = endorsement_refs(&endorsements);
        let reference_info = reference_info_fixture();

        let report = crate::asynchronous::verify_attestation(&attestation, &endorsement_refs)
            .await
            .unwrap();
        let uvm = crate::asynchronous::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509)
            .await
            .unwrap();

        let report_data = verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uvm,
            ACI_FEED,
            ACI_SVN,
        )
        .unwrap();

        assert_eq!(report_data, report.report_data);
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn step1_attestation_verification_works_and_rejects_invalid_inputs() {
        let attestation = attestation_fixture();
        let endorsements = amd_endorsement_fixture();
        let endorsement_refs = endorsement_refs(&endorsements);

        let report = crate::asynchronous::verify_attestation(&attestation, &endorsement_refs)
            .await
            .unwrap();
        assert_verified_attestation_matches_fixture(report);

        match crate::asynchronous::verify_attestation(&attestation, &endorsement_refs[..2]).await {
            Err(AciError::InvalidAmdEndorsements(actual)) => {
                assert_eq!(actual, "expected [vcek, ask, ark], got 2 certificate(s)")
            }
            other => panic!("expected InvalidAmdEndorsements, got {other:?}"),
        }

        let truncated = &attestation[..64];
        match crate::asynchronous::verify_attestation(truncated, &endorsement_refs).await {
            Err(AciError::InvalidAttestation(actual)) => assert_contains(&actual, "SizeError"),
            other => panic!("expected InvalidAttestation, got {other:?}"),
        }

        let mut tampered = attestation.clone();
        tampered[100] ^= 0xff;
        match crate::asynchronous::verify_attestation(&tampered, &endorsement_refs).await {
            Err(AciError::AttestationVerification(
                attestation::snp::verify::VerificationError::SignatureVerificationError(actual),
            )) => assert_contains(
                &actual.to_ascii_lowercase(),
                "signature verification failed",
            ),
            other => panic!("expected attestation signature verification error, got {other:?}"),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn step2_uvm_endorsement_verification_works_and_rejects_invalid_inputs() {
        let reference_info = reference_info_fixture();
        let expected_report = parse_attestation(&attestation_fixture()).unwrap();

        let uvm = crate::asynchronous::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509)
            .await
            .unwrap();
        assert_verified_uvm_matches_fixture(&uvm, expected_report);

        match crate::asynchronous::verify_uvm_endorsement(b"not cose", TRUSTED_ACI_DIDX509).await {
            Err(AciError::Cose(actual)) => assert_eq!(actual, "Failed to parse CBOR bytes"),
            other => panic!("expected Cose error, got {other:?}"),
        }

        match crate::asynchronous::verify_uvm_endorsement(&reference_info, "not-a-did").await {
            Err(AciError::DidX509(actual)) => {
                assert_eq!(actual, "expected did:x509:0:sha256:<fingerprint>")
            }
            other => panic!("expected DidX509 error, got {other:?}"),
        }

        match crate::asynchronous::verify_uvm_endorsement(
            &reference_info,
            "did:x509:0:sha256:wrong",
        )
        .await
        {
            Err(AciError::DidX509(actual)) => assert_eq!(
                actual,
                "issuer DID prefix did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s does not match trusted DID prefix did:x509:0:sha256:wrong"
            ),
            other => panic!("expected DidX509 error, got {other:?}"),
        }

        let mut tampered_signature = reference_info;
        *tampered_signature.last_mut().unwrap() ^= 1;
        match crate::asynchronous::verify_uvm_endorsement(&tampered_signature, TRUSTED_ACI_DIDX509)
            .await
        {
            Err(AciError::Signature(actual)) => assert_contains(
                &actual.to_ascii_lowercase(),
                "signature verification failed",
            ),
            other => panic!("expected Signature error, got {other:?}"),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn step3_policy_binding_works_and_rejects_invalid_inputs() {
        let attestation = attestation_fixture();
        let endorsements = amd_endorsement_fixture();
        let endorsement_refs = endorsement_refs(&endorsements);
        let report = crate::asynchronous::verify_attestation(&attestation, &endorsement_refs)
            .await
            .unwrap();
        let uvm = crate::asynchronous::verify_uvm_endorsement(
            &reference_info_fixture(),
            TRUSTED_ACI_DIDX509,
        )
        .await
        .unwrap();

        let report_data = verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        )
        .unwrap();
        assert_eq!(report_data, report.report_data);

        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN + 1,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "UVM SVN 104 is below trusted minimum 105")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut policy = report.host_data;
        policy[0] ^= 1;
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![policy],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "SNP HOST_DATA does not match trusted policy")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut wrong_feed = uvm.clone();
        endorsement_v1_mut(&mut wrong_feed).feed = Some("not-confidential-aci".to_string());
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            wrong_feed,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => assert_eq!(
                actual,
                "UVM feed Some(\"not-confidential-aci\") does not match trusted feed ContainerPlat-AMD-UVM"
            ),
            other => panic!("expected Policy error, got {other:?}"),
        }

        let matching_cpuid = snp::Cpuid::from(MILAN_CPUID);
        let mut minimum_tcb = report.reported_tcb;
        minimum_tcb.raw[0] = minimum_tcb.raw[0].saturating_add(1);
        match verify_c_aci_attestation(
            report,
            vec![(matching_cpuid, minimum_tcb)],
            vec![report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => assert_contains(&actual, "SNP reported TCB"),
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut wrong_measurement = report;
        wrong_measurement.measurement[0] ^= 1;
        match verify_c_aci_attestation(
            wrong_measurement,
            Vec::new(),
            vec![wrong_measurement.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => assert_eq!(
                actual,
                "ACI payload measurement does not match attestation measurement"
            ),
            other => panic!("expected Measurement error, got {other:?}"),
        }

        let debug_report = report_with_debug_enabled();
        match verify_c_aci_attestation(
            debug_report,
            Vec::new(),
            vec![debug_report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "SNP guest policy allows debug mode")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let host_report = report_with_vmpl(4);
        match verify_c_aci_attestation(
            host_report,
            Vec::new(),
            vec![host_report.host_data],
            uvm.clone(),
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Policy(actual)) => {
                assert_eq!(actual, "SNP report VMPL is outside the guest range")
            }
            other => panic!("expected Policy error, got {other:?}"),
        }

        let mut missing_svn_int = uvm.clone();
        endorsement_v1_mut(&mut missing_svn_int).payload =
            reference_payload_without_guestsvn_int(report);
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            missing_svn_int,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => {
                assert_eq!(actual, "x-ms-sevsnpvm-guestsvn-int must be a JSON integer")
            }
            other => panic!("expected Measurement error, got {other:?}"),
        }

        let mut uppercase_measurement = uvm;
        endorsement_v1_mut(&mut uppercase_measurement).payload =
            reference_payload_with_uppercase_measurement(report);
        match verify_c_aci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uppercase_measurement,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => assert_eq!(
                actual,
                "x-ms-sevsnpvm-launchmeasurement must match ^[0-9a-f]+$"
            ),
            other => panic!("expected Measurement error, got {other:?}"),
        }
    }
}

fn attestation_fixture() -> Vec<u8> {
    hex_to_bytes(REPORT_HEX.trim()).unwrap()
}

fn reference_info_fixture() -> Vec<u8> {
    decode_base64_fixture(REFERENCE_INFO_BASE64)
}

fn amd_endorsement_fixture() -> [Vec<u8>; 3] {
    endorsements_from_host_amd_cert_fixture(HOST_AMD_CERT_BASE64).unwrap()
}

fn endorsement_refs(endorsements: &[Vec<u8>; 3]) -> [&[u8]; 3] {
    [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ]
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

fn decode_base64_fixture(encoded: &str) -> Vec<u8> {
    let encoded = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    base64_standard_decode(&encoded).unwrap()
}

fn assert_verified_attestation_matches_fixture(report: AttestationReport) {
    let expected = parse_attestation(&attestation_fixture()).unwrap();
    assert_eq!(report.measurement, expected.measurement);
    assert_eq!(report.host_data, expected.host_data);
    assert_eq!(report.report_data, expected.report_data);
}

fn assert_verified_uvm_matches_fixture(
    endorsement: &CaciUvmEndorsement,
    expected_report: AttestationReport,
) {
    let v1 = endorsement_v1(endorsement);
    let payload = endorsement_payload(endorsement);

    assert_eq!(v1.issuer, TRUSTED_ACI_DIDX509);
    assert_eq!(v1.feed.as_deref(), Some(ACI_FEED));
    assert_eq!(endorsement_svn(endorsement), Some(ACI_SVN.to_string()));
    assert!(v1.x5chain.len() >= 2);
    assert_eq!(payload.measurement, expected_report.measurement);
}

fn report_with_debug_enabled() -> AttestationReport {
    report_from_reference_fixture(|bytes| {
        let mut policy = u64::from_le_bytes(bytes[0x008..0x010].try_into().unwrap());
        policy |= 1 << 19;
        bytes[0x008..0x010].copy_from_slice(&policy.to_le_bytes());
    })
}

fn report_with_vmpl(vmpl: u32) -> AttestationReport {
    report_from_reference_fixture(|bytes| {
        bytes[0x030..0x034].copy_from_slice(&vmpl.to_le_bytes());
    })
}

fn report_from_reference_fixture(mutate: impl FnOnce(&mut [u8])) -> AttestationReport {
    let mut report = attestation_fixture();
    mutate(&mut report);
    parse_attestation(&report).unwrap()
}

fn reference_payload_without_guestsvn_int(report: AttestationReport) -> Vec<u8> {
    format!(
        r#"{{
            "x-ms-sevsnpvm-launchmeasurement": "{}",
            "x-ms-sevsnpvm-guestsvn": "{}"
        }}"#,
        measurement_hex_lower(report),
        ACI_SVN,
    )
    .into_bytes()
}

fn reference_payload_with_uppercase_measurement(report: AttestationReport) -> Vec<u8> {
    format!(
        r#"{{
            "x-ms-sevsnpvm-launchmeasurement": "{}",
            "x-ms-sevsnpvm-guestsvn": "{}",
            "x-ms-sevsnpvm-guestsvn-int": {}
        }}"#,
        measurement_hex_upper(report),
        ACI_SVN,
        ACI_SVN,
    )
    .into_bytes()
}

fn measurement_hex_lower(report: AttestationReport) -> String {
    report
        .measurement
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn measurement_hex_upper(report: AttestationReport) -> String {
    report
        .measurement
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn endorsement_v1(endorsement: &CaciUvmEndorsement) -> &CaciUvmEndorsementV1 {
    match endorsement {
        CaciUvmEndorsement::V1(v1) => v1,
        #[allow(unreachable_patterns)]
        _ => panic!("expected CACI UVM endorsement V1"),
    }
}

fn endorsement_v1_mut(endorsement: &mut CaciUvmEndorsement) -> &mut CaciUvmEndorsementV1 {
    match endorsement {
        CaciUvmEndorsement::V1(v1) => v1,
        #[allow(unreachable_patterns)]
        _ => panic!("expected CACI UVM endorsement V1"),
    }
}

fn endorsement_payload(endorsement: &CaciUvmEndorsement) -> ReferenceInfoPayload {
    let v1 = endorsement_v1(endorsement);
    measurement_from_payload(&v1.payload, &v1.content_type).unwrap()
}

fn endorsement_svn(endorsement: &CaciUvmEndorsement) -> Option<String> {
    let v1 = endorsement_v1(endorsement);
    endorsement_payload(endorsement).svn.or(v1.svn.clone())
}

fn assert_contains(actual: &str, expected: &str) {
    assert!(
        actual.contains(expected),
        "expected error to contain {expected:?}, got {actual:?}"
    );
}
