// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::time::{Duration, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

const CONTAINERPLAT_DID: &str =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
const CONTAINERPLAT_CHAIN: &str = include_str!("../fixtures/deployed/containerplat/chain.pem");
#[cfg(sync_crypto)]
const CONFAKS_CHAIN: &str = include_str!("../fixtures/deployed/confaks/chain.pem");
#[cfg(sync_crypto)]
const ROOT_CA_CHAIN: &str = include_str!("../fixtures/upstream/did-x509/chains/root-ca.pem");
#[cfg(sync_crypto)]
const SAN_CHAIN: &str = include_str!("../fixtures/upstream/did-x509/chains/san.pem");
#[cfg(sync_crypto)]
const FULCIO_CHAIN: &str = include_str!(
    "../fixtures/upstream/did-x509/chains/fulcio-issuer-extension-is-accepted-when-not-critical.pem"
);
const FULCIO_URI_CHAIN: &str =
    include_str!("../fixtures/upstream/did-x509/chains/fulcio-issuer-with-uri-san.pem");
#[cfg(sync_crypto)]
const UNRELATED_CANDIDATE_CHAIN: &str = include_str!(
    "../fixtures/upstream/did-x509/chains/unrelated-candidate-cannot-satisfy-ca-fingerprint.pem"
);
#[cfg(sync_crypto)]
const DUPLICATE_SUBJECT_CHAIN: &str = include_str!(
    "../fixtures/upstream/did-x509/chains/duplicate-certificate-subject-attribute.pem"
);
#[cfg(sync_crypto)]
const DOTTED_SUBJECT_OID_CHAIN: &str =
    include_str!("../fixtures/upstream/did-x509/chains/subject-predicate-supports-dotted-oid.pem");

#[cfg(sync_crypto)]
#[test]
fn deployed_chain_satisfies_did_at_recorded_validation_time() {
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        CONTAINERPLAT_DID,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("deployed chain should satisfy its did:x509 identifier");
}

#[cfg(sync_crypto)]
#[test]
fn every_predicate_must_match_the_leaf_certificate() {
    let did = concat!(
        "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s",
        "::eku:1.3.6.1.4.1.311.76.59.1.1",
        "::eku:1.3.6.1.4.1.311.76.59.1.2",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("every matching predicate should be evaluated");
}

#[cfg(sync_crypto)]
#[test]
fn query_before_the_fragment_is_rejected_as_invalid_did_syntax() {
    let did = concat!(
        "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s",
        "::eku:1.3.6.1.4.1.311.76.59.1.2?versionId=1",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("DID URL queries are outside the validation API");

    assert!(
        matches!(
            error,
            tee_attestation_verification_didx509::ValidationError::InvalidDid { .. }
        ),
        "{did}: {error:?}"
    );
}

#[cfg(sync_crypto)]
#[test]
fn supported_fingerprint_algorithms_match_the_trust_anchor() {
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);
    let vectors = [
        (
            "sha384",
            "7L-4m2a0TR6bNcltcT49DI2-Y17k9ROPgybgPaLKOgfpO7IV1ARUVhCScv2FTVN9",
        ),
        (
            "sha512",
            "06xB647AbekDgik1FAJfxvrsgLr7Yu2Qvi8w7zanaeMeBZwxT82TNcl-L9G9ltWN32LXDHBnh1GBd0c2quy9uw",
        ),
    ];

    for (algorithm, fingerprint) in vectors {
        let did = format!("did:x509:0:{algorithm}:{fingerprint}::eku:1.3.6.1.4.1.311.76.59.1.2");
        tee_attestation_verification_didx509::validation_sync::validate_pem(
            &did,
            CONTAINERPLAT_CHAIN,
            tee_attestation_verification_didx509::ValidationTime::At(validation_time),
            tee_attestation_verification_didx509::PolicyConfig::default(),
        )
        .expect("supported fingerprint should match the trust anchor");
    }
}

#[cfg(sync_crypto)]
#[test]
fn subject_predicate_matches_the_leaf_distinguished_name() {
    let did = concat!(
        "did:x509:0:sha256:wB-YrYI1eo_9-9izSw6aviwkdLz4O7-kgrK_VzU4_OA",
        "::subject:CN:example.com",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        ROOT_CA_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("subject predicate should match the leaf certificate");
}

#[cfg(sync_crypto)]
#[test]
fn san_predicate_matches_the_named_general_name_type() {
    let did = concat!(
        "did:x509:0:sha256:4Wf3Hy45zPgsSGXmjnDNLtSdRVo19eFjirPM3lALnzE",
        "::san:email:user%40example.com",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        SAN_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("email SAN predicate should match the leaf certificate");
}

#[cfg(sync_crypto)]
#[test]
fn fulcio_issuer_predicate_matches_the_leaf_extension() {
    let did = concat!(
        "did:x509:0:sha256:PlQPAxVWk8aA1p5PdiZUuSPTGxDYJoPu49PVrzI96Mw",
        "::fulcio-issuer:accounts.google.com",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        FULCIO_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("Fulcio issuer predicate should match the leaf extension");
}

#[cfg(sync_crypto)]
#[test]
fn ca_fingerprint_may_identify_an_intermediate() {
    let did = concat!(
        "did:x509:0:sha256:OclQt0d8P5pIN-GHWS7TzUhAPHtVcI5NVijTFUZKq10",
        "::subject:CN:example.com",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        ROOT_CA_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("CA fingerprint should match any non-leaf certificate in the verified chain");
}

#[cfg(sync_crypto)]
#[test]
fn every_supplied_certificate_must_belong_to_the_verified_path() {
    let did = concat!(
        "did:x509:0:sha256:vkPFk-BEjqxROoUZwGI-p-xhq-sByWByqHps-KEl-vI",
        "::subject:CN:Leaf",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        UNRELATED_CANDIDATE_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("an unrelated certificate must not satisfy the CA fingerprint");

    assert!(matches!(
        error,
        tee_attestation_verification_didx509::ValidationError::InvalidChain { .. }
    ));
}

#[cfg(sync_crypto)]
#[test]
fn sibling_ca_cannot_satisfy_the_ca_fingerprint() {
    let containerplat = certificate_pems(CONTAINERPLAT_CHAIN);
    let confaks = certificate_pems(CONFAKS_CHAIN);
    let spliced_chain = [
        containerplat[0],
        confaks[1],
        containerplat[1],
        containerplat[2],
    ]
    .join("\n");
    let did = concat!(
        "did:x509:0:sha256:u3FuwNk-A7E42z36cRcb5Zn4IIXEVgWPcGS6jtT8Gjo",
        "::eku:1.3.6.1.4.1.311.76.59.1.2",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        &spliced_chain,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("an unrelated sibling CA must not satisfy the fingerprint");

    assert!(matches!(
        error,
        tee_attestation_verification_didx509::ValidationError::InvalidChain { .. }
    ));
}

#[cfg(sync_crypto)]
fn certificate_pems(chain: &str) -> Vec<&str> {
    chain
        .split_inclusive("-----END CERTIFICATE-----")
        .filter(|block| block.contains("-----BEGIN CERTIFICATE-----"))
        .collect()
}

#[cfg(sync_crypto)]
#[test]
fn malformed_fragment_is_rejected_as_invalid_did_syntax() {
    let did = format!("{CONTAINERPLAT_DID}#credential%ZZ");
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        &did,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("malformed fragment escapes must be rejected");

    assert!(
        matches!(
            &error,
            tee_attestation_verification_didx509::ValidationError::InvalidDid { .. }
        ),
        "{did}: {error:?}"
    );
}

#[cfg(sync_crypto)]
#[test]
fn invalid_did_debug_output_retains_the_input() {
    let did = "did:y509:0:sha256:not-a-fingerprint::eku:1.2.3";
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("invalid DID must fail before certificate validation");

    assert!(format!("{error:?}").contains(did));
    assert!(!error.to_string().contains(did));
}

#[cfg(sync_crypto)]
#[test]
fn invalid_pem_debug_output_retains_the_input() {
    let chain_pem = "not a PEM bundle";
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        CONTAINERPLAT_DID,
        chain_pem,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("invalid PEM must fail");

    assert!(format!("{error:?}").contains(chain_pem));
    assert!(!error.to_string().contains(chain_pem));
}

#[cfg(sync_crypto)]
#[test]
fn pem_bundle_rejects_non_certificate_content() {
    let chain_pem = format!("{CONTAINERPLAT_CHAIN}\nnot a certificate\n");
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        CONTAINERPLAT_DID,
        &chain_pem,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("PEM bundle must contain only certificate blocks and whitespace");

    assert!(matches!(
        error,
        tee_attestation_verification_didx509::ValidationError::InvalidPem { .. }
    ));
}

#[cfg(sync_crypto)]
#[test]
fn predicate_mismatch_debug_output_retains_the_inputs() {
    let did = concat!(
        "did:x509:0:sha256:A__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s",
        "::eku:1.3.6.1.4.1.311.76.59.1.2",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("incorrect CA fingerprint must fail");
    let debug = format!("{error:?}");

    assert!(debug.contains(did));
    assert!(debug.contains("MIIGazCCBFOgAwIBAgITMwAAAE+CVvVEUdIgyAAAAAAATz"));
    assert!(!error.to_string().contains(did));
    assert!(!error.to_string().contains(CONTAINERPLAT_CHAIN));
}

#[cfg(sync_crypto)]
#[test]
fn invalid_chain_debug_output_retains_the_inputs() {
    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        CONTAINERPLAT_DID,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(UNIX_EPOCH),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("the deployed chain was not valid at the Unix epoch");
    let debug = format!("{error:?}");

    assert!(debug.contains(CONTAINERPLAT_DID));
    assert!(debug.contains("MIIGazCCBFOgAwIBAgITMwAAAE+CVvVEUdIgyAAAAAAATz"));
    assert!(!error.to_string().contains(CONTAINERPLAT_DID));
    assert!(!error.to_string().contains(CONTAINERPLAT_CHAIN));
}

#[cfg(sync_crypto)]
#[test]
fn predicate_components_require_strict_percent_encoding_and_utf8() {
    let method = "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s";
    let invalid_dids = [
        format!("{method}::san:email:user@example.com"),
        format!("{method}::subject:CN:%FF"),
        format!("{method}::subject:CN:%"),
        format!("{method}::subject:CN:raw~tilde"),
        format!("{method}::subject:CN:a:CN:b"),
        format!("{method}::subject:%43%4E:value"),
        format!("{method}::eku:1%2E2%2E3"),
        format!("{method}::unknown:value"),
        "did:x509:1:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s".to_owned(),
        "did:x509:0:sha256:AA".to_owned(),
        "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s=".to_owned(),
    ];
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    for did in invalid_dids {
        let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
            &did,
            CONTAINERPLAT_CHAIN,
            tee_attestation_verification_didx509::ValidationTime::At(validation_time),
            tee_attestation_verification_didx509::PolicyConfig::default(),
        )
        .expect_err("invalid predicate encoding must fail");
        if !matches!(
            &error,
            tee_attestation_verification_didx509::ValidationError::InvalidDid { .. }
        ) {
            panic!("{did}: {error:?}");
        }
    }
}

#[cfg(sync_crypto)]
#[test]
fn valid_nonminimal_percent_encoding_is_accepted() {
    let did = concat!(
        "did:x509:0:sha256:wB-YrYI1eo_9-9izSw6aviwkdLz4O7-kgrK_VzU4_OA",
        "::subject:CN:example%2ecom",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        ROOT_CA_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("valid lowercase nonminimal escapes remain accepted");
}

#[cfg(sync_crypto)]
#[test]
fn street_is_a_supported_subject_label() {
    let did = concat!(
        "did:x509:0:sha256:wB-YrYI1eo_9-9izSw6aviwkdLz4O7-kgrK_VzU4_OA",
        "::subject:STREET:Example%20Street",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        ROOT_CA_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("the fixture has no matching street address");

    assert!(matches!(
        error,
        tee_attestation_verification_didx509::ValidationError::PredicateMismatch { .. }
    ));
}

#[cfg(sync_crypto)]
#[test]
fn duplicate_certificate_subject_attributes_are_rejected() {
    let did = concat!(
        "did:x509:0:sha256:art98HvR-DXJOIrUtXvJRezYSK_qAwY3aLkXpoAij7M",
        "::subject:CN:Leaf",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    let error = tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        DUPLICATE_SUBJECT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect_err("repeated certificate subject attributes are unsupported");

    assert!(matches!(
        error,
        tee_attestation_verification_didx509::ValidationError::InvalidChain { .. }
    ));
}

#[cfg(sync_crypto)]
#[test]
fn dotted_subject_oid_matches_an_ia5_string_attribute() {
    let did = concat!(
        "did:x509:0:sha256:q8luFglUPIwAjp1iJMj3bvNMqOz_zuLDNCozLlV2Iwc",
        "::subject:1.2.840.113549.1.9.1:test%40example.com",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    tee_attestation_verification_didx509::validation_sync::validate_pem(
        did,
        DOTTED_SUBJECT_OID_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .expect("IA5String subject values should match by dotted OID");
}

#[cfg(async_crypto)]
async fn validate_deployed_chain_asynchronously() {
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_761_595_353);

    tee_attestation_verification_didx509::validation_async::validate_pem(
        CONTAINERPLAT_DID,
        CONTAINERPLAT_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .await
    .expect("asynchronous validation should use the same contract");
}

#[cfg(async_crypto)]
async fn validate_fulcio_and_uri_san_asynchronously() {
    let did = concat!(
        "did:x509:0:sha256:4Wf3Hy45zPgsSGXmjnDNLtSdRVo19eFjirPM3lALnzE",
        "::fulcio-issuer:issuer.example.com",
        "::san:uri:https%3A%2F%2Fexample.com%2Fworkflow",
    );
    let validation_time = UNIX_EPOCH + Duration::from_secs(1_785_542_400);

    tee_attestation_verification_didx509::validation_async::validate_pem(
        did,
        FULCIO_URI_CHAIN,
        tee_attestation_verification_didx509::ValidationTime::At(validation_time),
        tee_attestation_verification_didx509::PolicyConfig::default(),
    )
    .await
    .expect("asynchronous validation should evaluate all predicates");
}

#[cfg(all(async_crypto, not(target_arch = "wasm32")))]
#[test]
fn asynchronous_api_validates_the_same_deployed_chain() {
    block_on(validate_deployed_chain_asynchronously());
}

#[cfg(all(async_crypto, not(target_arch = "wasm32")))]
#[test]
fn asynchronous_api_evaluates_fulcio_and_uri_san_predicates() {
    block_on(validate_fulcio_and_uri_san_asynchronously());
}

#[cfg(all(async_crypto, target_arch = "wasm32"))]
#[wasm_bindgen_test]
async fn webcrypto_validates_the_deployed_chain() {
    validate_deployed_chain_asynchronously().await;
}

#[cfg(all(async_crypto, target_arch = "wasm32", feature = "crypto_webcrypto"))]
#[wasm_bindgen_test]
async fn webcrypto_evaluates_fulcio_and_uri_san_predicates() {
    validate_fulcio_and_uri_san_asynchronously().await;
}

#[cfg(all(async_crypto, not(target_arch = "wasm32")))]
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};

    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}
