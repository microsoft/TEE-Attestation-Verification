// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde_json::Value;
use std::time::{Duration, UNIX_EPOCH};
use tee_attestation_verification_didx509::{
    DidDocument, PolicyConfig, ValidationError, ValidationTime,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

fn time(seconds: u64) -> ValidationTime {
    ValidationTime::At(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn assert_vector(vector: &Value, result: Result<DidDocument, ValidationError>) {
    let id = vector["id"].as_str().unwrap();
    // IP SANs cannot satisfy a DID predicate, but do not invalidate unrelated predicates.
    if id == "unsupported-certificate-san-type" {
        assert!(result.is_ok(), "{id}: {result:?}");
        return;
    }
    #[cfg(any(target_arch = "wasm32", windows))]
    if let Some(oid) = match id {
        "critical-certificate-policies-extension-is-accepted" => Some("2.5.29.32"),
        "san-within-permitted-subtree" => Some("2.5.29.30"),
        _ => None,
    } {
        let error = result.expect_err("TAV's partial path policy must fail closed");
        assert!(
            matches!(&error, ValidationError::InvalidChain { message, .. }
            if message.contains("unsupported extension") && message.contains(oid)),
            "{id}: {error}"
        );
        return;
    }
    if let Some(expected) = vector["output"].get("document") {
        let document = result.unwrap_or_else(|error| panic!("{id}: {error}"));
        let actual: Value = serde_json::from_str(&document.to_json()).unwrap();
        assert_eq!(&actual, expected, "{id}");
    } else {
        assert!(result.is_err(), "{id}: unexpectedly accepted");
    }
}

#[cfg(sync_crypto)]
#[test]
fn specification_vectors_resolve_synchronously() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../fixtures/upstream/did-x509/test-vectors.json"
    ))
    .unwrap();
    let times: Value = serde_json::from_str(include_str!(
        "../fixtures/upstream/did-x509/validation-times.json"
    ))
    .unwrap();
    for vector in vectors {
        let chain = vector["input"]["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let result = tee_attestation_verification_didx509::validation_sync::resolve_x509chain(
            vector["input"]["did"].as_str().unwrap(),
            &chain,
            time(times[vector["id"].as_str().unwrap()].as_u64().unwrap()),
            PolicyConfig::default(),
        );
        assert_vector(&vector, result);
    }
}

#[cfg(async_crypto)]
async fn asynchronous_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../fixtures/upstream/did-x509/test-vectors.json"
    ))
    .unwrap();
    let times: Value = serde_json::from_str(include_str!(
        "../fixtures/upstream/did-x509/validation-times.json"
    ))
    .unwrap();
    for vector in vectors {
        let chain = vector["input"]["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let result = tee_attestation_verification_didx509::validation_async::resolve_x509chain(
            vector["input"]["did"].as_str().unwrap(),
            &chain,
            time(times[vector["id"].as_str().unwrap()].as_u64().unwrap()),
            PolicyConfig::default(),
        )
        .await;
        assert_vector(&vector, result);
    }
}

#[cfg(all(async_crypto, target_arch = "wasm32"))]
#[wasm_bindgen_test]
async fn specification_vectors_resolve_with_webcrypto() {
    asynchronous_vectors().await;
}

#[cfg(all(async_crypto, not(target_arch = "wasm32")))]
#[test]
fn specification_vectors_resolve_asynchronously() {
    use std::task::{Context, Poll, Waker};
    let mut future = std::pin::pin!(asynchronous_vectors());
    match std::future::Future::poll(future.as_mut(), &mut Context::from_waker(Waker::noop())) {
        Poll::Ready(()) => {}
        Poll::Pending => panic!("Native TAV adapter unexpectedly suspended"),
    }
}

#[cfg(sync_crypto)]
#[test]
fn pem_der_and_specification_inputs_produce_the_same_document() {
    use tee_attestation_verification_crypto::{
        base64::base64_encode_no_padding, CertificateBackend, Crypto,
    };
    let pem = include_str!("../fixtures/deployed/containerplat/chain.pem");
    let did = "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
    let certificates = Crypto::from_pem_chain(pem.as_bytes()).unwrap();
    let der: Vec<_> = certificates
        .iter()
        .map(|cert| Crypto::to_der(cert).unwrap())
        .collect();
    let refs: Vec<_> = der.iter().map(Vec::as_slice).collect();
    let chain = der
        .iter()
        .map(|der| base64_encode_no_padding(der))
        .collect::<Vec<_>>()
        .join(",");
    let at = time(1761595353);
    let policy = PolicyConfig::default();
    let expected =
        tee_attestation_verification_didx509::validation_sync::resolve_pem(did, pem, at, policy)
            .unwrap();
    assert_eq!(
        tee_attestation_verification_didx509::validation_sync::resolve_der(did, &refs, at, policy)
            .unwrap(),
        expected
    );
    assert_eq!(
        tee_attestation_verification_didx509::validation_sync::resolve_x509chain(
            did, &chain, at, policy
        )
        .unwrap(),
        expected
    );
    assert_eq!(
        tee_attestation_verification_didx509::validation_sync::resolve_jwk_pem(
            did, pem, at, policy
        )
        .unwrap(),
        expected.verification_method.public_key_jwk
    );

    let mut trailing = der.clone();
    trailing[0].push(0);
    let refs: Vec<_> = trailing.iter().map(Vec::as_slice).collect();
    assert!(
        tee_attestation_verification_didx509::validation_sync::validate_der(did, &refs, at, policy)
            .is_err()
    );
    for malformed in [
        format!("{chain},"),
        format!(",{chain}"),
        format!("{chain}="),
        "AA".into(),
    ] {
        assert!(
            tee_attestation_verification_didx509::validation_sync::validate_x509chain(
                did, &malformed, at, policy
            )
            .is_err()
        );
    }
}

#[test]
fn errors_can_cross_thread_boundaries() {
    fn require<T: Send + Sync + 'static>() {}
    require::<ValidationError>();
}
