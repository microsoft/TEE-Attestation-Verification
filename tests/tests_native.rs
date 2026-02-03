#![cfg(not(target_arch = "wasm32"))]

mod common;

#[tokio::test]
async fn test_verify_milan_attestation() {
    let result = common::verify_milan_attestation()
        .await
        .expect("Verification call failed");

    assert!(
        result.is_valid,
        "Verification should pass: {:?}",
        result.errors
    );
}

#[tokio::test]
async fn test_verify_genoa_attestation() {
    let result = common::verify_genoa_attestation()
        .await
        .expect("Verification call failed");

    assert!(
        result.is_valid,
        "Verification should pass: {:?}",
        result.errors
    );
}

#[tokio::test]
async fn test_verify_turin_attestation() {
    let result = common::verify_turin_attestation()
        .await
        .expect("Verification call failed");

    assert!(
        result.is_valid,
        "Verification should pass: {:?}",
        result.errors
    );
}
