// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{Certificate, CertificateBackend, Crypto};

const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
const GENOA_ARK: &[u8] = include_bytes!("test_data/genoa_ark.pem");
const GENOA_ASK: &[u8] = include_bytes!("test_data/genoa_ask.pem");
const GENOA_VCEK: &[u8] = include_bytes!("test_data/genoa_vcek.pem");

fn cert(pem: &[u8]) -> Certificate {
    Crypto::from_pem(pem).unwrap()
}

#[test]
fn certificate_parse_and_encode_wrappers_round_trip() {
    let pem_chain = [MILAN_ASK, b"\n", MILAN_ARK].concat();
    let chain = Crypto::from_pem_chain(&pem_chain).expect("PEM chain should parse");
    assert_eq!(chain.len(), 2);

    let cert = cert(MILAN_VCEK);
    let der = Crypto::to_der(&cert).expect("DER encoding should succeed");
    let from_der = Crypto::from_der(&der).expect("DER parsing should succeed");
    assert_eq!(
        Crypto::to_der(&from_der).expect("Reparsed DER should encode"),
        der
    );

    let pem = Crypto::to_pem(&cert).expect("PEM encoding should succeed");
    let from_pem = Crypto::from_pem(pem.as_bytes()).expect("PEM parsing should succeed");
    assert_eq!(
        Crypto::to_der(&from_pem).expect("Reparsed PEM should encode as DER"),
        der
    );
}

#[test]
fn certificate_parse_wrappers_reject_invalid_input() {
    let malformed_pem = b"-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n";

    Crypto::from_pem(b"not a pem").expect_err("Invalid PEM should fail");
    Crypto::from_pem_chain(malformed_pem).expect_err("Invalid PEM chain should fail");
    Crypto::from_der(b"not der").expect_err("Invalid DER should fail");
}

#[test]
fn extension_lookup_rejects_malformed_oid() {
    let cert = cert(MILAN_VCEK);

    Crypto::get_extension_value_by_oid(&cert, "not-an-oid").expect_err("Malformed OID should fail");
}

#[cfg(sync_crypto)]
mod sync_tests {
    use super::*;
    use crate::CryptoBackend;

    #[test]
    fn full_chain_verifies() {
        <Crypto as CryptoBackend>::verify_chain(
            &cert(MILAN_ARK),
            &[&cert(MILAN_ASK)],
            &cert(MILAN_VCEK),
        )
        .unwrap();
    }

    #[test]
    fn untrusted_intermediates_are_required() {
        <Crypto as CryptoBackend>::verify_chain(&cert(MILAN_ARK), &[], &cert(MILAN_VCEK))
            .expect_err("VCEK should not verify without ASK intermediate");
    }

    #[test]
    fn self_signed_certificates() {
        <Crypto as CryptoBackend>::verify_chain(&cert(MILAN_ARK), &[], &cert(MILAN_ARK)).unwrap();
    }

    #[test]
    fn genoa_substitution_in_milan_chain_fails() {
        <Crypto as CryptoBackend>::verify_chain(
            &cert(GENOA_ARK),
            &[&cert(MILAN_ASK)],
            &cert(MILAN_VCEK),
        )
        .expect_err("Genoa ARK should not verify Milan ASK");

        <Crypto as CryptoBackend>::verify_chain(
            &cert(MILAN_ARK),
            &[&cert(GENOA_ASK)],
            &cert(MILAN_VCEK),
        )
        .expect_err("Milan ARK/Genoa ASK/Milan VCEK should not verify");

        <Crypto as CryptoBackend>::verify_chain(
            &cert(MILAN_ARK),
            &[&cert(MILAN_ASK)],
            &cert(GENOA_VCEK),
        )
        .expect_err("Milan ASK should not verify Genoa VCEK");
    }
}

#[cfg(async_crypto)]
mod async_tests {
    use super::*;
    use crate::AsyncCryptoBackend;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn full_chain_verifies() {
        <Crypto as AsyncCryptoBackend>::verify_chain(
            &cert(MILAN_ARK),
            &[&cert(MILAN_ASK)],
            &cert(MILAN_VCEK),
        )
        .await
        .unwrap();
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn untrusted_intermediates_are_required() {
        <Crypto as AsyncCryptoBackend>::verify_chain(&cert(MILAN_ARK), &[], &cert(MILAN_VCEK))
            .await
            .expect_err("VCEK should not verify without ASK intermediate");
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn self_signed_certificates() {
        <Crypto as AsyncCryptoBackend>::verify_chain(&cert(MILAN_ARK), &[], &cert(MILAN_ARK))
            .await
            .unwrap();
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn genoa_substitution_in_milan_chain_fails() {
        <Crypto as AsyncCryptoBackend>::verify_chain(
            &cert(GENOA_ARK),
            &[&cert(MILAN_ASK)],
            &cert(MILAN_VCEK),
        )
        .await
        .expect_err("Genoa ARK should not verify Milan ASK");

        <Crypto as AsyncCryptoBackend>::verify_chain(
            &cert(MILAN_ARK),
            &[&cert(GENOA_ASK)],
            &cert(MILAN_VCEK),
        )
        .await
        .expect_err("Milan ARK/Genoa ASK/Milan VCEK should not verify");

        <Crypto as AsyncCryptoBackend>::verify_chain(
            &cert(MILAN_ARK),
            &[&cert(MILAN_ASK)],
            &cert(GENOA_VCEK),
        )
        .await
        .expect_err("Milan ASK should not verify Genoa VCEK");
    }
}
