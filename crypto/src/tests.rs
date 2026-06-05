// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{Certificate, CertificateBackend, Crypto};

const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
const GENOA_ARK: &[u8] = include_bytes!("test_data/genoa_ark.pem");
const GENOA_ASK: &[u8] = include_bytes!("test_data/genoa_ask.pem");
const GENOA_VCEK: &[u8] = include_bytes!("test_data/genoa_vcek.pem");

const EC_TEST_MESSAGE: &[u8] = b"tee-attestation-verification crypto ec curve test vector";

const P256_SPKI_DER: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x44, 0xc8, 0x0b, 0xd0, 0x2c,
    0x87, 0x3a, 0x73, 0xca, 0x29, 0x7d, 0x35, 0x4b, 0x43, 0xd6, 0xc2, 0xef, 0xb5, 0xed, 0xc2, 0xa0,
    0x73, 0xa5, 0xdd, 0x64, 0xb3, 0xd1, 0x9e, 0xb3, 0xfb, 0x2c, 0xad, 0xc9, 0x0e, 0xfa, 0xd4, 0x9b,
    0xea, 0x7e, 0x56, 0x6c, 0x35, 0x2d, 0x9e, 0xd7, 0x2f, 0x71, 0x4b, 0x1a, 0x7e, 0xab, 0x40, 0x89,
    0x84, 0x65, 0x89, 0x96, 0xe8, 0x72, 0xa2, 0x59, 0x6e, 0x85, 0x18,
];

const P256_SIGNATURE_FIXED: &[u8] = &[
    0x4a, 0xe0, 0x7c, 0x36, 0x2c, 0x8f, 0xde, 0x1e, 0xcd, 0x60, 0x25, 0xa6, 0x78, 0x4a, 0x72, 0x5c,
    0xe3, 0x6a, 0x07, 0x0c, 0xc5, 0x32, 0x55, 0xd3, 0xf0, 0xba, 0xfc, 0x89, 0xd9, 0xaa, 0xd1, 0xc3,
    0xf8, 0x65, 0x3c, 0xe9, 0xe2, 0x79, 0xe4, 0x56, 0xf3, 0x45, 0x6b, 0x1c, 0x9b, 0x25, 0x62, 0x2b,
    0x7d, 0xde, 0xf5, 0x43, 0xfc, 0x09, 0x78, 0x2c, 0x1b, 0xc2, 0x4e, 0x12, 0x3d, 0xbc, 0x0f, 0x16,
];

const P384_SPKI_DER: &[u8] = &[
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xe3, 0xca, 0x56, 0x1f, 0xb9, 0xa3, 0x19, 0xd8,
    0x36, 0x16, 0xcf, 0x4a, 0x93, 0x61, 0x82, 0x52, 0x46, 0x14, 0x81, 0x30, 0xec, 0xc5, 0x44, 0x6d,
    0xba, 0x68, 0xab, 0x94, 0x4d, 0x81, 0x46, 0xab, 0x50, 0xc1, 0x7f, 0xcd, 0x84, 0xcc, 0x1b, 0x94,
    0x7d, 0x34, 0x6a, 0xa5, 0xf1, 0x9c, 0xc4, 0x0d, 0x71, 0xd2, 0xae, 0xdf, 0xbe, 0x11, 0x0e, 0x71,
    0x7d, 0x23, 0x05, 0x1c, 0x98, 0x7c, 0x33, 0x68, 0x2b, 0xb2, 0x45, 0xc4, 0xfa, 0x36, 0x82, 0x59,
    0x9e, 0x1f, 0x78, 0x6b, 0x27, 0x93, 0x6a, 0x2b, 0x9e, 0xfb, 0x18, 0x01, 0x89, 0x00, 0x28, 0x7d,
    0xc5, 0x6f, 0xab, 0x40, 0xd1, 0x42, 0xc6, 0x5f,
];

const P384_SIGNATURE_FIXED: &[u8] = &[
    0xdd, 0x2b, 0x15, 0xe0, 0xd1, 0x32, 0x67, 0xf1, 0x61, 0x0d, 0x4c, 0xb9, 0x06, 0x7f, 0x72, 0x30,
    0xf5, 0x85, 0x05, 0xb2, 0x64, 0x65, 0xbf, 0xdd, 0x79, 0x74, 0x17, 0xba, 0x26, 0xbc, 0x39, 0xe2,
    0x29, 0x27, 0x3b, 0x71, 0x5d, 0x1e, 0x83, 0x83, 0x25, 0xb8, 0x2c, 0x1b, 0x0f, 0xec, 0x8f, 0xbb,
    0xac, 0xc6, 0x48, 0x7c, 0x82, 0xdf, 0xea, 0x51, 0xee, 0x8a, 0xf8, 0xe3, 0xe6, 0x91, 0xcb, 0x03,
    0x00, 0xf2, 0xe6, 0x02, 0x97, 0xd5, 0xd0, 0x2e, 0x81, 0x3f, 0x2a, 0x5b, 0xd8, 0xfe, 0x43, 0xd6,
    0xbe, 0x0d, 0xa3, 0x81, 0x62, 0xfb, 0x0d, 0xd2, 0x7b, 0x8e, 0x1a, 0x62, 0x3e, 0xcb, 0x04, 0xe3,
];

const P521_SPKI_DER: &[u8] = &[
    0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
    0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00, 0x04, 0x00, 0xb7, 0x86, 0xc6, 0xa7, 0x9f,
    0xd1, 0x6c, 0x08, 0xc0, 0xa3, 0x04, 0x40, 0x42, 0xd5, 0xf0, 0x7b, 0xad, 0x2f, 0xe5, 0x39, 0x31,
    0xa5, 0x6f, 0xf1, 0xa7, 0x95, 0xc6, 0x5f, 0xa2, 0x42, 0xb7, 0x90, 0x98, 0xa9, 0x3a, 0x2f, 0x26,
    0x5f, 0x59, 0xdf, 0x52, 0xc9, 0x75, 0x1e, 0x04, 0x12, 0x89, 0x67, 0xa0, 0xcc, 0x0c, 0x02, 0xb8,
    0x24, 0xe5, 0xcb, 0x47, 0x04, 0xf0, 0xed, 0x2b, 0xe8, 0xc2, 0x8e, 0xd4, 0x01, 0x2d, 0xcc, 0xbc,
    0xb6, 0xc3, 0xc0, 0x14, 0x04, 0x04, 0x23, 0xfd, 0xcc, 0x52, 0x80, 0xb6, 0xf3, 0x39, 0xfb, 0xca,
    0xbe, 0xb9, 0xc3, 0x9a, 0xf7, 0x45, 0x1c, 0x96, 0x82, 0xf4, 0x23, 0x06, 0x90, 0xda, 0x86, 0x7b,
    0xd0, 0xb0, 0xab, 0x09, 0xec, 0xea, 0xfb, 0x82, 0x82, 0x72, 0x19, 0x9d, 0x7d, 0xe9, 0x84, 0x8b,
    0x23, 0x00, 0x81, 0x5e, 0x6a, 0xb0, 0x1c, 0xcb, 0x65, 0x39, 0x80, 0x13, 0x04, 0xb6,
];

const P521_SIGNATURE_FIXED: &[u8] = &[
    0x01, 0x5a, 0x9b, 0x7c, 0xcd, 0x37, 0x2c, 0xa5, 0x14, 0xd9, 0xe8, 0x56, 0x9c, 0xc3, 0xd9, 0x5b,
    0x0c, 0x2f, 0xa3, 0xce, 0xe9, 0x8a, 0x85, 0xf7, 0xa3, 0x47, 0x98, 0xab, 0xd5, 0x3c, 0x5f, 0x99,
    0xc7, 0x1a, 0xa1, 0x5a, 0xd8, 0x64, 0x41, 0xac, 0x2f, 0xfb, 0x1b, 0x95, 0x23, 0xac, 0xd6, 0xbb,
    0x20, 0xc0, 0xce, 0x17, 0x20, 0xf2, 0xf4, 0x19, 0xc5, 0xba, 0x06, 0x96, 0x86, 0x4f, 0x3d, 0x82,
    0xe1, 0x68, 0x01, 0xe1, 0x3a, 0x89, 0x11, 0xf5, 0x27, 0xb8, 0xec, 0x3a, 0x84, 0x0a, 0xc0, 0xc8,
    0x04, 0xf6, 0x61, 0x16, 0x1b, 0x43, 0x17, 0x2f, 0x46, 0x47, 0x5b, 0xf1, 0x1b, 0x2b, 0xd3, 0x6d,
    0xda, 0xe9, 0x90, 0x2a, 0xe9, 0x4d, 0x0f, 0x2e, 0x3e, 0x9f, 0x33, 0x5c, 0x61, 0x60, 0x81, 0xb8,
    0x22, 0xa5, 0xe9, 0xe8, 0xdf, 0x03, 0x49, 0xf3, 0x15, 0x5a, 0x95, 0x6c, 0x64, 0x3b, 0x9a, 0xb6,
    0x4e, 0x30, 0xec, 0x2e,
];

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
    use crate::{
        AsyncCryptoBackend, AsyncKeyBackend, AsyncKeySignatureBackend, EcSignatureKeyAlgorithm,
        SignatureBackend, SignatureKeyAlgorithm,
    };

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
    async fn ecdsa_fixed_signatures_verify_for_all_supported_curves() {
        for vector in ec_signature_vectors() {
            let key = <Crypto as AsyncKeyBackend>::key_from_spki_der(
                vector.spki_der,
                SignatureKeyAlgorithm::Ec(vector.algorithm),
            )
            .await
            .expect("ECDSA public key should parse");
            let (r, s) = vector.components();
            let signature =
                <Crypto as SignatureBackend>::signature_from_ec_components(r, s, vector.algorithm)
                    .expect("ECDSA signature components should parse");

            <Crypto as AsyncKeySignatureBackend>::verify_signature(
                &key,
                &signature,
                EC_TEST_MESSAGE,
            )
            .await
            .expect("ECDSA fixed-width signature should verify");
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn ecdsa_fixed_signatures_reject_tampering() {
        for vector in ec_signature_vectors() {
            let key = <Crypto as AsyncKeyBackend>::key_from_spki_der(
                vector.spki_der,
                SignatureKeyAlgorithm::Ec(vector.algorithm),
            )
            .await
            .expect("ECDSA public key should parse");
            let mut tampered = vector.signature.to_vec();
            let last = tampered.last_mut().expect("test signature is not empty");
            *last ^= 0x01;
            let scalar_len = vector.algorithm.scalar_byte_len();
            let signature = <Crypto as SignatureBackend>::signature_from_ec_components(
                &tampered[..scalar_len],
                &tampered[scalar_len..],
                vector.algorithm,
            )
            .expect("tampered ECDSA signature components should parse");

            <Crypto as AsyncKeySignatureBackend>::verify_signature(
                &key,
                &signature,
                EC_TEST_MESSAGE,
            )
            .await
            .expect_err("tampered ECDSA signature should fail");
        }
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

    struct EcSignatureVector {
        algorithm: EcSignatureKeyAlgorithm,
        spki_der: &'static [u8],
        signature: &'static [u8],
    }

    impl EcSignatureVector {
        fn components(&self) -> (&'static [u8], &'static [u8]) {
            self.signature.split_at(self.algorithm.scalar_byte_len())
        }
    }

    fn ec_signature_vectors() -> [EcSignatureVector; 3] {
        [
            EcSignatureVector {
                algorithm: EcSignatureKeyAlgorithm::P256,
                spki_der: P256_SPKI_DER,
                signature: P256_SIGNATURE_FIXED,
            },
            EcSignatureVector {
                algorithm: EcSignatureKeyAlgorithm::P384,
                spki_der: P384_SPKI_DER,
                signature: P384_SIGNATURE_FIXED,
            },
            EcSignatureVector {
                algorithm: EcSignatureKeyAlgorithm::P521,
                spki_der: P521_SPKI_DER,
                signature: P521_SIGNATURE_FIXED,
            },
        ]
    }
}
