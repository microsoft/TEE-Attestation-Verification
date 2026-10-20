// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(crypto_backend = "crypto_openssl")]

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{extension::BasicConstraints, X509Name, X509},
};
use std::time::Duration;
use tee_attestation_verification_crypto::{AsyncCryptoBackend, Crypto, CryptoBackend};

fn certificate(
    serial: u32,
    issuer: Option<(&X509, &PKey<Private>)>,
    ca: bool,
) -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", &format!("certificate {serial}"))
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder
        .set_issuer_name(issuer.map_or(name.as_ref(), |(cert, _)| cert.subject_name()))
        .unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_str("20250101000000Z").unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_str("20300101000000Z").unwrap())
        .unwrap();
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if ca {
        constraints.ca();
    }
    builder
        .append_extension(constraints.build().unwrap())
        .unwrap();
    builder
        .sign(issuer.map_or(&key, |(_, key)| key), MessageDigest::sha256())
        .unwrap();
    (builder.build(), key)
}

#[tokio::test]
async fn default_chain_verification_requires_the_supplied_path() {
    let (root, root_key) = certificate(1, None, true);
    let (upper, upper_key) = certificate(2, Some((&root, &root_key)), true);
    let (lower, lower_key) = certificate(3, Some((&upper, &upper_key)), true);
    let (leaf, _) = certificate(4, Some((&lower, &lower_key)), false);
    let (unrelated, _) = certificate(5, None, true);
    let time = Some(Duration::from_secs(1_785_542_400));

    for (anchor, intermediates, target) in [
        (&root, vec![&upper, &lower], &leaf),
        (&upper, vec![&lower], &leaf),
        (&root, vec![], &root),
    ] {
        <Crypto as CryptoBackend>::verify_chain(anchor, &intermediates, target, time).unwrap();
        <Crypto as AsyncCryptoBackend>::verify_chain(anchor, &intermediates, target, time)
            .await
            .unwrap();
    }

    for intermediates in [
        vec![&lower, &upper],
        vec![&unrelated, &upper, &lower],
        vec![&upper, &lower, &lower],
    ] {
        let error = <Crypto as CryptoBackend>::verify_chain(&root, &intermediates, &leaf, time)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Verified path differs from supplied path"
        );
        let error =
            <Crypto as AsyncCryptoBackend>::verify_chain(&root, &intermediates, &leaf, time)
                .await
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Verified path differs from supplied path"
        );
    }
}
