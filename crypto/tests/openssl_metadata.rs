// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(crypto_backend = "crypto_openssl")]

use foreign_types_shared::ForeignType;
use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time},
    bn::{BigNum, BigNumContext},
    ec::{Asn1Flag, EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPublic, PKey, Private},
    rsa::Rsa,
    x509::{extension::KeyUsage, X509Extension, X509Name, X509},
};
use std::ffi::CString;
use tee_attestation_verification_crypto::{
    x509::{PublicKey, SubjectAlternativeName},
    CertificateBackend, Crypto,
};

fn name(entries: &[(&str, i32, &[u8], bool)]) -> X509Name {
    let name = X509Name::builder().unwrap().build();
    for (oid, tag, bytes, same_rdn) in entries {
        let oid = CString::new(*oid).unwrap();
        // SAFETY: name is uniquely owned; OpenSSL copies the supplied OID/value.
        assert_eq!(
            unsafe {
                openssl_sys::X509_NAME_add_entry_by_txt(
                    name.as_ptr(),
                    oid.as_ptr(),
                    *tag,
                    bytes.as_ptr(),
                    bytes.len().try_into().unwrap(),
                    -1,
                    if *same_rdn { -1 } else { 0 },
                )
            },
            1
        );
    }
    name
}

fn default_name() -> X509Name {
    name(&[("CN", openssl_sys::V_ASN1_UTF8STRING, b"metadata", false)])
}

fn signing_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn certificate<T: HasPublic>(
    subject: &X509Name,
    extensions: Vec<X509Extension>,
    key: &PKey<T>,
) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(subject).unwrap();
    builder.set_issuer_name(&default_name()).unwrap();
    builder
        .set_not_before(&Asn1Time::from_str("20250101000000Z").unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_str("20300101000000Z").unwrap())
        .unwrap();
    builder.set_pubkey(key).unwrap();
    for extension in extensions {
        builder.append_extension(extension).unwrap();
    }
    builder
        .sign(&signing_key(), MessageDigest::sha256())
        .unwrap();
    let der = builder.build().to_der().unwrap();
    Crypto::from_der(&der).unwrap()
}

fn extension(oid: &str, der: &[u8]) -> X509Extension {
    X509Extension::new_from_der(
        &Asn1Object::from_str(oid).unwrap(),
        false,
        &Asn1OctetString::new_from_bytes(der).unwrap(),
    )
    .unwrap()
}

fn with_extension(oid: &str, der: &[u8]) -> X509 {
    certificate(&default_name(), vec![extension(oid, der)], &signing_key())
}

fn replace(der: &mut [u8], old: &[u8], new: &[u8], last: bool) {
    assert_eq!(old.len(), new.len());
    let offsets: Vec<_> = der
        .windows(old.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == old).then_some(index))
        .collect();
    let offset = if last {
        *offsets.last().unwrap()
    } else {
        *offsets.first().unwrap()
    };
    der[offset..offset + old.len()].copy_from_slice(new);
}

#[test]
fn preserves_rdn_groups_repeats_unicode_and_nuls() {
    let subject = name(&[
        (
            "CN",
            openssl_sys::V_ASN1_UTF8STRING,
            b"caf\xc3\xa9\0suffix",
            false,
        ),
        ("OU", openssl_sys::V_ASN1_PRINTABLESTRING, b"first", true),
        (
            "CN",
            openssl_sys::V_ASN1_BMPSTRING,
            b"\0s\0e\0c\0o\0n\0d",
            false,
        ),
        (
            "1.2.3.4",
            openssl_sys::V_ASN1_T61STRING,
            b"custom\0value",
            false,
        ),
    ]);
    let cert = certificate(&subject, vec![], &signing_key());
    let details = Crypto::certificate_details(&cert).unwrap();
    assert_eq!(
        details.subject.iter().map(Vec::len).collect::<Vec<_>>(),
        [2, 1, 1]
    );
    assert!(details.subject[0]
        .iter()
        .any(|a| a.oid == "2.5.4.3" && a.value == "caf\u{e9}\0suffix"));
    assert_eq!(details.subject[1][0].oid, "2.5.4.3");
    assert_eq!(details.subject[1][0].value, "second");
    assert_eq!(details.subject[2][0].oid, "1.2.3.4");
    assert_eq!(details.subject[2][0].value, "custom\0value");
}

#[test]
fn preserves_absent_and_present_empty_extensions() {
    let cert = certificate(&default_name(), vec![], &signing_key());
    let details = Crypto::certificate_details(&cert).unwrap();
    assert_eq!(details.subject_alt_names, None);
    assert_eq!(details.extended_key_usage, None);
    let cert = certificate(
        &default_name(),
        vec![
            extension("2.5.29.17", b"\x30\x00"),
            extension("2.5.29.37", b"\x30\x00"),
        ],
        &signing_key(),
    );
    let details = Crypto::certificate_details(&cert).unwrap();
    assert_eq!(details.subject_alt_names, Some(vec![]));
    assert_eq!(details.extended_key_usage, Some(vec![]));
}

#[test]
fn preserves_san_strings_and_non_predicate_names() {
    let cert = with_extension(
        "2.5.29.17",
        b"\x30\x15\x81\x03a\0b\x82\x03dns\x86\x03uri\x87\x04\x7f\0\0\x01",
    );
    assert_eq!(
        Crypto::certificate_details(&cert)
            .unwrap()
            .subject_alt_names
            .unwrap(),
        [
            SubjectAlternativeName::Email("a\0b".into()),
            SubjectAlternativeName::Dns("dns".into()),
            SubjectAlternativeName::Uri("uri".into()),
            SubjectAlternativeName::Other,
        ]
    );
}

#[test]
fn preserves_repeated_and_unknown_eku_oids() {
    let cert = with_extension(
        "2.5.29.37",
        b"\x30\x0c\x06\x02\x2a\x03\x06\x02\x2a\x03\x06\x02\x2a\x04",
    );
    assert_eq!(
        Crypto::certificate_details(&cert)
            .unwrap()
            .extended_key_usage
            .unwrap(),
        ["1.2.3", "1.2.3", "1.2.4"]
    );
}

#[test]
fn malformed_san_and_eku_are_errors_not_absence() {
    for oid in ["2.5.29.17", "2.5.29.37"] {
        for bytes in [
            b"\x30\x00\x00".as_slice(),
            b"\x30\x81\x00",
            b"\x30\x80\x00\x00",
            b"\x05\x00",
        ] {
            assert!(
                Crypto::certificate_details(&with_extension(oid, bytes)).is_err(),
                "{oid}: {bytes:x?}"
            );
        }
    }
    for bytes in [
        b"\x30\x04\x82\x02\xc3\xa9".as_slice(),
        b"\x30\x03\x81\x01\xff",
        b"\x30\x03\x86\x01\xff",
        b"\x30\x02\xa3\x00",
        b"\x30\x02\x89\x00",
    ] {
        assert!(
            Crypto::certificate_details(&with_extension("2.5.29.17", bytes)).is_err(),
            "{bytes:x?}"
        );
    }
    assert!(
        Crypto::certificate_details(&with_extension("2.5.29.37", b"\x30\x03\x06\x01\x80")).is_err()
    );
}

#[test]
fn duplicate_unknown_extensions_are_rejected() {
    let cert = certificate(
        &default_name(),
        vec![
            extension("1.2.3.4", b"\x05\x00"),
            extension("1.2.3.4", b"\x05\x00"),
        ],
        &signing_key(),
    );
    assert!(Crypto::certificate_details(&cert).is_err());
}

#[test]
fn rejects_invalid_subject_string_encodings() {
    let cert = certificate(
        &name(&[("CN", openssl_sys::V_ASN1_UTF8STRING, b"ab", false)]),
        vec![],
        &signing_key(),
    );
    let der = cert.to_der().unwrap();
    for invalid in [
        b"\x0c\x02\xc0\x80".as_slice(),
        b"\x13\x02a@",
        b"\x16\x02\xc3\xa9",
        b"\x14\x02\xc3\xa9",
        b"\x1e\x02\xd8\x00",
        b"\x1e\x02\xff\xff",
        b"\x1c\x02ab",
    ] {
        let mut mutated = der.clone();
        replace(&mut mutated, b"\x0c\x02ab", invalid, false);
        let result = Crypto::from_der(&mutated).and_then(|cert| Crypto::certificate_details(&cert));
        assert!(result.is_err(), "{invalid:x?}");
    }
}

#[test]
fn rejects_signature_algorithm_disagreement_without_mutating_shared_certificate() {
    let cert = certificate(&default_name(), vec![], &signing_key());
    let mut der = cert.to_der().unwrap();
    replace(
        &mut der,
        b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
        b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03",
        true,
    );
    let cert = Crypto::from_der(&der).unwrap();
    let shared = cert.clone();
    assert!(Crypto::certificate_details(&cert).is_err());
    assert_eq!(shared.to_der().unwrap(), der);
}

#[test]
fn rejects_explicit_default_version_without_mutating_shared_certificate() {
    let cert = certificate(&default_name(), vec![], &signing_key());
    let mut der = cert.to_der().unwrap();
    replace(
        &mut der,
        b"\xa0\x03\x02\x01\x02",
        b"\xa0\x03\x02\x01\x00",
        false,
    );
    let cert = Crypto::from_der(&der).unwrap();
    let shared = cert.clone();
    assert!(Crypto::certificate_details(&cert).is_err());
    assert_eq!(shared.to_der().unwrap(), der);
}

#[test]
fn extracts_key_usage_bits() {
    let cert = certificate(
        &default_name(),
        vec![KeyUsage::new()
            .digital_signature()
            .key_agreement()
            .build()
            .unwrap()],
        &signing_key(),
    );
    let usage = Crypto::key_usage(&cert).unwrap().unwrap();
    assert!(usage.digital_signature);
    assert!(usage.key_agreement);
    assert!(!usage.key_cert_sign);
}

#[test]
fn extracts_rsa_components_without_strength_policy() {
    let key = PKey::from_rsa(Rsa::generate(512).unwrap()).unwrap();
    let expected = key.rsa().unwrap();
    let cert = certificate(&default_name(), vec![], &key);
    assert_eq!(
        Crypto::public_key_components(&cert).unwrap(),
        PublicKey::Rsa {
            n: expected.n().to_vec(),
            e: expected.e().to_vec()
        }
    );
}

#[test]
fn extracts_all_named_ec_curves_with_fixed_width_coordinates() {
    for (nid, curve, width) in [
        (Nid::X9_62_PRIME256V1, "P-256", 32),
        (Nid::SECP384R1, "P-384", 48),
        (Nid::SECP521R1, "P-521", 66),
    ] {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let cert = certificate(&default_name(), vec![], &key);
        let PublicKey::Ec {
            curve: actual,
            x,
            y,
        } = Crypto::public_key_components(&cert).unwrap()
        else {
            panic!("Expected an EC key");
        };
        assert_eq!(actual, curve);
        assert_eq!((x.len(), y.len()), (width, width));
    }
}

#[test]
fn rejects_explicit_ec_parameters() {
    let mut group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    group.set_asn1_flag(Asn1Flag::EXPLICIT_CURVE);
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let cert = certificate(&default_name(), vec![], &key);
    assert!(Crypto::public_key_components(&cert).is_err());
}

#[test]
fn rejects_compressed_ec_points() {
    extern "C" {
        fn EC_KEY_set_conv_form(
            key: *mut openssl_sys::EC_KEY,
            form: openssl_sys::point_conversion_form_t,
        );
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    // SAFETY: key is uniquely owned and the conversion form is a valid enum value.
    unsafe {
        EC_KEY_set_conv_form(
            key.as_ptr(),
            openssl_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
        );
    }
    let cert = certificate(&default_name(), vec![], &PKey::from_ec_key(key).unwrap());
    assert!(Crypto::public_key_components(&cert).is_err());
}

#[test]
fn resolution_preserves_zero_padding_without_testing_curve_membership() {
    let key = signing_key();
    let ec = key.ec_key().unwrap();
    let point = ec
        .public_key()
        .to_bytes(
            ec.group(),
            PointConversionForm::UNCOMPRESSED,
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap();
    let cert = certificate(&default_name(), vec![], &key);
    let mut der = cert.to_der().unwrap();
    let mut zero_point = vec![0; 65];
    zero_point[0] = 4;
    replace(&mut der, &point, &zero_point, false);
    let cert = Crypto::from_der(&der).unwrap();
    assert_eq!(
        Crypto::public_key_components(&cert).unwrap(),
        PublicKey::Ec {
            curve: "P-256",
            x: vec![0; 32],
            y: vec![0; 32]
        }
    );
    replace(&mut der, b"\x03\x42\x00\x04", b"\x03\x42\x01\x04", false);
    let cert = Crypto::from_der(&der).unwrap();
    assert!(Crypto::public_key_components(&cert).is_err());
}

#[test]
fn rejects_unsorted_rdn_without_changing_shared_der() {
    let subject = name(&[
        ("CN", openssl_sys::V_ASN1_UTF8STRING, b"aa", false),
        ("OU", openssl_sys::V_ASN1_UTF8STRING, b"bb", true),
    ]);
    let cert = certificate(&subject, vec![], &signing_key());
    let mut der = cert.to_der().unwrap();
    replace(
        &mut der,
        b"\x30\x09\x06\x03\x55\x04\x03\x0c\x02aa\x30\x09\x06\x03\x55\x04\x0b\x0c\x02bb",
        b"\x30\x09\x06\x03\x55\x04\x0b\x0c\x02bb\x30\x09\x06\x03\x55\x04\x03\x0c\x02aa",
        false,
    );
    let cert = Crypto::from_der(&der).unwrap();
    let shared = cert.clone();
    assert!(Crypto::certificate_details(&cert).is_err());
    assert_eq!(shared.to_der().unwrap(), der);
}

#[test]
fn accepts_edi_directory_strings_but_rejects_invalid_ones() {
    for bytes in [
        b"\x30\x07\xa5\x05\xa1\x03\x0c\x01a".as_slice(),
        b"\x30\x07\xa5\x05\xa1\x03\x13\x01a",
        b"\x30\x07\xa5\x05\xa1\x03\x14\x01a",
        b"\x30\x08\xa5\x06\xa1\x04\x1e\x02\x00a",
    ] {
        assert_eq!(
            Crypto::certificate_details(&with_extension("2.5.29.17", bytes))
                .unwrap()
                .subject_alt_names,
            Some(vec![SubjectAlternativeName::Other])
        );
    }
    for bytes in [
        b"\x30\x07\xa5\x05\xa1\x03\x0c\x01\xff".as_slice(),
        b"\x30\x07\xa5\x05\xa1\x03\x13\x01@",
        b"\x30\x07\xa5\x05\xa1\x03\x14\x01\xff",
        b"\x30\x07\xa5\x05\xa1\x03\x16\x01a",
        b"\x30\x08\xa5\x06\xa1\x04\x1e\x02\xff\xff",
    ] {
        assert!(
            Crypto::certificate_details(&with_extension("2.5.29.17", bytes)).is_err(),
            "{bytes:x?}"
        );
    }
}

#[test]
fn empty_rdn_groups_are_an_explicit_native_api_limitation() {
    let subject = X509Name::from_der(b"\x30\x02\x31\x00").unwrap();
    let cert = certificate(&subject, vec![], &signing_key());
    let error = Crypto::certificate_details(&cert).unwrap_err().to_string();
    assert!(error.contains("unsupported empty RDN"), "{error}");
    let cert = certificate(
        &X509Name::builder().unwrap().build(),
        vec![],
        &signing_key(),
    );
    assert!(Crypto::certificate_details(&cert)
        .unwrap()
        .subject
        .is_empty());
}

#[test]
fn rsa_requires_positive_components_not_mathematical_validity() {
    for (n, e, valid) in [(1, 1, true), (0, 3, false), (3, 0, false)] {
        let n = BigNum::from_u32(n).unwrap();
        let key =
            PKey::from_rsa(Rsa::from_public_components(n, BigNum::from_u32(e).unwrap()).unwrap())
                .unwrap();
        let cert = certificate(&default_name(), vec![], &key);
        assert_eq!(Crypto::public_key_components(&cert).is_ok(), valid);
    }
}

#[test]
fn rejects_negative_rsa_integers_and_invalid_parameters() {
    let key = PKey::from_rsa(
        Rsa::from_public_components(BigNum::from_u32(3).unwrap(), BigNum::from_u32(3).unwrap())
            .unwrap(),
    )
    .unwrap();
    let original = certificate(&default_name(), vec![], &key).to_der().unwrap();
    for invalid in [
        b"\x30\x06\x02\x01\xff\x02\x01\x03".as_slice(),
        b"\x30\x06\x02\x01\x03\x02\x01\xff",
    ] {
        let mut der = original.clone();
        replace(
            &mut der,
            b"\x30\x06\x02\x01\x03\x02\x01\x03",
            invalid,
            false,
        );
        let cert = Crypto::from_der(&der).unwrap();
        assert!(Crypto::public_key_components(&cert).is_err());
    }
    let mut der = original;
    replace(
        &mut der,
        b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00",
        b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x30\x00",
        false,
    );
    assert!(Crypto::public_key_components(&Crypto::from_der(&der).unwrap()).is_err());
}

#[test]
fn oid_strings_are_numeric_and_preserve_supported_representation_limits() {
    let longest = format!("1.2{}", ".1".repeat(38));
    let cert = certificate(
        &name(&[(&longest, openssl_sys::V_ASN1_UTF8STRING, b"custom", false)]),
        vec![],
        &signing_key(),
    );
    assert_eq!(
        Crypto::certificate_details(&cert).unwrap().subject[0][0].oid,
        longest
    );
    for oid in [
        format!("{longest}.1"),
        "1.2.4294967296".into(),
        "2.40.1".into(),
    ] {
        let cert = certificate(
            &name(&[(&oid, openssl_sys::V_ASN1_UTF8STRING, b"custom", false)]),
            vec![],
            &signing_key(),
        );
        assert!(Crypto::certificate_details(&cert).is_err(), "{oid}");
    }
}

#[test]
fn preserves_legacy_time_and_serial_encoding_bounds() {
    for (time, valid) in [
        ("19690101000000Z", false),
        ("19700101000000Z", true),
        ("20490101000000Z", true),
        ("20500101000000Z", true),
        ("20250101000000+0000", false),
        ("202501010000Z", false),
        ("20250230000000Z", false),
    ] {
        let cert = certificate(&default_name(), vec![], &signing_key());
        let time_value = Asn1Time::from_str("20250101000000Z").unwrap();
        // SAFETY: the uniquely owned ASN1_TIME is an ASN1_STRING. Set raw
        // content here to exercise encodings rejected by the typed constructor.
        assert_eq!(
            unsafe {
                openssl_sys::ASN1_STRING_set(
                    time_value.as_ptr().cast(),
                    time.as_ptr().cast(),
                    time.len().try_into().unwrap(),
                )
            },
            1
        );
        // SAFETY: cert is uniquely owned and the setter copies time_value.
        assert_eq!(
            unsafe { openssl_sys::X509_set1_notBefore(cert.as_ptr(), time_value.as_ptr()) },
            1
        );
        assert_eq!(Crypto::certificate_details(&cert).is_ok(), valid, "{time}");
    }
    for (length, valid) in [(21, true), (22, false)] {
        let cert = certificate(&default_name(), vec![], &signing_key());
        let serial = BigNum::from_slice(&vec![0x7f; length])
            .unwrap()
            .to_asn1_integer()
            .unwrap();
        // SAFETY: cert is uniquely owned and the setter copies serial.
        assert_eq!(
            unsafe { openssl_sys::X509_set_serialNumber(cert.as_ptr(), serial.as_ptr()) },
            1
        );
        assert_eq!(Crypto::certificate_details(&cert).is_ok(), valid);
    }
}

#[test]
fn decodes_existing_public_certificate_without_altering_der() {
    let cert = Crypto::from_pem(include_bytes!("../src/test_data/milan_ark.pem")).unwrap();
    let der = Crypto::to_der(&cert).unwrap();
    let shared = cert.clone();
    assert!(!Crypto::certificate_details(&cert)
        .unwrap()
        .subject
        .is_empty());
    assert!(matches!(
        Crypto::public_key_components(&cert).unwrap(),
        PublicKey::Rsa { .. }
    ));
    assert_eq!(Crypto::to_der(&shared).unwrap(), der);
}

#[test]
fn regression_rejects_noncanonical_critical_booleans_without_mutating_shared_der() {
    let cert = Crypto::from_pem(include_bytes!("../src/test_data/milan_ark.pem")).unwrap();
    let original = Crypto::to_der(&cert).unwrap();
    let mut accepted = Vec::new();
    for extension_oid in [0x0f, 0x13] {
        for boolean in [0x01, 0x7f] {
            let mut der = original.clone();
            replace(
                &mut der,
                &[0x06, 0x03, 0x55, 0x1d, extension_oid, 0x01, 0x01, 0xff],
                &[0x06, 0x03, 0x55, 0x1d, extension_oid, 0x01, 0x01, boolean],
                false,
            );
            let cert = Crypto::from_der(&der).unwrap();
            let shared = cert.clone();
            if Crypto::certificate_details(&cert).is_ok() {
                accepted.push((extension_oid, boolean));
            }
            assert_eq!(Crypto::to_der(&cert).unwrap(), der);
            assert_eq!(Crypto::to_der(&shared).unwrap(), der);
        }
    }
    assert!(
        accepted.is_empty(),
        "Accepted noncanonical critical flags: {accepted:x?}"
    );
}

#[test]
fn regression_key_usage_rejects_malformed_der_without_mutating_shared_der() {
    let mut accepted = Vec::new();
    for payload in [
        b"\x03\x02\x07\x80\x00".as_slice(),
        b"\x05\x00",
        b"\x03\x02\x07\x81",
        b"\x03\x81\x02\x07\x80",
        b"\x03\x01\x07",
        b"\x03\x02\x08\x80",
        b"\x03\x00",
        b"",
    ] {
        let cert = with_extension("2.5.29.15", payload);
        let der = Crypto::to_der(&cert).unwrap();
        let shared = cert.clone();
        if Crypto::key_usage(&cert).is_ok() {
            accepted.push(payload);
        }
        assert_eq!(Crypto::to_der(&cert).unwrap(), der);
        assert_eq!(Crypto::to_der(&shared).unwrap(), der);
    }
    assert!(
        accepted.is_empty(),
        "Accepted malformed KeyUsage: {accepted:x?}"
    );
}

#[test]
fn key_usage_distinguishes_absence_empty_and_individual_bits() {
    let cert = certificate(&default_name(), vec![], &signing_key());
    assert_eq!(Crypto::key_usage(&cert).unwrap(), None);
    for (payload, digital_signature, key_agreement, key_cert_sign) in [
        (b"\x03\x01\x00".as_slice(), false, false, false),
        (b"\x03\x02\x07\x80", true, false, false),
        (b"\x03\x02\x03\x08", false, true, false),
        (b"\x03\x02\x02\x04", false, false, true),
    ] {
        let cert = with_extension("2.5.29.15", payload);
        let usage = Crypto::key_usage(&cert).unwrap().unwrap();
        assert_eq!(usage.digital_signature, digital_signature);
        assert_eq!(usage.key_agreement, key_agreement);
        assert_eq!(usage.key_cert_sign, key_cert_sign);
    }
}

#[test]
fn regression_key_extraction_does_not_validate_unrelated_certificate_structure() {
    let key = signing_key();
    let cert = certificate(&default_name(), vec![], &key);
    let expected = Crypto::public_key_components(&cert).unwrap();
    let mut der = Crypto::to_der(&cert).unwrap();
    replace(
        &mut der,
        b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
        b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03",
        true,
    );
    let mismatched_algorithm = Crypto::from_der(&der).unwrap();
    let empty_rdn = certificate(
        &X509Name::from_der(b"\x30\x02\x31\x00").unwrap(),
        vec![],
        &key,
    );
    for cert in [mismatched_algorithm, empty_rdn] {
        let der = Crypto::to_der(&cert).unwrap();
        assert!(Crypto::certificate_details(&cert).is_err());
        assert_eq!(Crypto::public_key_components(&cert).unwrap(), expected);
        assert_eq!(Crypto::to_der(&cert).unwrap(), der);
    }
}
