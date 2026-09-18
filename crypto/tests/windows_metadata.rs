// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(feature = "x509", crypto_backend = "crypto_windows"))]

use std::ffi::CString;
use tee_attestation_verification_crypto::{
    x509::{PublicKey, SubjectAlternativeName},
    CertificateBackend, Crypto,
};
use windows::{
    core::{PCSTR, PSTR},
    Win32::Security::Cryptography as Native,
};

type Certificate = <Crypto as CertificateBackend>::Certificate;

// These fixtures have public-key bytes and a dummy signature, never private
// keys. They exercise metadata decoding, not certificate trust.
fn encode<T>(kind: PCSTR, value: &T) -> Vec<u8> {
    let mut length = 0;
    unsafe {
        Native::CryptEncodeObjectEx(
            Native::X509_ASN_ENCODING,
            kind,
            (value as *const T).cast(),
            Default::default(),
            None,
            None,
            &mut length,
        )
        .unwrap();
    }
    let mut output = vec![0; length as usize];
    unsafe {
        Native::CryptEncodeObjectEx(
            Native::X509_ASN_ENCODING,
            kind,
            (value as *const T).cast(),
            Default::default(),
            None,
            Some(output.as_mut_ptr().cast()),
            &mut length,
        )
        .unwrap();
    }
    output.truncate(length as usize);
    output
}

fn sequence(fields: &[&[u8]]) -> Vec<u8> {
    let mut fields: Vec<_> = fields
        .iter()
        .map(|field| Native::CRYPT_INTEGER_BLOB {
            cbData: field.len().try_into().unwrap(),
            pbData: field.as_ptr().cast_mut(),
        })
        .collect();
    encode(
        Native::X509_SEQUENCE_OF_ANY,
        &Native::CRYPT_SEQUENCE_OF_ANY {
            cValue: fields.len().try_into().unwrap(),
            rgValue: fields.as_mut_ptr(),
        },
    )
}

fn tagged_sequence(tag: u8, fields: &[&[u8]]) -> Vec<u8> {
    let mut encoded = sequence(fields);
    encoded[0] = tag;
    encoded
}

fn oid(value: &str) -> Vec<u8> {
    let value = CString::new(value).unwrap();
    encode(
        Native::X509_OBJECT_IDENTIFIER,
        &PSTR(value.as_ptr().cast_mut().cast()),
    )
}

fn octets(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut encoded = encode(
        Native::X509_OCTET_STRING,
        &Native::CRYPT_INTEGER_BLOB {
            cbData: bytes.len().try_into().unwrap(),
            pbData: bytes.as_ptr().cast_mut(),
        },
    );
    encoded[0] = tag;
    encoded
}

fn attribute(id: &str, tag: u8, bytes: &[u8]) -> Vec<u8> {
    sequence(&[&oid(id), &octets(tag, bytes)])
}

fn rdn(attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut attributes = attributes.to_vec();
    attributes.sort();
    tagged_sequence(
        0x31,
        &attributes.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )
}

fn subject() -> Vec<u8> {
    sequence(&[&rdn(&[attribute("2.5.4.3", 0x0c, b"metadata")])])
}

fn ec_spki(parameters: &[u8], point: &[u8], unused: u32) -> Vec<u8> {
    sequence(&[
        &sequence(&[&oid("1.2.840.10045.2.1"), parameters]),
        &encode(
            Native::X509_BITS,
            &Native::CRYPT_BIT_BLOB {
                cbData: point.len().try_into().unwrap(),
                pbData: point.as_ptr().cast_mut(),
                cUnusedBits: unused,
            },
        ),
    ])
}

fn default_spki() -> Vec<u8> {
    let mut point = vec![0; 65];
    point[0] = 4;
    ec_spki(&oid("1.2.840.10045.3.1.7"), &point, 0)
}

fn rsa_spki(n: &[u8], e: &[u8], parameters: &[u8]) -> Vec<u8> {
    let id = oid("1.2.840.113549.1.1.1");
    let algorithm = if parameters.is_empty() {
        sequence(&[&id])
    } else {
        sequence(&[&id, parameters])
    };
    let key = sequence(&[&octets(0x02, n), &octets(0x02, e)]);
    sequence(&[
        &algorithm,
        &encode(
            Native::X509_BITS,
            &Native::CRYPT_BIT_BLOB {
                cbData: key.len().try_into().unwrap(),
                pbData: key.as_ptr().cast_mut(),
                cUnusedBits: 0,
            },
        ),
    ])
}

fn certificate_der(
    subject: &[u8],
    extensions: &[(&str, &[u8])],
    spki: &[u8],
    validity: &[u8],
) -> Vec<u8> {
    let algorithm = sequence(&[&oid("1.2.840.10045.4.3.2")]);
    let issuer = self::subject();
    let extension_values: Vec<_> = extensions
        .iter()
        .map(|(id, value)| sequence(&[&oid(id), &octets(0x04, value)]))
        .collect();
    let extensions_der = tagged_sequence(
        0xa3,
        &[&sequence(
            &extension_values
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
        )],
    );
    let mut fields = vec![
        b"\xa0\x03\x02\x01\x02".as_slice(),
        b"\x02\x01\x01",
        &algorithm,
        &issuer,
        validity,
        subject,
        spki,
    ];
    if !extensions.is_empty() {
        fields.push(&extensions_der);
    }
    sequence(&[&sequence(&fields), &algorithm, b"\x03\x02\x00\x00"])
}

fn fixture(subject: &[u8], extensions: &[(&str, &[u8])], spki: &[u8]) -> Certificate {
    let validity = sequence(&[b"\x18\x0f20250101000000Z", b"\x18\x0f20300101000000Z"]);
    Crypto::from_der(&certificate_der(subject, extensions, spki, &validity)).unwrap()
}

fn extension(id: &str, value: &[u8]) -> Certificate {
    fixture(&subject(), &[(id, value)], &default_spki())
}

fn replace(der: &mut [u8], old: &[u8], new: &[u8], last: bool) {
    assert_eq!(old.len(), new.len());
    let indices: Vec<_> = der
        .windows(old.len())
        .enumerate()
        .filter_map(|(index, value)| (value == old).then_some(index))
        .collect();
    let index = if last {
        indices.last()
    } else {
        indices.first()
    }
    .unwrap();
    der[*index..*index + old.len()].copy_from_slice(new);
}

#[test]
fn preserves_rdn_groups_duplicates_empty_groups_and_string_bytes() {
    let name = sequence(&[
        &rdn(&[
            attribute("2.5.4.3", 0x0c, b"caf\xc3\xa9\0suffix"),
            attribute("2.5.4.11", 0x13, b"unit"),
        ]),
        &rdn(&[attribute("2.5.4.3", 0x1e, b"\0s\0e\0c\0o\0n\0d")]),
        &rdn(&[]),
        &rdn(&[attribute("1.2.3.4", 0x14, b"custom\0value")]),
        &rdn(&[attribute("1.2.3.5", 0x16, b"a\0b")]),
    ]);
    let cert = fixture(&name, &[], &default_spki());
    let details = Crypto::certificate_details(&cert).unwrap();
    assert_eq!(
        details.subject.iter().map(Vec::len).collect::<Vec<_>>(),
        [2, 1, 0, 1, 1]
    );
    assert!(details.subject[0]
        .iter()
        .any(|a| a.oid == "2.5.4.3" && a.value == "caf\u{e9}\0suffix"));
    assert_eq!(details.subject[1][0].value, "second");
    assert_eq!(details.subject[3][0].value, "custom\0value");
    assert_eq!(details.subject[4][0].value, "a\0b");
}

#[test]
fn rejects_invalid_subject_encodings_and_unsorted_rdns() {
    for (tag, bytes) in [
        (0x0c, b"\xc0\x80".as_slice()),
        (0x13, b"@"),
        (0x16, b"\xff"),
        (0x14, b"\xe9"),
        (0x1e, b"\xd8\x00"),
        (0x1e, b"\xff\xff"),
        (0x1e, b"\0"),
        (0x1c, b"\0\0\0a"),
    ] {
        let name = sequence(&[&rdn(&[attribute("2.5.4.3", tag, bytes)])]);
        let result = Crypto::certificate_details(&fixture(&name, &[], &default_spki()));
        assert!(result.is_err(), "{tag:x}: {bytes:x?}");
    }
    let mut attributes = vec![
        attribute("2.5.4.3", 0x0c, b"aa"),
        attribute("2.5.4.11", 0x0c, b"bb"),
    ];
    attributes.sort();
    attributes.reverse();
    let name = sequence(&[&tagged_sequence(0x31, &[&attributes[0], &attributes[1]])]);
    assert!(Crypto::certificate_details(&fixture(&name, &[], &default_spki())).is_err());
}

#[test]
fn distinguishes_absent_empty_and_repeated_extensions() {
    let details = Crypto::certificate_details(&fixture(&subject(), &[], &default_spki())).unwrap();
    assert_eq!(details.subject_alt_names, None);
    assert_eq!(details.extended_key_usage, None);
    let cert = fixture(
        &subject(),
        &[("2.5.29.17", b"\x30\x00"), ("2.5.29.37", b"\x30\x00")],
        &default_spki(),
    );
    let details = Crypto::certificate_details(&cert).unwrap();
    assert_eq!(details.subject_alt_names, Some(vec![]));
    assert_eq!(details.extended_key_usage, Some(vec![]));
    let cert = extension(
        "2.5.29.37",
        &sequence(&[&oid("1.2.3"), &oid("1.2.3"), &oid("1.2.4")]),
    );
    assert_eq!(
        Crypto::certificate_details(&cert)
            .unwrap()
            .extended_key_usage
            .unwrap(),
        ["1.2.3", "1.2.3", "1.2.4"]
    );
    let cert = fixture(
        &subject(),
        &[("1.2.3.4", b"\x05\x00"), ("1.2.3.4", b"\x05\x00")],
        &default_spki(),
    );
    assert!(Crypto::certificate_details(&cert).is_err());
}

#[test]
fn preserves_san_nuls_and_accepts_non_predicate_names() {
    let san = sequence(&[
        &octets(0x81, b"a\0b"),
        &octets(0x82, b"dn\0s"),
        &octets(0x86, b"uri\0suffix"),
        &octets(0x87, &[127, 0, 0, 1]),
        &tagged_sequence(0xa4, &[&subject()]),
        &tagged_sequence(
            0xa0,
            &[&oid("1.2.3"), &tagged_sequence(0xa0, &[b"\x05\x00"])],
        ),
        b"\x88\x02\x2a\x03",
        &tagged_sequence(0xa5, &[&tagged_sequence(0xa1, &[b"\x0c\x01a"])]),
    ]);
    assert_eq!(
        Crypto::certificate_details(&extension("2.5.29.17", &san))
            .unwrap()
            .subject_alt_names
            .unwrap(),
        [
            SubjectAlternativeName::Email("a\0b".into()),
            SubjectAlternativeName::Dns("dn\0s".into()),
            SubjectAlternativeName::Uri("uri\0suffix".into()),
            SubjectAlternativeName::Other,
            SubjectAlternativeName::Other,
            SubjectAlternativeName::Other,
            SubjectAlternativeName::Other,
            SubjectAlternativeName::Other,
        ]
    );
}

#[test]
fn rejects_malformed_san_eku_and_edi_directory_strings() {
    for id in ["2.5.29.17", "2.5.29.37"] {
        for bytes in [
            b"\x30\x00\0".as_slice(),
            b"\x30\x81\x00",
            b"\x30\x80\0\0",
            b"\x05\x00",
        ] {
            assert!(
                Crypto::certificate_details(&extension(id, bytes)).is_err(),
                "{id}: {bytes:x?}"
            );
        }
    }
    for bytes in [
        b"\x30\x03\x82\x01\xff".as_slice(),
        b"\x30\x02\xa3\x00",
        b"\x30\x02\x89\x00",
        b"\x30\x07\xa5\x05\xa1\x03\x16\x01a",
        b"\x30\x07\xa5\x05\xa1\x03\x13\x01@",
        b"\x30\x07\xa5\x05\xa1\x03\x0c\x01\xff",
        b"\x30\x02\xa5\x00",
    ] {
        assert!(
            Crypto::certificate_details(&extension("2.5.29.17", bytes)).is_err(),
            "{bytes:x?}"
        );
    }
    assert!(Crypto::certificate_details(&extension("2.5.29.37", b"\x30\x03\x06\x01\x80")).is_err());
}

#[test]
fn time_encoding_is_preserved_but_noncanonical_or_invalid_times_are_rejected() {
    for (not_before, valid) in [
        (b"\x17\x0d250101000000Z".as_slice(), true),
        (b"\x18\x0f20250101000000Z", true),
        (b"\x18\x0f20500101000000Z", true),
        (b"\x18\x0f19690101000000Z", false),
        (b"\x18\x0f20250230000000Z", false),
        (b"\x18\x0d202501010000Z", false),
        (b"\x18\x1320250101000000+0000", false),
    ] {
        let der = certificate_der(
            &subject(),
            &[],
            &default_spki(),
            &sequence(&[not_before, b"\x18\x0f20510101000000Z"]),
        );
        let result = Crypto::from_der(&der).and_then(|cert| Crypto::certificate_details(&cert));
        assert_eq!(result.is_ok(), valid, "{not_before:x?}");
    }
}

#[test]
fn rejects_trailing_bytes_default_version_and_algorithm_disagreement_without_mutation() {
    let cert = fixture(&subject(), &[], &default_spki());
    let original = Crypto::to_der(&cert).unwrap();
    let mut trailing = original.clone();
    trailing.push(0);
    let result = Crypto::from_der(&trailing).and_then(|cert| Crypto::certificate_details(&cert));
    assert!(result.is_err());
    let expected_key = Crypto::public_key_components(&cert).unwrap();
    for algorithm_mismatch in [false, true] {
        let mut der = original.clone();
        if algorithm_mismatch {
            replace(
                &mut der,
                b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
                b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03",
                true,
            );
        } else {
            replace(
                &mut der,
                b"\xa0\x03\x02\x01\x02",
                b"\xa0\x03\x02\x01\x00",
                false,
            );
        }
        let cert = Crypto::from_der(&der).unwrap();
        let shared = cert.clone();
        assert!(Crypto::certificate_details(&cert).is_err());
        assert_eq!(Crypto::public_key_components(&cert).unwrap(), expected_key);
        assert_eq!(Crypto::to_der(&shared).unwrap(), der);
    }
}

#[test]
fn key_usage_distinguishes_absence_empty_and_individual_bits() {
    assert_eq!(
        Crypto::key_usage(&fixture(&subject(), &[], &default_spki())).unwrap(),
        None
    );
    for (bytes, digital_signature, key_agreement, key_cert_sign) in [
        (b"\x03\x01\x00".as_slice(), false, false, false),
        (b"\x03\x02\x07\x80", true, false, false),
        (b"\x03\x02\x03\x08", false, true, false),
        (b"\x03\x02\x02\x04", false, false, true),
    ] {
        let usage = Crypto::key_usage(&extension("2.5.29.15", bytes))
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                usage.digital_signature,
                usage.key_agreement,
                usage.key_cert_sign
            ),
            (digital_signature, key_agreement, key_cert_sign)
        );
    }
}

#[test]
fn malformed_key_usage_is_an_error_not_absence() {
    for bytes in [
        b"\x03\x02\x07\x80\0".as_slice(),
        b"\x05\x00",
        b"\x03\x02\x07\x81",
        b"\x03\x81\x02\x07\x80",
        b"\x03\x01\x07",
        b"\x03\x02\x08\x80",
        b"\x03\x00",
        b"",
    ] {
        let cert = extension("2.5.29.15", bytes);
        let der = Crypto::to_der(&cert).unwrap();
        assert!(Crypto::key_usage(&cert).is_err(), "{bytes:x?}");
        assert_eq!(Crypto::to_der(&cert).unwrap(), der);
    }
    let duplicate = fixture(
        &subject(),
        &[
            ("2.5.29.15", b"\x03\x02\x07\x80"),
            ("2.5.29.15", b"\x03\x02\x02\x04"),
        ],
        &default_spki(),
    );
    assert!(Crypto::key_usage(&duplicate).is_err());
}

#[test]
fn opaque_other_name_values_reject_invalid_universal_tags() {
    for value in [b"\x00\x00".as_slice(), b"\x21\x00", b"\x10\x00"] {
        let san = sequence(&[&tagged_sequence(
            0xa0,
            &[&oid("1.2.3"), &tagged_sequence(0xa0, &[value])],
        )]);
        assert!(Crypto::certificate_details(&extension("2.5.29.17", &san)).is_err());
    }
}

#[test]
fn opaque_multi_octet_tags_are_an_explicit_native_adapter_limitation() {
    let san = sequence(&[&tagged_sequence(
        0xa0,
        &[&oid("1.2.3"), &tagged_sequence(0xa0, &[b"\x9f\x1f\x00"])],
    )]);
    assert!(Crypto::certificate_details(&extension("2.5.29.17", &san)).is_err());
}

#[test]
fn rsa_components_have_no_strength_or_u32_exponent_limit() {
    for (n, e) in [
        (b"\x01".as_slice(), b"\x01".as_slice()),
        (b"\x00\x80", b"\x01\x00\x00\x00\x01"),
        (b"\x01\x02\x03", b"\x01\x00\x00\x00\x00\x00\x00\x00\x01"),
    ] {
        for parameters in [b"\x05\x00".as_slice(), b""] {
            let cert = fixture(&subject(), &[], &rsa_spki(n, e, parameters));
            let n = n.strip_prefix(&[0]).unwrap_or(n);
            assert_eq!(
                Crypto::public_key_components(&cert).unwrap(),
                PublicKey::Rsa {
                    n: n.to_vec(),
                    e: e.to_vec()
                }
            );
        }
    }
}

#[test]
fn rsa_rejects_negative_zero_nonminimal_integers_and_invalid_parameters() {
    for (n, e, parameters) in [
        (
            b"\xff".as_slice(),
            b"\x03".as_slice(),
            b"\x05\x00".as_slice(),
        ),
        (b"\x03", b"\xff", b"\x05\x00"),
        (b"\x00", b"\x03", b"\x05\x00"),
        (b"\x03", b"\x00", b"\x05\x00"),
        (b"\x00\x03", b"\x03", b"\x05\x00"),
        (b"\x03", b"\x03", b"\x30\x00"),
    ] {
        assert!(Crypto::public_key_components(&fixture(
            &subject(),
            &[],
            &rsa_spki(n, e, parameters)
        ))
        .is_err());
    }
}

#[test]
fn ec_preserves_coordinate_width_without_point_validation() {
    for (id, curve, width) in [
        ("1.2.840.10045.3.1.7", "P-256", 32),
        ("1.3.132.0.34", "P-384", 48),
        ("1.3.132.0.35", "P-521", 66),
    ] {
        let mut point = vec![0; 1 + 2 * width];
        point[0] = 4;
        let cert = fixture(&subject(), &[], &ec_spki(&oid(id), &point, 0));
        assert_eq!(
            Crypto::public_key_components(&cert).unwrap(),
            PublicKey::Ec {
                curve,
                x: vec![0; width],
                y: vec![0; width]
            }
        );
    }
}

const P256_GENERATOR: &[u8; 65] = b"\x04\
    \x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\
    \x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96\
    \x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\
    \x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5";

#[test]
fn ec_rejects_valid_compressed_points_and_explicit_parameters() {
    let named = oid("1.2.840.10045.3.1.7");
    let cert = fixture(&subject(), &[], &ec_spki(&named, P256_GENERATOR, 0));
    assert_eq!(
        Crypto::public_key_components(&cert).unwrap(),
        PublicKey::Ec {
            curve: "P-256",
            x: P256_GENERATOR[1..33].to_vec(),
            y: P256_GENERATOR[33..].to_vec(),
        }
    );

    // The P-256 generator has odd y, so its compressed SEC1 prefix is 03.
    let mut compressed = vec![3];
    compressed.extend_from_slice(&P256_GENERATOR[1..33]);
    assert_eq!(compressed.len(), 33);
    let cert = fixture(&subject(), &[], &ec_spki(&named, &compressed, 0));
    let error = Crypto::public_key_components(&cert)
        .unwrap_err()
        .to_string();
    assert!(error.contains("uncompressed EC public key"), "{error}");

    // From the repository root, regenerate public parameters without a key:
    // openssl ecparam -provider default -propquery provider=default -name prime256v1 \
    //   -param_enc explicit -outform DER \
    //   -out crypto/tests/fixtures/windows-metadata/p256-explicit.der
    let explicit = include_bytes!("fixtures/windows-metadata/p256-explicit.der");
    let cert = fixture(&subject(), &[], &ec_spki(explicit, P256_GENERATOR, 0));
    assert!(Crypto::public_key_components(&cert).is_err());
}

#[test]
fn ec_rejects_malformed_points_parameters_and_unused_bits() {
    let named = oid("1.2.840.10045.3.1.7");
    for (prefix, unused) in [(2, 0), (4, 1)] {
        let mut point = vec![0; 65];
        point[0] = prefix;
        let cert = fixture(&subject(), &[], &ec_spki(&named, &point, unused));
        assert!(Crypto::public_key_components(&cert).is_err());
    }
    let mut explicit = default_spki();
    replace(
        &mut explicit,
        b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        b"\x30\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        false,
    );
    assert!(Crypto::public_key_components(&fixture(&subject(), &[], &explicit)).is_err());
}

#[test]
fn existing_public_certificate_decodes_without_altering_der() {
    let cert = Crypto::from_pem(include_bytes!("../src/test_data/milan_ark.pem")).unwrap();
    let original = Crypto::to_der(&cert).unwrap();
    assert!(!Crypto::certificate_details(&cert)
        .unwrap()
        .subject
        .is_empty());
    assert!(matches!(
        Crypto::public_key_components(&cert).unwrap(),
        PublicKey::Rsa { .. }
    ));
    assert_eq!(Crypto::to_der(&cert).unwrap(), original);
    for boolean in [0x01, 0x7f] {
        let mut der = original.clone();
        replace(
            &mut der,
            b"\x06\x03\x55\x1d\x0f\x01\x01\xff",
            &[6, 3, 0x55, 0x1d, 0x0f, 1, 1, boolean],
            false,
        );
        let cert = Crypto::from_der(&der).unwrap();
        assert!(Crypto::certificate_details(&cert).is_err());
        assert_eq!(Crypto::to_der(&cert).unwrap(), der);
    }
}
