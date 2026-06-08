#![allow(dead_code)]

use std::time::Duration;

use super::CertificateBackend;

/// Policy evaluation.
///
/// After evaluating that the certificate path signatures match, we need to evaluate policies against that.
///
/// Policies evaluate a borrowed certificate path and return typed errors for validation failures.
/// Within that I can see two useful primitives: windowing and folding.
///
/// Windowing allows us to evaluate a predicate over a sliding window of certificates.
/// e.g. we might want to check that the issuer and subject of adjacent certificate match
/// This should be controlled by a window size parameter, and for a window size of 3 over [A, B, C] we expect to see [None, None, A], [None, A, B], [A, B, C], [B, C, None], [C, None, None].
///
/// Folding works similarly but it also has an accumulator
/// Windowing is a special case of folding where the accumulator is ignored.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BasicConstraints {
    critical: bool,
    ca: bool,
    path_len_constraint: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeyUsage {
    key_cert_sign: bool,
}

pub(crate) fn fold_policy<'a, Certificate, Accumulator, Error, const WINDOW_SIZE: usize>(
    path: &[&'a Certificate],
    initial_accumulator: Accumulator,
    predicate: impl Fn(
        [Option<&'a Certificate>; WINDOW_SIZE],
        Accumulator,
    ) -> std::result::Result<Accumulator, Error>,
) -> std::result::Result<Accumulator, Error> {
    assert!(WINDOW_SIZE > 0, "window size must be non-zero");

    let mut accumulator = initial_accumulator;

    for window_index in 0..path.len() + WINDOW_SIZE - 1 {
        let window = std::array::from_fn(|offset| {
            (window_index + offset)
                .checked_sub(WINDOW_SIZE - 1)
                .and_then(|path_index| path.get(path_index).copied())
        });

        accumulator = predicate(window, accumulator)?;
    }

    Ok(accumulator)
}

#[allow(dead_code)]
pub(crate) fn window_policy<'a, Certificate, Error, const WINDOW_SIZE: usize>(
    path: &[&'a Certificate],
    predicate: impl Fn([Option<&'a Certificate>; WINDOW_SIZE]) -> std::result::Result<(), Error>,
) -> std::result::Result<(), Error> {
    fold_policy(path, (), |window, ()| predicate(window))
}

pub(crate) fn window_policy_1<'a, Certificate, Error>(
    path: &[&'a Certificate],
    predicate: impl Fn([Option<&'a Certificate>; 1]) -> std::result::Result<(), Error>,
) -> std::result::Result<(), Error> {
    window_policy::<_, Error, 1>(path, predicate)
}

pub(crate) fn rfc5280_policy<Backend: CertificateBackend>(
    path: &[&Backend::Certificate],
    unix_time: Duration,
) -> super::Result<()> {
    if path.is_empty() {
        return Err("Certificate path must not be empty".into());
    }

    // Subject and issuer name constraints
    window_policy::<_, Box<dyn std::error::Error>, 2>(path, |window| match window {
        [None, Some(cert)] => {
            if !Backend::is_self_issued(cert)? {
                return Err(format!(
                    "First certificate {} is not self-issued",
                    Backend::subject_name(cert)
                )
                .into());
            }

            Ok(())
        }
        [Some(issuer), Some(subject)] => {
            if !Backend::issuer_name_matches_subject(subject, issuer)? {
                return Err(format!(
                    "Issuer name {} does not match issuing certificate subject name {}",
                    Backend::issuer_name(subject),
                    Backend::subject_name(issuer)
                )
                .into());
            }

            Ok(())
        }
        [Some(_), None] => Ok(()),
        [None, None] => Err("Certificate path must not be empty".into()),
    })?;

    // Validity
    window_policy_1::<_, Box<dyn std::error::Error>>(path, |window| {
        let cert = window[0].unwrap();
        let cert_subject = Backend::subject_name(cert);
        if !Backend::is_valid_at(cert, unix_time)? {
            return Err(format!(
                "Certificate {} is not valid at the given time",
                cert_subject
            )
            .into());
        }
        assert_skipped_extension_not_present::<Backend>(cert, oid::CERTIFICATE_POLICIES)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::POLICY_MAPPINGS)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::NAME_CONSTRAINTS)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::POLICY_CONSTRAINTS)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::INHIBIT_ANY_POLICY)?;
        assert_no_unhandled_critical_extensions::<Backend>(cert)?;
        Ok(())
    })?;

    // CA constraints
    window_policy::<_, Box<dyn std::error::Error>, 2>(path, |window| match window {
        [Some(cert), Some(_)] => {
            if Backend::version(cert)? != 2 {
                return Err(format!(
                    "Issuer certificate {} must be a v3 certificate",
                    Backend::subject_name(cert)
                )
                .into());
            }

            let basic_constraints = basic_constraints::<Backend>(cert)?.ok_or_else(|| {
                format!(
                    "Issuer certificate {} is missing basicConstraints",
                    Backend::subject_name(cert)
                )
            })?;
            if !basic_constraints.critical {
                return Err(format!(
                    "Issuer certificate {} basicConstraints extension must be critical",
                    Backend::subject_name(cert)
                )
                .into());
            }
            if !basic_constraints.ca {
                return Err(format!(
                    "Issuer certificate {} basicConstraints cA must be asserted",
                    Backend::subject_name(cert)
                )
                .into());
            }

            if let Some(key_usage) = key_usage::<Backend>(cert)? {
                if !key_usage.key_cert_sign {
                    return Err(format!(
                        "Issuer certificate {} keyUsage must allow certificate signing",
                        Backend::subject_name(cert)
                    )
                    .into());
                }
            }

            Ok(())
        }
        [None, Some(_)] | [Some(_), None] => Ok(()),
        [None, None] => Err("Certificate path must not be empty".into()),
    })?;

    fold_policy::<_, _, Box<dyn std::error::Error>, 2>(
        path,
        path.len(),
        |window, max_path_length| match window {
            [Some(cert), Some(_)] => {
                let mut max_path_length = max_path_length;

                if !Backend::is_self_issued(cert)? {
                    if max_path_length == 0 {
                        return Err(format!(
                            "Issuer certificate {} exceeds pathLenConstraint",
                            Backend::subject_name(cert)
                        )
                        .into());
                    }

                    max_path_length -= 1;
                }

                if let Some(path_len_constraint) =
                    basic_constraints::<Backend>(cert)?.and_then(|bc| {
                        if bc.ca {
                            bc.path_len_constraint
                        } else {
                            None
                        }
                    })
                {
                    max_path_length = max_path_length.min(path_len_constraint);
                }

                Ok(max_path_length)
            }
            [None, Some(_)] | [Some(_), None] => Ok(max_path_length),
            [None, None] => Err("Certificate path must not be empty".into()),
        },
    )?;

    Ok(())
}

fn basic_constraints<Backend: CertificateBackend>(
    cert: &Backend::Certificate,
) -> super::Result<Option<BasicConstraints>> {
    let Some(value) = Backend::get_extension_value_by_oid(cert, oid::BASIC_CONSTRAINTS)? else {
        return Ok(None);
    };
    let critical = Backend::extension_criticality(cert, oid::BASIC_CONSTRAINTS)?.unwrap_or(false);
    let mut reader = DerReader::new(&value);
    let sequence = reader.read_tagged(0x30)?;
    reader.finish()?;

    let mut sequence = DerReader::new(sequence);
    let ca = if sequence.peek_tag() == Some(0x01) {
        sequence.read_bool()?
    } else {
        false
    };
    let path_len_constraint = if sequence.peek_tag() == Some(0x02) {
        Some(sequence.read_usize()?)
    } else {
        None
    };
    sequence.finish()?;

    Ok(Some(BasicConstraints {
        critical,
        ca,
        path_len_constraint,
    }))
}

fn key_usage<Backend: CertificateBackend>(
    cert: &Backend::Certificate,
) -> super::Result<Option<KeyUsage>> {
    let Some(value) = Backend::get_extension_value_by_oid(cert, oid::KEY_USAGE)? else {
        return Ok(None);
    };
    let mut reader = DerReader::new(&value);
    let bit_string = reader.read_tagged(0x03)?;
    reader.finish()?;

    if bit_string.is_empty() {
        return Err("keyUsage BIT STRING missing unused-bit count".into());
    }
    let unused_bits = bit_string[0];
    if unused_bits > 7 {
        return Err("keyUsage BIT STRING has invalid unused-bit count".into());
    }

    Ok(Some(KeyUsage {
        key_cert_sign: bit_string
            .get(1)
            .map(|first_byte| first_byte & 0x04 != 0)
            .unwrap_or(false),
    }))
}

struct DerReader<'a> {
    input: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.input.first().copied()
    }

    fn read_bool(&mut self) -> super::Result<bool> {
        let value = self.read_tagged(0x01)?;
        if value.len() != 1 {
            return Err("BOOLEAN value must contain exactly one byte".into());
        }

        Ok(value[0] != 0)
    }

    fn read_usize(&mut self) -> super::Result<usize> {
        let value = self.read_tagged(0x02)?;
        if value.is_empty() {
            return Err("INTEGER value must not be empty".into());
        }
        if value[0] & 0x80 != 0 {
            return Err("INTEGER value must be non-negative".into());
        }

        value.iter().try_fold(0usize, |acc, byte| {
            acc.checked_mul(256)
                .and_then(|acc| acc.checked_add(usize::from(*byte)))
                .ok_or_else(|| {
                    Box::<dyn std::error::Error>::from("INTEGER value does not fit usize")
                })
        })
    }

    fn read_tagged(&mut self, expected_tag: u8) -> super::Result<&'a [u8]> {
        let Some((&tag, rest)) = self.input.split_first() else {
            return Err("Unexpected end of DER input".into());
        };
        if tag != expected_tag {
            return Err(format!("Unexpected DER tag {tag:#x}, expected {expected_tag:#x}").into());
        }

        let (length, rest) = read_der_length(rest)?;
        if rest.len() < length {
            return Err("DER length exceeds remaining input".into());
        }

        let (value, remaining) = rest.split_at(length);
        self.input = remaining;
        Ok(value)
    }

    fn finish(&self) -> super::Result<()> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err("Unexpected trailing DER input".into())
        }
    }
}

fn read_der_length(input: &[u8]) -> super::Result<(usize, &[u8])> {
    let Some((&first, rest)) = input.split_first() else {
        return Err("Unexpected end of DER length".into());
    };

    if first & 0x80 == 0 {
        return Ok((usize::from(first), rest));
    }

    let length_bytes = usize::from(first & 0x7f);
    if length_bytes == 0 {
        return Err("Indefinite DER lengths are not allowed".into());
    }
    if rest.len() < length_bytes {
        return Err("DER length byte count exceeds remaining input".into());
    }

    let (length, rest) = rest.split_at(length_bytes);
    let length = length.iter().try_fold(0usize, |acc, byte| {
        acc.checked_mul(256)
            .and_then(|acc| acc.checked_add(usize::from(*byte)))
            .ok_or_else(|| Box::<dyn std::error::Error>::from("DER length does not fit usize"))
    })?;

    Ok((length, rest))
}

fn assert_skipped_extension_not_present<Backend: CertificateBackend>(
    cert: &Backend::Certificate,
    oid: &str,
) -> super::Result<()> {
    if Backend::extension_criticality(cert, oid)?.is_some() {
        return Err(format!(
            "Certificate {} contains unsupported extension {}",
            Backend::subject_name(cert),
            oid
        )
        .into());
    }

    Ok(())
}

fn assert_no_unhandled_critical_extensions<Backend: CertificateBackend>(
    cert: &Backend::Certificate,
) -> super::Result<()> {
    for critical_oid in Backend::critical_extension_oids(cert) {
        if !oid::HANDLED_CRITICAL_EXTENSIONS.contains(&critical_oid.as_str()) {
            return Err(format!(
                "Certificate {} contains unhandled critical extension {}",
                Backend::subject_name(cert),
                critical_oid
            )
            .into());
        }
    }

    Ok(())
}

mod oid {
    pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
    pub const KEY_USAGE: &str = "2.5.29.15";
    pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";
    pub const POLICY_MAPPINGS: &str = "2.5.29.33";
    pub const NAME_CONSTRAINTS: &str = "2.5.29.30";
    pub const POLICY_CONSTRAINTS: &str = "2.5.29.36";
    pub const INHIBIT_ANY_POLICY: &str = "2.5.29.54";

    pub const HANDLED_CRITICAL_EXTENSIONS: &[&str] = &[BASIC_CONSTRAINTS, KEY_USAGE];
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{fold_policy, rfc5280_policy, window_policy, BasicConstraints, KeyUsage};
    use crate::{CertificateBackend, Result};

    #[test]
    fn fold_policy_evaluates_padded_windows() {
        let certificates = ["A", "B", "C"];
        let path = certificates.iter().collect::<Vec<_>>();

        let windows = fold_policy::<_, _, (), 3>(&path, Vec::new(), |window, mut windows| {
            windows.push(window.map(|entry| entry.copied()));
            Ok(windows)
        })
        .unwrap();

        assert_eq!(
            windows,
            vec![
                [None, None, Some("A")],
                [None, Some("A"), Some("B")],
                [Some("A"), Some("B"), Some("C")],
                [Some("B"), Some("C"), None],
                [Some("C"), None, None],
            ]
        );
    }

    #[test]
    fn fold_policy_returns_final_accumulator() {
        let certificates = [1, 2, 3];
        let path = certificates.iter().collect::<Vec<_>>();

        let sum = fold_policy::<_, _, (), 1>(&path, 0, |[cert], sum| {
            Ok(sum + *cert.expect("window should contain one certificate"))
        })
        .unwrap();

        assert_eq!(sum, 6);
    }

    #[test]
    fn fold_policy_short_circuits_on_first_error() {
        let certificates = [1, 2, 3];
        let path = certificates.iter().collect::<Vec<_>>();

        let error = fold_policy::<_, _, &str, 1>(&path, 0, |[cert], count| {
            if *cert.expect("window should contain one certificate") == 2 {
                return Err("stop");
            }

            Ok(count + 1)
        })
        .expect_err("policy should stop at failing certificate");

        assert_eq!(error, "stop");
    }

    #[test]
    fn window_policy_discards_accumulator() {
        let certificates = ["A", "B"];
        let path = certificates.iter().collect::<Vec<_>>();

        window_policy::<_, (), 2>(&path, |window| match window.map(|entry| entry.copied()) {
            [None, Some("A")] | [Some("A"), Some("B")] | [Some("B"), None] => Ok(()),
            unexpected => panic!("unexpected window: {:?}", unexpected),
        })
        .unwrap();
    }

    #[test]
    fn rfc5280_policy_accepts_valid_path() {
        let root = TestCertificate::ca("Root", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10)).unwrap();
    }

    #[test]
    fn rfc5280_policy_rejects_non_self_issued_first_certificate() {
        let root = TestCertificate::ca("Root", "Other");
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("first certificate must be self-issued");
    }

    #[test]
    fn rfc5280_policy_rejects_issuer_subject_mismatch() {
        let root = TestCertificate::ca("Root", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Other");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("issuer subject must match subject issuer");
    }

    #[test]
    fn rfc5280_policy_rejects_invalid_cert_time() {
        let root = TestCertificate::ca("Root", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(200))
            .expect_err("certificate must be valid at evaluation time");
    }

    #[test]
    fn rfc5280_policy_rejects_skipped_extension() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.extensions.insert("2.5.29.32".to_string(), true);
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("unsupported skipped extension must fail");
    }

    #[test]
    fn rfc5280_policy_rejects_non_critical_skipped_extension() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.extensions.insert("2.5.29.32".to_string(), false);
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("unsupported skipped extension must fail even when non-critical");
    }

    #[test]
    fn rfc5280_policy_rejects_unhandled_critical_extension() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.extensions.insert("1.2.3.4.5".to_string(), true);
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("unknown critical extension must fail");
    }

    #[test]
    fn rfc5280_policy_rejects_non_ca_issuer() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.basic_constraints = Some(BasicConstraints {
            critical: true,
            ca: false,
            path_len_constraint: None,
        });
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("issuer must assert basicConstraints cA");
    }

    #[test]
    fn rfc5280_policy_rejects_issuer_without_key_cert_sign_usage() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.key_usage = Some(KeyUsage {
            key_cert_sign: false,
        });
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("issuer keyUsage must allow certificate signing");
    }

    #[test]
    fn rfc5280_policy_rejects_path_len_constraint_exceeded() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.basic_constraints = Some(BasicConstraints {
            critical: true,
            ca: true,
            path_len_constraint: Some(0),
        });
        let intermediate = TestCertificate::ca("Intermediate", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Intermediate");
        let path = [&root, &intermediate, &leaf];

        rfc5280_policy::<TestBackend>(&path, Duration::from_secs(10))
            .expect_err("root pathLenConstraint should reject intermediate CA");
    }

    #[derive(Clone, Debug)]
    struct TestCertificate {
        subject: String,
        issuer: String,
        valid_from: Duration,
        valid_until: Duration,
        v3: bool,
        basic_constraints: Option<BasicConstraints>,
        key_usage: Option<KeyUsage>,
        extensions: HashMap<String, bool>,
    }

    impl TestCertificate {
        fn ca(subject: &str, issuer: &str) -> Self {
            let mut extensions = HashMap::new();
            extensions.insert("2.5.29.19".to_string(), true);
            extensions.insert("2.5.29.15".to_string(), true);

            Self {
                subject: subject.to_string(),
                issuer: issuer.to_string(),
                valid_from: Duration::from_secs(0),
                valid_until: Duration::from_secs(100),
                v3: true,
                basic_constraints: Some(BasicConstraints {
                    critical: true,
                    ca: true,
                    path_len_constraint: None,
                }),
                key_usage: Some(KeyUsage {
                    key_cert_sign: true,
                }),
                extensions,
            }
        }

        fn leaf(subject: &str, issuer: &str) -> Self {
            Self {
                subject: subject.to_string(),
                issuer: issuer.to_string(),
                valid_from: Duration::from_secs(0),
                valid_until: Duration::from_secs(100),
                v3: true,
                basic_constraints: None,
                key_usage: None,
                extensions: HashMap::new(),
            }
        }
    }

    struct TestBackend;

    impl CertificateBackend for TestBackend {
        type Certificate = TestCertificate;

        fn from_pem(_pem: &[u8]) -> Result<Self::Certificate> {
            unimplemented!("test backend does not parse certificates")
        }

        fn from_pem_chain(_pem: &[u8]) -> Result<Vec<Self::Certificate>> {
            unimplemented!("test backend does not parse certificate chains")
        }

        fn from_der(_der: &[u8]) -> Result<Self::Certificate> {
            unimplemented!("test backend does not parse certificates")
        }

        fn to_der(_cert: &Self::Certificate) -> Result<Vec<u8>> {
            unimplemented!("test backend does not encode certificates")
        }

        fn to_pem(_cert: &Self::Certificate) -> Result<String> {
            unimplemented!("test backend does not encode certificates")
        }

        fn get_public_key(_cert: &Self::Certificate) -> Result<Vec<u8>> {
            unimplemented!("test backend does not expose public keys")
        }

        fn public_key_algorithm(_cert: &Self::Certificate) -> Result<String> {
            unimplemented!("test backend does not expose public key algorithms")
        }

        fn get_extension_value_by_oid(
            cert: &Self::Certificate,
            oid: &str,
        ) -> Result<Option<Vec<u8>>> {
            match oid {
                "2.5.29.19" => Ok(cert.basic_constraints.map(encode_basic_constraints)),
                "2.5.29.15" => Ok(cert.key_usage.map(encode_key_usage)),
                _ => Ok(None),
            }
        }

        fn subject_name(cert: &Self::Certificate) -> String {
            cert.subject.clone()
        }

        fn issuer_name(cert: &Self::Certificate) -> String {
            cert.issuer.clone()
        }

        fn issuer_name_matches_subject(
            cert: &Self::Certificate,
            issuer: &Self::Certificate,
        ) -> Result<bool> {
            Ok(cert.issuer == issuer.subject)
        }

        fn is_valid_at(cert: &Self::Certificate, unix_time: Duration) -> Result<bool> {
            Ok(cert.valid_from <= unix_time && unix_time <= cert.valid_until)
        }

        fn version(cert: &Self::Certificate) -> Result<u8> {
            Ok(if cert.v3 { 2 } else { 0 })
        }

        fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
            Ok(cert.extensions.get(oid).copied())
        }

        fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
            cert.extensions
                .iter()
                .filter_map(|(oid, critical)| critical.then(|| oid.clone()))
                .collect()
        }
    }

    fn encode_basic_constraints(basic_constraints: BasicConstraints) -> Vec<u8> {
        let mut value = Vec::new();
        if basic_constraints.ca {
            value.extend([0x01, 0x01, 0xff]);
        }
        if let Some(path_len_constraint) = basic_constraints.path_len_constraint {
            value.push(0x02);
            value.push(0x01);
            value.push(
                path_len_constraint
                    .try_into()
                    .expect("test path len fits u8"),
            );
        }

        let mut der = vec![
            0x30,
            value.len().try_into().expect("test DER length fits u8"),
        ];
        der.extend(value);
        der
    }

    fn encode_key_usage(key_usage: KeyUsage) -> Vec<u8> {
        if key_usage.key_cert_sign {
            vec![0x03, 0x02, 0x02, 0x04]
        } else {
            vec![0x03, 0x01, 0x00]
        }
    }
}
