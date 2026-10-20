// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{
    parser::{Predicate, SanKind},
    PredicateMismatch,
};
use tee_attestation_verification_crypto::{
    x509::{Attribute, SubjectAlternativeName},
    Certificate, CertificateBackend, Crypto, Result,
};

pub(crate) struct Model {
    pub certificate: Certificate,
    subject: Vec<Attribute>,
    names: Vec<SubjectAlternativeName>,
    eku: Vec<String>,
    fulcio: Option<Vec<u8>>,
}

pub(crate) fn certificate_model(chain: &[Certificate]) -> Result<Model> {
    let mut decoded = Vec::with_capacity(chain.len());
    for (index, certificate) in chain.iter().enumerate() {
        for oid in Crypto::critical_extension_oids(certificate) {
            if !matches!(
                oid.as_str(),
                "2.5.29.15"
                    | "2.5.29.17"
                    | "2.5.29.19"
                    | "2.5.29.30"
                    | "2.5.29.32"
                    | "2.5.29.33"
                    | "2.5.29.36"
                    | "2.5.29.37"
                    | "2.5.29.54"
            ) {
                return Err(format!(
                    "Critical extension {oid} is outside the did:x509 certificate model"
                )
                .into());
            }
        }
        let details = Crypto::certificate_details(certificate)?;
        let subject = details.subject.into_iter().flatten().collect::<Vec<_>>();
        for (index, attribute) in subject.iter().enumerate() {
            if subject[..index]
                .iter()
                .any(|other| other.oid == attribute.oid)
            {
                return Err("Certificate subject contains repeated attributes".into());
            }
        }
        let names = details.subject_alt_names;
        if names.as_ref().is_some_and(|names| names.is_empty()) {
            return Err("Empty subject alternative name extension".into());
        }
        let eku = details.extended_key_usage;
        if let Some(eku) = &eku {
            if eku.is_empty() {
                return Err("Empty extended key usage extension".into());
            }
            for (index, oid) in eku.iter().enumerate() {
                if eku[..index].contains(oid) {
                    return Err("Repeated extended key usage".into());
                }
            }
        }
        if Crypto::extension_criticality(certificate, "1.3.6.1.4.1.57264.1.1")? == Some(true) {
            return Err("Fulcio issuer extension must not be critical".into());
        }
        if index > 0 {
            let constraints =
                Crypto::basic_constraints(certificate)?.ok_or("Issuer has no basicConstraints")?;
            if !constraints.ca {
                return Err("Issuer is not a CA".into());
            }
            if Crypto::key_usage(certificate)?.is_some_and(|usage| !usage.key_cert_sign) {
                return Err("Issuer key usage does not permit certificate signing".into());
            }
        }
        decoded.push((certificate, subject, names, eku));
    }
    let (certificate, subject, names, eku) = decoded.into_iter().next().ok_or("Empty chain")?;
    Ok(Model {
        certificate: certificate.clone(),
        subject,
        names: names.unwrap_or_default(),
        eku: eku.unwrap_or_default(),
        fulcio: Crypto::get_extension_value_by_oid(&chain[0], "1.3.6.1.4.1.57264.1.1")?,
    })
}

pub(crate) fn evaluate(
    model: &Model,
    predicates: &[Predicate],
) -> std::result::Result<(), PredicateMismatch> {
    for predicate in predicates {
        match predicate {
            Predicate::Subject(attributes) => {
                for (oid, expected) in attributes {
                    if !model
                        .subject
                        .iter()
                        .any(|attribute| &attribute.oid == oid && &attribute.value == expected)
                    {
                        return Err(PredicateMismatch::Subject {
                            key: oid.clone(),
                            expected: expected.clone(),
                        });
                    }
                }
            }
            Predicate::San { kind, value } => {
                if !model.names.iter().any(|name| match (kind, name) {
                    (SanKind::Email, SubjectAlternativeName::Email(actual))
                    | (SanKind::Dns, SubjectAlternativeName::Dns(actual))
                    | (SanKind::Uri, SubjectAlternativeName::Uri(actual)) => {
                        actual.as_str() == value
                    }
                    _ => false,
                }) {
                    return Err(PredicateMismatch::SubjectAlternativeName {
                        kind: kind.name().into(),
                        expected: value.clone(),
                    });
                }
            }
            Predicate::Eku(oid) if !model.eku.contains(oid) => {
                return Err(PredicateMismatch::ExtendedKeyUsage { oid: oid.clone() });
            }
            Predicate::Eku(_) => {}
            Predicate::FulcioIssuer(issuer) => {
                if model.fulcio.as_deref() != Some(format!("https://{issuer}").as_bytes()) {
                    return Err(PredicateMismatch::FulcioIssuer {
                        expected: issuer.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}
