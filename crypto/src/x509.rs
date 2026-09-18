// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-neutral certificate metadata returned by [`crate::CertificateBackend`].
//! Decoded metadata does not imply trust.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub oid: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectAlternativeName {
    Email(String),
    Dns(String),
    Uri(String),
    /// A decoded alternative name outside the supported string forms.
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateDetails {
    /// RDN groups, preserving repeated attributes.
    pub subject: Vec<Vec<Attribute>>,
    /// `None` means absent; an empty vector means present but empty.
    pub subject_alt_names: Option<Vec<SubjectAlternativeName>>,
    pub extended_key_usage: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKey {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ec {
        curve: &'static str,
        x: Vec<u8>,
        y: Vec<u8>,
    },
}
