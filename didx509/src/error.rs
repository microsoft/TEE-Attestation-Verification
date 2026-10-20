// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::{fmt, time::SystemTime};

/// Time used for certificate path validation. Historical time is caller policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationTime {
    Now,
    At(SystemTime),
}

/// Failed validation or resolution. Display omits the supplied DID and chain.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    UnsupportedPolicy {
        message: String,
    },
    InvalidDid {
        did: String,
        message: String,
    },
    InvalidPem {
        chain_pem: String,
        message: String,
    },
    InvalidInput {
        message: String,
    },
    InvalidChain {
        did: String,
        chain_input: String,
        message: String,
    },
    PredicateMismatch {
        did: String,
        chain_input: String,
        mismatch: PredicateMismatch,
    },
    InvalidKey {
        message: String,
    },
}

#[derive(Debug)]
#[non_exhaustive]
pub enum PredicateMismatch {
    CaFingerprint,
    Subject { key: String, expected: String },
    SubjectAlternativeName { kind: String, expected: String },
    ExtendedKeyUsage { oid: String },
    FulcioIssuer { expected: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPolicy { message } => {
                write!(formatter, "unsupported validation policy: {message}")
            }
            Self::InvalidDid { message, .. } => {
                write!(formatter, "invalid did:x509 identifier: {message}")
            }
            Self::InvalidPem { message, .. } => {
                write!(formatter, "invalid certificate PEM: {message}")
            }
            Self::InvalidInput { message } => {
                write!(formatter, "invalid certificate input: {message}")
            }
            Self::InvalidChain { message, .. } => {
                write!(formatter, "invalid certificate chain: {message}")
            }
            Self::PredicateMismatch { mismatch, .. } => mismatch.fmt(formatter),
            Self::InvalidKey { message } => write!(formatter, "invalid leaf key: {message}"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl fmt::Display for PredicateMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaFingerprint => formatter.write_str("CA fingerprint does not match"),
            Self::Subject { key, .. } => {
                write!(formatter, "certificate subject {key} does not match")
            }
            Self::SubjectAlternativeName { kind, .. } => {
                write!(formatter, "certificate {kind} SAN does not match")
            }
            Self::ExtendedKeyUsage { .. } => {
                formatter.write_str("certificate extended key usage does not match")
            }
            Self::FulcioIssuer { .. } => formatter.write_str("Fulcio issuer does not match"),
        }
    }
}
