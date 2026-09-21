// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! did:x509 validation and resolution over TAV's selected crypto backend.
//! `validation_sync` and `validation_async` are generated from one implementation.

mod document;
mod error;
mod input;
mod parser;
mod policy_config;
mod predicate;

pub use document::{DidDocument, Jwk, VerificationMethod};
pub use error::{PredicateMismatch, ValidationError, ValidationTime};
pub use policy_config::PolicyConfig;

use maybe_async_attr::maybe_async;

#[maybe_async(
    sync: {
        use tee_attestation_verification_crypto::CryptoBackend;
    },
    async: {
        use tee_attestation_verification_crypto::AsyncCryptoBackend;
    },
)]
pub mod validation {
    use crate::{
        input::Chain,
        parser::{self, FingerprintAlgorithm},
        predicate, DidDocument, Jwk, PolicyConfig, PredicateMismatch, ValidationError,
        ValidationTime, VerificationMethod,
    };
    use std::time::UNIX_EPOCH;
    use tee_attestation_verification_crypto::{
        base64::base64_encode_no_padding, x509, Certificate, CertificateBackend, Crypto,
        DigestAlgorithm,
    };

    #[maybe_async_fn]
    /// Validate an ordered, certificate-only PEM path at the caller's chosen time.
    pub fn validate_pem(
        did: &str,
        chain_pem: &str,
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<(), ValidationError> {
        mb_await!(validate(did, Chain::Pem(chain_pem), time, policy)).map(|_| ())
    }

    #[maybe_async_fn]
    /// Validate the specification's comma-separated base64url DER `x509chain`.
    pub fn validate_x509chain(
        did: &str,
        chain: &str,
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<(), ValidationError> {
        mb_await!(validate(did, Chain::X509(chain), time, policy)).map(|_| ())
    }

    #[maybe_async_fn]
    /// Validate individual DER certificates, leaf first and trust anchor last.
    pub fn validate_der(
        did: &str,
        chain: &[&[u8]],
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<(), ValidationError> {
        mb_await!(validate(did, Chain::Der(chain), time, policy)).map(|_| ())
    }

    #[maybe_async_fn]
    /// Resolve an ordered PEM path into a typed DID Document.
    pub fn resolve_pem(
        did: &str,
        chain_pem: &str,
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<DidDocument, ValidationError> {
        mb_await!(resolve(did, Chain::Pem(chain_pem), time, policy))
    }

    #[maybe_async_fn]
    /// Resolve using the specification's `x509chain` input.
    pub fn resolve_x509chain(
        did: &str,
        chain: &str,
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<DidDocument, ValidationError> {
        mb_await!(resolve(did, Chain::X509(chain), time, policy))
    }

    #[maybe_async_fn]
    /// Resolve directly from individual DER certificates without PEM conversion.
    pub fn resolve_der(
        did: &str,
        chain: &[&[u8]],
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<DidDocument, ValidationError> {
        mb_await!(resolve(did, Chain::Der(chain), time, policy))
    }

    #[maybe_async_fn]
    /// Resolve the leaf's public JWK, including validation and key-usage checks.
    pub fn resolve_jwk_pem(
        did: &str,
        chain: &str,
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<Jwk, ValidationError> {
        Ok(mb_await!(resolve_pem(did, chain, time, policy))?
            .verification_method
            .public_key_jwk)
    }

    #[maybe_async_fn]
    fn validate<'a>(
        did: &'a str,
        input: Chain<'_>,
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<(&'a str, Certificate), ValidationError> {
        if policy.rfc5280_validation {
            return Err(ValidationError::UnsupportedPolicy {
                message: "full RFC 5280 validation is not implemented".into(),
            });
        }
        let parsed = parser::parse(did).map_err(|message| ValidationError::InvalidDid {
            did: did.to_owned(),
            message,
        })?;
        let certificates = input.parse()?;
        if certificates.len() < 2 {
            return Err(ValidationError::InvalidChain {
                did: did.to_owned(),
                chain_input: input.diagnostic(),
                message: "expected a leaf and trust anchor".into(),
            });
        }
        let unix_time = match time {
            ValidationTime::Now => None,
            ValidationTime::At(time) => Some(time.duration_since(UNIX_EPOCH).map_err(|_| {
                ValidationError::InvalidInput {
                    message: "validation time predates the Unix epoch".into(),
                }
            })?),
        };
        let root = &certificates[certificates.len() - 1];
        let intermediates: Vec<_> = certificates[1..certificates.len() - 1]
            .iter()
            .rev()
            .collect();
        mb_await!(Crypto::verify_chain_exact(
            root,
            &intermediates,
            &certificates[0],
            unix_time
        ))
        .map_err(|error| ValidationError::InvalidChain {
            did: did.to_owned(),
            chain_input: input.diagnostic(),
            message: error.to_string(),
        })?;
        let model = predicate::certificate_model(&certificates).map_err(|error| {
            ValidationError::InvalidChain {
                did: did.to_owned(),
                chain_input: input.diagnostic(),
                message: error.to_string(),
            }
        })?;
        let algorithm = match parsed.algorithm {
            FingerprintAlgorithm::Sha256 => DigestAlgorithm::Sha256,
            FingerprintAlgorithm::Sha384 => DigestAlgorithm::Sha384,
            FingerprintAlgorithm::Sha512 => DigestAlgorithm::Sha512,
        };
        let mut matches = false;
        for ca in &certificates[1..] {
            let der = Crypto::to_der(ca).map_err(|error| ValidationError::InvalidChain {
                did: did.to_owned(),
                chain_input: input.diagnostic(),
                message: error.to_string(),
            })?;
            let fingerprint = mb_await!(Crypto::digest(algorithm, &der)).map_err(|error| {
                ValidationError::InvalidChain {
                    did: did.to_owned(),
                    chain_input: input.diagnostic(),
                    message: error.to_string(),
                }
            })?;
            if fingerprint == parsed.fingerprint {
                matches = true;
                break;
            }
        }
        if !matches {
            return Err(ValidationError::PredicateMismatch {
                did: did.to_owned(),
                chain_input: input.diagnostic(),
                mismatch: PredicateMismatch::CaFingerprint,
            });
        }
        predicate::evaluate(&model, &parsed.predicates).map_err(|mismatch| {
            ValidationError::PredicateMismatch {
                did: did.to_owned(),
                chain_input: input.diagnostic(),
                mismatch,
            }
        })?;
        Ok((parsed.id, model.certificate))
    }

    #[maybe_async_fn]
    fn resolve(
        did: &str,
        input: Chain<'_>,
        time: ValidationTime,
        policy: PolicyConfig,
    ) -> Result<DidDocument, ValidationError> {
        let (id, leaf) = mb_await!(validate(did, input, time, policy))?;
        let usage = Crypto::key_usage(&leaf).map_err(|error| ValidationError::InvalidKey {
            message: error.to_string(),
        })?;
        let digital_signature = usage.as_ref().is_none_or(|usage| usage.digital_signature);
        let key_agreement = usage.as_ref().is_none_or(|usage| usage.key_agreement);
        if !digital_signature && !key_agreement {
            return Err(ValidationError::InvalidKey {
                message: "key usage permits neither signatures nor key agreement".into(),
            });
        }
        let key = match Crypto::public_key_components(&leaf).map_err(|error| {
            ValidationError::InvalidKey {
                message: error.to_string(),
            }
        })? {
            x509::PublicKey::Rsa { n, e } => Jwk::Rsa {
                n: base64_encode_no_padding(&n),
                e: base64_encode_no_padding(&e),
            },
            x509::PublicKey::Ec { curve, x, y } => Jwk::Ec {
                crv: curve.to_owned(),
                x: base64_encode_no_padding(&x),
                y: base64_encode_no_padding(&y),
            },
        };
        let key_id = format!("{id}#0");
        Ok(DidDocument {
            id: id.to_owned(),
            verification_method: VerificationMethod {
                id: key_id.clone(),
                controller: id.to_owned(),
                public_key_jwk: key,
            },
            authentication: if digital_signature {
                vec![key_id.clone()]
            } else {
                vec![]
            },
            assertion_method: if digital_signature {
                vec![key_id.clone()]
            } else {
                vec![]
            },
            key_agreement: if key_agreement { vec![key_id] } else { vec![] },
        })
    }
}
