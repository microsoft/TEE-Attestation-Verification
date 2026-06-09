// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable pure-Rust cryptographic backend.
//!
//! This backend is selected when `crypto_pure_rust` is enabled and no
//! target-preferred backend is enabled. It uses pure-Rust crates for X.509
//! certificate parsing, certificate-chain signature checks, and SEV-SNP
//! attestation report signature verification.

use p256::ecdsa::{Signature as EcdsaP256Signature, VerifyingKey as EcdsaP256VerifyingKey};
use p384::ecdsa::{Signature as EcdsaP384Signature, VerifyingKey as EcdsaP384VerifyingKey};
use p521::ecdsa::{Signature as EcdsaP521Signature, VerifyingKey as EcdsaP521VerifyingKey};
use rsa::{
    pkcs8::DecodePublicKey,
    pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    RsaPublicKey,
};
use sha2::{Sha256, Sha384, Sha512};
use std::time::Duration;
#[cfg(not(target_family = "wasm"))]
use std::time::{SystemTime, UNIX_EPOCH};

use super::x509_certificate::{self, Certificate};
use super::x509_policy;
use super::{
    CertificateBackend, CryptoBackend, EcSignatureKeyAlgorithm, KeyBackend, Result,
    RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

pub enum Key {
    EcdsaP256(EcdsaP256VerifyingKey),
    EcdsaP384(EcdsaP384VerifyingKey),
    EcdsaP521(EcdsaP521VerifyingKey),
    RsaPssSha256(PssVerifyingKey<Sha256>),
    RsaPssSha384(PssVerifyingKey<Sha384>),
    RsaPssSha512(PssVerifyingKey<Sha512>),
}

pub enum Signature {
    EcdsaP256(EcdsaP256Signature),
    EcdsaP384(EcdsaP384Signature),
    EcdsaP521(EcdsaP521Signature),
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        signature: PssSignature,
    },
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256) => Ok(Signature::EcdsaP256(
                EcdsaP256Signature::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA P-256 signature: {:?}", e))?,
            )),
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => Ok(Signature::EcdsaP384(
                EcdsaP384Signature::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA P-384 signature: {:?}", e))?,
            )),
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521) => Ok(Signature::EcdsaP521(
                EcdsaP521Signature::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA P-521 signature: {:?}", e))?,
            )),
            SignatureKeyAlgorithm::RsaPss(algorithm) => Ok(Signature::RsaPss {
                algorithm,
                signature: PssSignature::try_from(signature)
                    .map_err(|e| format!("Failed to parse RSA-PSS signature: {:?}", e))?,
            }),
        }
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let expected_len = algorithm.scalar_byte_len();
        if r.len() != expected_len || s.len() != expected_len {
            return Err(format!(
                "Invalid ECDSA {} component length: expected {}, got r={} s={}",
                algorithm.name(),
                expected_len,
                r.len(),
                s.len()
            )
            .into());
        }

        let mut fixed = Vec::with_capacity(algorithm.fixed_signature_byte_len());
        fixed.extend_from_slice(r);
        fixed.extend_from_slice(s);
        match algorithm {
            EcSignatureKeyAlgorithm::P256 => Ok(Signature::EcdsaP256(
                EcdsaP256Signature::from_slice(&fixed).map_err(|e| {
                    format!("Failed to parse fixed-width ECDSA P-256 signature: {:?}", e)
                })?,
            )),
            EcSignatureKeyAlgorithm::P384 => Ok(Signature::EcdsaP384(
                EcdsaP384Signature::from_slice(&fixed).map_err(|e| {
                    format!("Failed to parse fixed-width ECDSA P-384 signature: {:?}", e)
                })?,
            )),
            EcSignatureKeyAlgorithm::P521 => Ok(Signature::EcdsaP521(
                EcdsaP521Signature::from_slice(&fixed).map_err(|e| {
                    format!("Failed to parse fixed-width ECDSA P-521 signature: {:?}", e)
                })?,
            )),
        }
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256) => {
                let key = EcdsaP256VerifyingKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Key::EcdsaP256(key))
            }
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => {
                let key = EcdsaP384VerifyingKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Key::EcdsaP384(key))
            }
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521) => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;

                let public_key = p521::PublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                let key =
                    EcdsaP521VerifyingKey::from_encoded_point(&public_key.to_encoded_point(false))
                        .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Key::EcdsaP521(key))
            }
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256) => {
                let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Key::RsaPssSha256(PssVerifyingKey::<Sha256>::new(rsa_pub)))
            }
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
                let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Key::RsaPssSha384(PssVerifyingKey::<Sha384>::new(rsa_pub)))
            }
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps512) => {
                let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Key::RsaPssSha512(PssVerifyingKey::<Sha512>::new(rsa_pub)))
            }
        }
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        Certificate::from_pem(pem)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        Certificate::from_pem_chain(pem)
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        Certificate::from_der(der)
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        cert.to_pem()
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.public_key_spki_der()
    }

    fn public_key_algorithm(cert: &Self::Certificate) -> Result<String> {
        Ok(cert.public_key_algorithm())
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.get_extension_value_by_oid(oid)
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        cert.subject_name()
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        cert.issuer_name()
    }

    fn issuer_name_matches_subject(
        cert: &Self::Certificate,
        issuer: &Self::Certificate,
    ) -> Result<bool> {
        cert.issuer_name_matches_subject(issuer)
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        cert.is_valid_at(unix_time)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        Ok(cert.version())
    }

    fn basic_constraints(cert: &Self::Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.basic_constraints()
    }

    fn key_usage(cert: &Self::Certificate) -> Result<Option<super::KeyUsage>> {
        cert.key_usage()
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        cert.extension_criticality(oid)
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        cert.critical_extension_oids()
    }
}

impl CryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        match (key, signature) {
            (Key::EcdsaP256(key), Signature::EcdsaP256(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P256)
            }
            (Key::EcdsaP384(key), Signature::EcdsaP384(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P384)
            }
            (Key::EcdsaP521(key), Signature::EcdsaP521(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P521)
            }
            (
                Key::RsaPssSha256(key),
                Signature::RsaPss {
                    algorithm: RsaPssSignatureKeyAlgorithm::Ps256,
                    signature,
                },
            ) => verify_rsa_pss_signature(key, signed_bytes, signature),
            (
                Key::RsaPssSha384(key),
                Signature::RsaPss {
                    algorithm: RsaPssSignatureKeyAlgorithm::Ps384,
                    signature,
                },
            ) => verify_rsa_pss_signature(key, signed_bytes, signature),
            (
                Key::RsaPssSha512(key),
                Signature::RsaPss {
                    algorithm: RsaPssSignatureKeyAlgorithm::Ps512,
                    signature,
                },
            ) => verify_rsa_pss_signature(key, signed_bytes, signature),
            _ => Err(format!(
                "Signature algorithm {:?} does not match key algorithm {:?}",
                signature.algorithm(),
                key.algorithm()
            )
            .into()),
        }
    }

    fn verify_chain(
        trusted_cert: &Certificate,
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
    ) -> Result<()> {
        x509_certificate::verify_certificate_path(
            verify_certificate_signature,
            trusted_cert,
            untrusted_chain,
            leaf,
        )?;

        let policy_path = policy_path(trusted_cert, untrusted_chain, leaf);
        x509_policy::rfc5280_policy::<Crypto>(&policy_path, unix_time_now()?)
    }
}

#[cfg(not(target_family = "wasm"))]
fn unix_time_now() -> Result<Duration> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?)
}

#[cfg(target_family = "wasm")]
fn unix_time_now() -> Result<Duration> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || millis < 0.0 || millis > u64::MAX as f64 {
        return Err("Failed to read current Unix time from JavaScript Date".into());
    }

    Ok(Duration::from_millis(millis as u64))
}

fn policy_path<'a>(
    trusted_cert: &'a Certificate,
    untrusted_chain: &[&'a Certificate],
    leaf: &'a Certificate,
) -> Vec<&'a Certificate> {
    let mut path = Vec::with_capacity(untrusted_chain.len() + 2);
    path.push(trusted_cert);
    for cert in untrusted_chain {
        if path.last().copied() != Some(*cert) {
            path.push(*cert);
        }
    }
    if path.last().copied() != Some(leaf) {
        path.push(leaf);
    }
    path
}

fn verify_certificate_signature(issuer: &Certificate, subject: &Certificate) -> Result<()> {
    let tbs_bytes = subject.tbs_certificate_der()?;
    let issuer_spki = issuer.public_key_spki_der()?;
    let algorithm = subject.signature_algorithm()?;
    let key = <Key as KeyBackend>::from_spki_der(&issuer_spki, algorithm)?;
    let signature =
        <Signature as SignatureBackend>::from_bytes(subject.signature_bytes(), algorithm)?;

    <Crypto as CryptoBackend>::verify_signature(&key, &signature, &tbs_bytes)
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Key::EcdsaP256(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            Key::EcdsaP384(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Key::EcdsaP521(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521),
            Key::RsaPssSha256(_) => {
                SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256)
            }
            Key::RsaPssSha384(_) => {
                SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384)
            }
            Key::RsaPssSha512(_) => {
                SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps512)
            }
        }
    }
}

fn verify_ecdsa_signature<K, S>(
    key: &K,
    signed_bytes: &[u8],
    signature: &S,
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<()>
where
    K: ecdsa::signature::Verifier<S>,
{
    ecdsa::signature::Verifier::verify(key, signed_bytes, &signature).map_err(|e| {
        format!(
            "ECDSA {} signature verification failed: {:?}",
            algorithm.name(),
            e
        )
    })?;
    Ok(())
}

fn verify_rsa_pss_signature<D>(
    key: &PssVerifyingKey<D>,
    signed_bytes: &[u8],
    signature: &PssSignature,
) -> Result<()>
where
    D: sha2::Digest,
    PssVerifyingKey<D>: rsa::signature::Verifier<PssSignature>,
{
    use rsa::signature::Verifier;
    key.verify(signed_bytes, signature)
        .map_err(|e| format!("RSA-PSS signature verification failed: {:?}", e))?;
    Ok(())
}

impl Signature {
    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::EcdsaP256(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            Self::EcdsaP384(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Self::EcdsaP521(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
        }
    }
}
