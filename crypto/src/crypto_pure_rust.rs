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
use sha2::Sha384;

use super::x509_certificate::{self, Certificate};
use super::{
    CertificateBackend, CryptoBackend, EcSignatureKeyAlgorithm, KeyBackend, KeySignatureBackend,
    Result, RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

pub enum Key {
    EcdsaP256(EcdsaP256VerifyingKey),
    EcdsaP384(EcdsaP384VerifyingKey),
    EcdsaP521(EcdsaP521VerifyingKey),
    RsaPssSha384(PssVerifyingKey<Sha384>),
}

pub enum Signature {
    EcdsaP256(EcdsaP256Signature),
    EcdsaP384(EcdsaP384Signature),
    EcdsaP521(EcdsaP521Signature),
    RsaPssSha384(PssSignature),
}

impl SignatureBackend for Crypto {
    type Signature = Signature;

    fn signature_from_der(
        signature: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Self::Signature> {
        signature_from_der(signature, algorithm)
    }

    fn signature_from_raw(
        signature: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Self::Signature> {
        signature_from_raw(signature, algorithm)
    }

    fn signature_from_ec_components(
        r: &[u8],
        s: &[u8],
        algorithm: EcSignatureKeyAlgorithm,
    ) -> Result<Self::Signature> {
        signature_from_ec_components(r, s, algorithm)
    }
}

impl KeyBackend for Crypto {
    type Key = Key;

    fn key_from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self::Key> {
        Key::from_spki_der(spki_der, algorithm)
    }
}

impl KeySignatureBackend for Crypto {
    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        key.verify(signed_bytes, signature)
    }
}

impl Crypto {
    pub fn key_from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Key> {
        Key::from_spki_der(spki_der, algorithm)
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

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.get_extension_value_by_oid(oid)
    }
}

impl CryptoBackend for Crypto {
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
        )
    }
}

fn verify_certificate_signature(issuer: &Certificate, subject: &Certificate) -> Result<()> {
    let tbs_bytes = subject.tbs_certificate_der()?;
    let issuer_spki = issuer.public_key_spki_der()?;
    let key =
        <Crypto as KeyBackend>::key_from_spki_der(&issuer_spki, subject.signature_algorithm()?)?;
    let signature = <Crypto as SignatureBackend>::signature_from_raw(
        subject.signature_bytes(),
        subject.signature_algorithm()?,
    )?;

    <Crypto as KeySignatureBackend>::verify_signature(&key, &signature, &tbs_bytes)
}

impl Key {
    pub fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
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
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
                let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Key::RsaPssSha384(PssVerifyingKey::<Sha384>::new(rsa_pub)))
            }
            _ => Err(format!("Unsupported signature key algorithm: {algorithm:?}").into()),
        }
    }

    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Key::EcdsaP256(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            Key::EcdsaP384(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Key::EcdsaP521(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521),
            Key::RsaPssSha384(_) => {
                SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384)
            }
        }
    }

    pub fn verify(&self, signed_bytes: &[u8], signature: &Signature) -> Result<()> {
        match (self, signature) {
            (Key::EcdsaP256(key), Signature::EcdsaP256(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P256)
            }
            (Key::EcdsaP384(key), Signature::EcdsaP384(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P384)
            }
            (Key::EcdsaP521(key), Signature::EcdsaP521(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P521)
            }
            (Key::RsaPssSha384(key), Signature::RsaPssSha384(signature)) => {
                use rsa::signature::Verifier;
                key.verify(signed_bytes, &signature)
                    .map_err(|e| format!("RSA-PSS signature verification failed: {:?}", e))?;
                Ok(())
            }
            _ => Err(format!(
                "Signature algorithm {:?} does not match key algorithm {:?}",
                signature.algorithm(),
                self.algorithm()
            )
            .into()),
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

fn signature_from_der(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Signature> {
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
        SignatureKeyAlgorithm::RsaPss(_) => Err("RSA-PSS signatures must be raw bytes".into()),
    }
}

fn signature_from_raw(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Signature> {
    match algorithm {
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
            Ok(Signature::RsaPssSha384(
                PssSignature::try_from(signature)
                    .map_err(|e| format!("Failed to parse RSA-PSS signature: {:?}", e))?,
            ))
        }
        SignatureKeyAlgorithm::RsaPss(algorithm) => {
            Err(format!("Unsupported RSA-PSS signature algorithm: {algorithm:?}").into())
        }
        SignatureKeyAlgorithm::Ec(_) => Err("ECDSA signatures must be DER or components".into()),
    }
}

fn signature_from_ec_components(
    r: &[u8],
    s: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Signature> {
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

impl Signature {
    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::EcdsaP256(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            Self::EcdsaP384(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Self::EcdsaP521(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521),
            Self::RsaPssSha384(_) => {
                SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384)
            }
        }
    }
}
