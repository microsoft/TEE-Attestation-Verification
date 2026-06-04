// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable pure-Rust cryptographic backend.
//!
//! This backend is selected when `crypto_pure_rust` is enabled and no
//! target-preferred backend is enabled. It uses pure-Rust crates for X.509
//! certificate parsing, certificate-chain signature checks, and SEV-SNP
//! attestation report signature verification.

use p384::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use rsa::{
    pkcs8::DecodePublicKey,
    pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    RsaPublicKey,
};
use sha2::Sha384;

use super::signature as signature_types;
use super::x509_certificate::{self, Certificate};
use super::{
    CertificateBackend, CryptoBackend, EcSignatureKeyAlgorithm, Result,
    RsaPssSignatureKeyAlgorithm, Signature, SignatureBackend, SignatureEncoding,
    SignatureKeyAlgorithm,
};

pub struct Crypto;

pub enum Key {
    EcdsaP384(EcdsaVerifyingKey),
    RsaPssSha384(PssVerifyingKey<Sha384>),
}

impl SignatureBackend for Crypto {
    type Key = Key;
    type Signature<'a> = signature_types::Signature<'a>;

    fn key_from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self::Key> {
        Key::from_spki_der(spki_der, algorithm)
    }

    fn verify_signature(
        key: &Self::Key,
        signed_bytes: &[u8],
        signature: &Self::Signature<'_>,
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
    let key = <Crypto as SignatureBackend>::key_from_spki_der(
        &issuer_spki,
        subject.signature_algorithm()?,
    )?;
    let signature = Signature::raw(subject.signature_bytes());

    <Crypto as SignatureBackend>::verify_signature(&key, &tbs_bytes, &signature)
}

impl Key {
    pub fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => {
                let key = EcdsaVerifyingKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Key::EcdsaP384(key))
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
            Key::EcdsaP384(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Key::RsaPssSha384(_) => {
                SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384)
            }
        }
    }

    pub fn verify(&self, signed_bytes: &[u8], signature: &Signature<'_>) -> Result<()> {
        match self {
            Key::EcdsaP384(key) => {
                let signature = ecdsa_p384_signature(signature)?;

                use p384::ecdsa::signature::Verifier;
                key.verify(signed_bytes, &signature)
                    .map_err(|e| format!("ECDSA signature verification failed: {:?}", e))?;
                Ok(())
            }
            Key::RsaPssSha384(key) => {
                if signature.encoding() != SignatureEncoding::Raw {
                    return Err("RSA-PSS verification requires raw signature encoding".into());
                }

                let signature = PssSignature::try_from(signature.bytes())
                    .map_err(|e| format!("Failed to parse RSA-PSS signature: {:?}", e))?;

                use rsa::signature::Verifier;
                key.verify(signed_bytes, &signature)
                    .map_err(|e| format!("RSA-PSS signature verification failed: {:?}", e))?;
                Ok(())
            }
        }
    }
}

fn ecdsa_p384_signature(signature: &Signature<'_>) -> Result<EcdsaSignature> {
    match signature.encoding() {
        SignatureEncoding::Der => EcdsaSignature::from_der(signature.bytes())
            .map_err(|e| format!("Failed to parse DER ECDSA signature: {:?}", e).into()),
        SignatureEncoding::EcdsaFixed => {
            let fixed = signature.ecdsa_p384_fixed_bytes()?;
            let r: [u8; 48] = fixed[..48]
                .try_into()
                .map_err(|_| "Invalid r scalar length")?;
            let s: [u8; 48] = fixed[48..]
                .try_into()
                .map_err(|_| "Invalid s scalar length")?;
            EcdsaSignature::from_scalars(r, s).map_err(|e| {
                format!("Failed to parse ECDSA signature from scalars: {:?}", e).into()
            })
        }
        SignatureEncoding::Raw => {
            Err("ECDSA verification requires DER or fixed-width signature encoding".into())
        }
    }
}
