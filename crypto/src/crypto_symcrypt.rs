// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SymCrypt-backed cryptographic backend.
//!
//! This backend uses SymCrypt for synchronous certificate-chain and SEV-SNP
//! attestation report signature verification. Certificate parsing, encoding,
//! and extension inspection use the shared pure-Rust X.509 parser.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pkcs1::RsaPublicKey;
use symcrypt::{
    ecc::{CurveType, EcKey, EcKeyUsage},
    hash::{self, HashAlgorithm},
    rsa::{RsaKey, RsaKeyUsage},
};
use x509_cert::{
    der::{oid::ObjectIdentifier, Decode},
    spki::SubjectPublicKeyInfoRef,
};

use super::x509_certificate::{self, Certificate as X509Certificate};
use super::x509_policy;
use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, RsaPkcs1v15SignatureKeyAlgorithm,
    RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    inner: X509Certificate,
}

pub struct Key {
    key: SymCryptKey,
    algorithm: SignatureKeyAlgorithm,
}

enum SymCryptKey {
    Ec(EcKey),
    Rsa(RsaKey),
}

pub enum Signature {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
        fixed: Vec<u8>,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => Ok(Signature::Ecdsa {
                algorithm,
                fixed: super::ecdsa_signature::ecdsa_der_to_fixed(signature, algorithm)?,
            }),
            SignatureKeyAlgorithm::RsaPss(algorithm) => Ok(Signature::RsaPss {
                algorithm,
                raw: signature.to_vec(),
            }),
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => Ok(Signature::RsaPkcs1v15 {
                algorithm,
                raw: signature.to_vec(),
            }),
        }
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        Ok(Signature::Ecdsa {
            algorithm,
            fixed: super::ecdsa_signature::fixed_from_components(r, s, algorithm)?,
        })
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        Ok(Key {
            key: import_spki_key(spki_der, algorithm)?,
            algorithm,
        })
    }
}

impl Certificate {
    fn from_inner(inner: X509Certificate) -> Self {
        Self { inner }
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        Ok(Certificate::from_inner(X509Certificate::from_pem(pem)?))
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        X509Certificate::from_pem_chain(pem)?
            .into_iter()
            .map(Certificate::from_inner)
            .map(Ok)
            .collect()
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        Ok(Certificate::from_inner(X509Certificate::from_der(der)?))
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.to_der()
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        cert.inner.to_pem()
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.public_key_spki_der()
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.inner.get_extension_value_by_oid(oid)
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        cert.inner.subject_name()
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        cert.inner.issuer_name()
    }

    fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.subject_name_der()
    }

    fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.issuer_name_der()
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: Duration) -> Result<bool> {
        cert.inner.is_valid_at(unix_time)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        Ok(cert.inner.version())
    }

    fn basic_constraints(cert: &Self::Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.inner.basic_constraints()
    }

    fn key_usage(cert: &Self::Certificate) -> Result<Option<super::KeyUsage>> {
        cert.inner.key_usage()
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        cert.inner.extension_criticality(oid)
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        cert.inner.critical_extension_oids()
    }
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.algorithm
    }
}

impl CryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    fn digest(algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(match algorithm {
            DigestAlgorithm::Sha256 => hash::sha256(bytes).to_vec(),
            DigestAlgorithm::Sha384 => hash::sha384(bytes).to_vec(),
            DigestAlgorithm::Sha512 => hash::sha512(bytes).to_vec(),
        })
    }

    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        let signature_algorithm = signature.algorithm();
        if !compatible_key_and_signature(key.algorithm, signature_algorithm) {
            return Err(format!(
                "SymCrypt signature algorithm {signature_algorithm:?} does not match key algorithm {:?}",
                key.algorithm
            )
            .into());
        }

        let digest = Self::digest(signature_algorithm.digest(), signed_bytes)?;
        match (&key.key, signature) {
            (SymCryptKey::Ec(key), Signature::Ecdsa { algorithm, fixed }) => {
                key.ecdsa_verify(fixed, &digest).map_err(|e| {
                    format!(
                        "ECDSA {} signature verification failed: {e:?}",
                        algorithm.name()
                    )
                })?
            }
            (SymCryptKey::Rsa(key), Signature::RsaPss { algorithm, raw }) => key
                .pss_verify(
                    &digest,
                    raw,
                    hash_algorithm(algorithm.digest()),
                    algorithm.salt_len(),
                )
                .map_err(|e| format!("RSA-PSS signature verification failed: {e:?}"))?,
            (SymCryptKey::Rsa(key), Signature::RsaPkcs1v15 { algorithm, raw }) => key
                .pkcs1_verify(&digest, raw, hash_algorithm(algorithm.digest()))
                .map_err(|e| format!("RSA PKCS#1 v1.5 signature verification failed: {e:?}"))?,
            _ => return Err("Incompatible key and signature types".into()),
        }

        Ok(())
    }

    fn verify_chain(
        trusted_cert: &Self::Certificate,
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
        unix_time: Option<Duration>,
    ) -> Result<()> {
        let untrusted_x509 = untrusted_chain
            .iter()
            .map(|cert| &cert.inner)
            .collect::<Vec<_>>();

        x509_certificate::verify_certificate_path(
            verify_x509_certificate_signature,
            &trusted_cert.inner,
            &untrusted_x509,
            &leaf.inner,
        )?;

        let policy_path = std::iter::once(trusted_cert)
            .chain(untrusted_chain.iter().copied())
            .chain(std::iter::once(leaf));
        x509_policy::rfc5280_policy::<Crypto, _>(policy_path, unix_time.unwrap_or(unix_time_now()?))
    }
}

fn unix_time_now() -> Result<Duration> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?)
}

fn verify_x509_certificate_signature(
    issuer: &X509Certificate,
    subject: &X509Certificate,
) -> Result<()> {
    let spki_der = issuer.public_key_spki_der()?;
    let algorithm = subject.signature_algorithm()?;
    let key = <Key as KeyBackend>::from_spki_der(&spki_der, algorithm)?;
    let data = subject.tbs_certificate_der()?;
    let signature =
        <Signature as SignatureBackend>::from_bytes(subject.signature_bytes(), algorithm)?;

    <Crypto as CryptoBackend>::verify_signature(&key, &signature, &data)
}

fn import_spki_key(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<SymCryptKey> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| format!("Failed to parse public key SPKI: {e:?}"))?;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or("Public key SPKI bit string is not byte-aligned")?;

    match algorithm {
        SignatureKeyAlgorithm::Ec(algorithm) => {
            // RFC 5480 section 2.1.1 defines id-ecPublicKey.
            // https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1
            if spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") {
                return Err(
                    format!("Expected EC public key OID, got {}", spki.algorithm.oid).into(),
                );
            }

            let curve_oid = spki
                .algorithm
                .parameters
                .ok_or("EC public key curve parameters are required")?
                .decode_as::<ObjectIdentifier>()
                .map_err(|e| format!("Failed to parse EC curve OID: {e:?}"))?;
            if curve_oid != ec_curve_oid(algorithm) {
                return Err(format!(
                    "EC public key curve does not match requested {} algorithm",
                    algorithm.name()
                )
                .into());
            }

            let expected_len = 1 + 2 * algorithm.scalar_byte_len();
            if key_bytes.len() != expected_len || key_bytes.first() != Some(&0x04) {
                return Err(format!(
                    "An uncompressed SEC1 {} public key is required",
                    algorithm.name()
                )
                .into());
            }

            let key =
                EcKey::set_public_key(ec_curve_type(algorithm), &key_bytes[1..], EcKeyUsage::EcDsa)
                    .map_err(|e| format!("Failed to import SymCrypt EC public key: {e:?}"))?;
            Ok(SymCryptKey::Ec(key))
        }
        SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
            // RFC 8017 appendix A.1 defines rsaEncryption.
            // https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1
            if spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
                return Err(
                    format!("Expected RSA public key OID, got {}", spki.algorithm.oid).into(),
                );
            }
            if spki
                .algorithm
                .parameters
                .map(|parameters| !parameters.is_null())
                .unwrap_or(false)
            {
                return Err("Unsupported RSA public key parameters".into());
            }

            let rsa = RsaPublicKey::from_der(key_bytes)
                .map_err(|e| format!("Failed to parse PKCS#1 RSA public key: {e:?}"))?;
            let key = RsaKey::set_public_key(
                rsa.modulus.as_bytes(),
                rsa.public_exponent.as_bytes(),
                RsaKeyUsage::Sign,
            )
            .map_err(|e| format!("Failed to import SymCrypt RSA public key: {e:?}"))?;
            Ok(SymCryptKey::Rsa(key))
        }
    }
}

impl Signature {
    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm, .. } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Self::RsaPkcs1v15 { algorithm, .. } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }
}

fn ec_curve_type(algorithm: EcSignatureKeyAlgorithm) -> CurveType {
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => CurveType::NistP256,
        EcSignatureKeyAlgorithm::P384 => CurveType::NistP384,
        EcSignatureKeyAlgorithm::P521 => CurveType::NistP521,
    }
}

fn ec_curve_oid(algorithm: EcSignatureKeyAlgorithm) -> ObjectIdentifier {
    // RFC 5480 section 2.1.1.1 defines the secp256r1, secp384r1, and secp521r1 OIDs.
    // https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1.1
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
        EcSignatureKeyAlgorithm::P384 => ObjectIdentifier::new_unwrap("1.3.132.0.34"),
        EcSignatureKeyAlgorithm::P521 => ObjectIdentifier::new_unwrap("1.3.132.0.35"),
    }
}

fn hash_algorithm(algorithm: DigestAlgorithm) -> HashAlgorithm {
    match algorithm {
        DigestAlgorithm::Sha256 => HashAlgorithm::Sha256,
        DigestAlgorithm::Sha384 => HashAlgorithm::Sha384,
        DigestAlgorithm::Sha512 => HashAlgorithm::Sha512,
    }
}
