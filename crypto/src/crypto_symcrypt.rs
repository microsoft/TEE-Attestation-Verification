// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SymCrypt cryptographic backend.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs1::RsaPublicKey;
use symcrypt::{
    ecc::{CurveType, EcKey, EcKeyUsage},
    hash::{self, HashAlgorithm},
    rsa::{RsaKey, RsaKeyUsage},
};
use x509_cert::{
    der::{asn1::UintRef, oid::ObjectIdentifier, Decode, Sequence},
    spki::SubjectPublicKeyInfoRef,
};

use super::x509_certificate::{self, Certificate};
use super::x509_policy;
use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

pub enum Key {
    Ec {
        algorithm: EcSignatureKeyAlgorithm,
        key: EcKey,
    },
    Rsa {
        algorithm: SignatureKeyAlgorithm,
        key: RsaKey,
    },
}

pub struct Signature {
    algorithm: SignatureKeyAlgorithm,
    bytes: Vec<u8>,
}

#[derive(Sequence)]
struct DerEcdsaSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let bytes = match algorithm {
            SignatureKeyAlgorithm::Ec(ec_algorithm) => {
                ecdsa_der_to_fixed_width(signature, ec_algorithm)?
            }
            SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
                signature.to_vec()
            }
        };

        Ok(Self { algorithm, bytes })
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let scalar_len = algorithm.scalar_byte_len();
        if r.len() != scalar_len || s.len() != scalar_len {
            return Err(format!(
                "Invalid ECDSA {} component length: expected {}, got r={} s={}",
                algorithm.name(),
                scalar_len,
                r.len(),
                s.len()
            )
            .into());
        }

        let mut bytes = Vec::with_capacity(algorithm.fixed_signature_byte_len());
        bytes.extend_from_slice(r);
        bytes.extend_from_slice(s);
        Ok(Self {
            algorithm: SignatureKeyAlgorithm::Ec(algorithm),
            bytes,
        })
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
            .map_err(|e| format!("Failed to parse public key SPKI: {e:?}"))?;
        let key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or("Public key SPKI bit string is not byte-aligned")?;

        match algorithm {
            SignatureKeyAlgorithm::Ec(ec_algorithm) => {
                if spki.algorithm.oid != oid::EC_PUBLIC_KEY {
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
                if curve_oid != ec_curve_oid(ec_algorithm) {
                    return Err(format!(
                        "EC public key curve does not match requested {} algorithm",
                        ec_algorithm.name()
                    )
                    .into());
                }

                let public_key = uncompressed_ec_public_key(key_bytes, ec_algorithm)?;

                let key = EcKey::set_public_key(
                    ec_curve_type(ec_algorithm),
                    &public_key[1..],
                    EcKeyUsage::EcDsa,
                )
                .map_err(|e| format!("Failed to import SymCrypt EC public key: {e:?}"))?;
                Ok(Self::Ec {
                    algorithm: ec_algorithm,
                    key,
                })
            }
            SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
                if spki.algorithm.oid != oid::RSA_ENCRYPTION {
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
                Ok(Self::Rsa { algorithm, key })
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

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.get_extension_value_by_oid(oid)
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        cert.subject_name()
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        cert.issuer_name()
    }

    fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.subject_name_der()
    }

    fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.issuer_name_der()
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: Duration) -> Result<bool> {
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
        if !compatible_key_and_signature(key.algorithm(), signature.algorithm) {
            return Err(format!(
                "Signature algorithm {:?} does not match key algorithm {:?}",
                signature.algorithm,
                key.algorithm()
            )
            .into());
        }

        let digest_algorithm = signature.algorithm.digest();
        let digest = Self::digest(digest_algorithm, signed_bytes)?;
        match (key, signature.algorithm) {
            (Key::Ec { algorithm, key }, SignatureKeyAlgorithm::Ec(_)) => {
                key.ecdsa_verify(&signature.bytes, &digest).map_err(|e| {
                    format!(
                        "ECDSA {} signature verification failed: {e:?}",
                        algorithm.name()
                    )
                })?
            }
            (Key::Rsa { key, .. }, SignatureKeyAlgorithm::RsaPss(algorithm)) => key
                .pss_verify(
                    &digest,
                    &signature.bytes,
                    hash_algorithm(algorithm.digest()),
                    algorithm.salt_len(),
                )
                .map_err(|e| format!("RSA-PSS signature verification failed: {e:?}"))?,
            (Key::Rsa { key, .. }, SignatureKeyAlgorithm::RsaPkcs1v15(algorithm)) => key
                .pkcs1_verify(
                    &digest,
                    &signature.bytes,
                    hash_algorithm(algorithm.digest()),
                )
                .map_err(|e| format!("RSA PKCS#1 v1.5 signature verification failed: {e:?}"))?,
            _ => return Err("Incompatible key and signature types".into()),
        }

        Ok(())
    }

    fn verify_chain(
        trusted_cert: &Certificate,
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
        unix_time: Option<Duration>,
    ) -> Result<()> {
        x509_certificate::verify_certificate_path(
            verify_certificate_signature,
            trusted_cert,
            untrusted_chain,
            leaf,
        )?;

        let policy_path = std::iter::once(trusted_cert)
            .chain(untrusted_chain.iter().copied())
            .chain(std::iter::once(leaf));
        x509_policy::rfc5280_policy::<Crypto, _>(
            policy_path,
            unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH)?),
        )
    }
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ec { algorithm, .. } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::Rsa { algorithm, .. } => *algorithm,
        }
    }
}

fn verify_certificate_signature(issuer: &Certificate, subject: &Certificate) -> Result<()> {
    let algorithm = subject.signature_algorithm()?;
    let key = Key::from_spki_der(&issuer.public_key_spki_der()?, algorithm)?;
    let signature = Signature::from_bytes(subject.signature_bytes(), algorithm)?;
    Crypto::verify_signature(&key, &signature, &subject.tbs_certificate_der()?)
}

fn ecdsa_der_to_fixed_width(
    signature: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
    let signature = DerEcdsaSignature::from_der(signature)
        .map_err(|e| format!("Failed to parse DER ECDSA signature: {e:?}"))?;
    let scalar_len = algorithm.scalar_byte_len();
    let mut fixed = Vec::with_capacity(algorithm.fixed_signature_byte_len());
    append_fixed_width_integer(&mut fixed, signature.r.as_bytes(), scalar_len, algorithm)?;
    append_fixed_width_integer(&mut fixed, signature.s.as_bytes(), scalar_len, algorithm)?;
    Ok(fixed)
}

fn append_fixed_width_integer(
    output: &mut Vec<u8>,
    integer: &[u8],
    width: usize,
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<()> {
    if integer.len() > width {
        return Err(format!(
            "ECDSA {} signature component exceeds {} bytes",
            algorithm.name(),
            width
        )
        .into());
    }

    output.resize(output.len() + width - integer.len(), 0);
    output.extend_from_slice(integer);
    Ok(())
}

fn ec_curve_type(algorithm: EcSignatureKeyAlgorithm) -> CurveType {
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => CurveType::NistP256,
        EcSignatureKeyAlgorithm::P384 => CurveType::NistP384,
        EcSignatureKeyAlgorithm::P521 => CurveType::NistP521,
    }
}

fn uncompressed_ec_public_key(
    key_bytes: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
    let bytes = match algorithm {
        EcSignatureKeyAlgorithm::P256 => p256::PublicKey::from_sec1_bytes(key_bytes)
            .map(|key| key.to_encoded_point(false).as_bytes().to_vec())
            .map_err(|e| format!("Failed to parse P-256 public key: {e:?}"))?,
        EcSignatureKeyAlgorithm::P384 => p384::PublicKey::from_sec1_bytes(key_bytes)
            .map(|key| key.to_encoded_point(false).as_bytes().to_vec())
            .map_err(|e| format!("Failed to parse P-384 public key: {e:?}"))?,
        EcSignatureKeyAlgorithm::P521 => p521::PublicKey::from_sec1_bytes(key_bytes)
            .map(|key| key.to_encoded_point(false).as_bytes().to_vec())
            .map_err(|e| format!("Failed to parse P-521 public key: {e:?}"))?,
    };
    Ok(bytes)
}

fn ec_curve_oid(algorithm: EcSignatureKeyAlgorithm) -> ObjectIdentifier {
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => oid::P256,
        EcSignatureKeyAlgorithm::P384 => oid::P384,
        EcSignatureKeyAlgorithm::P521 => oid::P521,
    }
}

fn hash_algorithm(algorithm: DigestAlgorithm) -> HashAlgorithm {
    match algorithm {
        DigestAlgorithm::Sha256 => HashAlgorithm::Sha256,
        DigestAlgorithm::Sha384 => HashAlgorithm::Sha384,
        DigestAlgorithm::Sha512 => HashAlgorithm::Sha512,
    }
}

mod oid {
    use x509_cert::der::oid::ObjectIdentifier;

    pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    pub const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    pub const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    pub const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
    pub const RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
}
