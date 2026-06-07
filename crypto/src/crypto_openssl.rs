// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native OpenSSL-backed cryptographic backend.
//!
//! This backend uses OpenSSL for X.509 certificate parsing and encoding,
//! certificate-chain verification, and SEV-SNP attestation report signature
//! verification. It is the native backend selected when `crypto_openssl` is
//! enabled for a non-`wasm32` target.

use foreign_types::ForeignType;
use openssl::asn1::Asn1Object;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier as OpenSslVerifier};
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;
use openssl_sys::{
    ASN1_STRING_get0_data, ASN1_STRING_length, X509_EXTENSION_get_data, X509_get_ext,
    X509_get_ext_by_OBJ,
};

use super::{
    CertificateBackend, CryptoBackend, DigestAlgorithm, EcSignatureKeyAlgorithm, KeyBackend,
    Result, RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

type Certificate = openssl::x509::X509;

pub struct Key {
    key: PKey<Public>,
    verification: OpenSslKeyVerification,
}

pub enum Signature {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
        der: Vec<u8>,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
}

enum OpenSslKeyVerification {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
        digest: MessageDigest,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        digest: MessageDigest,
    },
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let key = PKey::public_key_from_der(spki_der)?;
        let verification = OpenSslKeyVerification::from_key_algorithm(&key, algorithm)?;

        Ok(Key { key, verification })
    }
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => {
                let der = EcdsaSig::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA signature: {:?}", e))?
                    .to_der()?;
                Ok(Self::Ecdsa { algorithm, der })
            }
            SignatureKeyAlgorithm::RsaPss(algorithm) => Ok(Self::RsaPss {
                algorithm,
                raw: signature.to_vec(),
            }),
        }
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let r = ec_component_from_bytes("r", r, algorithm)?;
        let s = ec_component_from_bytes("s", s, algorithm)?;
        let der = EcdsaSig::from_private_components(r, s)?.to_der()?;

        Ok(Self::Ecdsa { algorithm, der })
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_pem(pem).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        openssl::x509::X509::stack_from_pem(pem)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_der(der).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        let pem = cert
            .to_pem()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        String::from_utf8(pem).map_err(|e| format!("Failed to decode PEM as UTF-8: {:?}", e).into())
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        let pub_key = cert.public_key()?;
        Ok(pub_key.public_key_to_der()?)
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        let oid = Asn1Object::from_str(oid)
            .map_err(|e| format!("Invalid extension OID {}: {:?}", oid, e))?;

        unsafe {
            let index = X509_get_ext_by_OBJ(cert.as_ptr(), oid.as_ptr(), -1);
            if index == -1 {
                return Ok(None);
            }

            let extension = X509_get_ext(cert.as_ptr(), index);
            if extension.is_null() {
                return Err("OpenSSL returned null extension pointer".into());
            }

            let data = X509_EXTENSION_get_data(extension);
            if data.is_null() {
                return Err("OpenSSL returned null extension data".into());
            }

            let len = ASN1_STRING_length(data.cast());
            if len < 0 {
                return Err("OpenSSL returned negative extension length".into());
            }

            let data_ptr = ASN1_STRING_get0_data(data.cast());
            if data_ptr.is_null() {
                return Err("OpenSSL returned null extension bytes".into());
            }

            let bytes = std::slice::from_raw_parts(data_ptr, len as usize).to_vec();
            Ok(Some(bytes))
        }
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
        key.verification.ensure_signature_algorithm(signature)?;
        let signature = signature.as_openssl_bytes();
        let mut verifier = key.verification.verifier(&key.key)?;

        match verifier.verify_oneshot(signature, signed_bytes) {
            Ok(true) => Ok(()),
            Ok(false) => Err(key.verification.failure_message().into()),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn verify_chain(
        trusted_cert: &Certificate,
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
    ) -> Result<()> {
        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        store_builder.add_cert(trusted_cert.to_owned())?;
        store_builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        let store = store_builder.build();
        let mut ctx = openssl::x509::X509StoreContext::new()?;
        let mut chain = Stack::<Certificate>::new()?;
        for cert in untrusted_chain {
            chain.push((*cert).to_owned())?;
        }
        match ctx.init(&store, leaf, &chain, |c| c.verify_cert()) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Certificate verification failed".into()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.verification.algorithm()
    }
}

impl OpenSslKeyVerification {
    fn from_key_algorithm(key: &PKey<Public>, algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => {
                let key = key
                    .ec_key()
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                let curve_name = key
                    .group()
                    .curve_name()
                    .ok_or("ECDSA public key must use a named curve")?;
                let expected_curve_name = ec_curve_nid(algorithm);
                if curve_name != expected_curve_name {
                    return Err(format!(
                        "ECDSA public key curve does not match algorithm {}",
                        algorithm.name()
                    )
                    .into());
                }

                Ok(Self::Ecdsa {
                    algorithm,
                    digest: message_digest(algorithm.digest()),
                })
            }
            SignatureKeyAlgorithm::RsaPss(algorithm) => {
                key.rsa()
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Self::RsaPss {
                    algorithm,
                    digest: message_digest(algorithm.digest()),
                })
            }
        }
    }

    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm, .. } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
        }
    }

    fn ensure_signature_algorithm(&self, signature: &Signature) -> Result<()> {
        let expected = self.algorithm();
        let actual = signature.algorithm();
        if actual != expected {
            return Err(format!(
                "Signature algorithm {actual:?} does not match key algorithm {expected:?}"
            )
            .into());
        }

        Ok(())
    }

    fn verifier<'key>(&self, key: &'key PKey<Public>) -> Result<OpenSslVerifier<'key>> {
        let digest = self.digest();
        let mut verifier = OpenSslVerifier::new(digest, key)?;

        if matches!(self, Self::RsaPss { .. }) {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            verifier.set_rsa_mgf1_md(digest)?;
        }

        Ok(verifier)
    }

    fn digest(&self) -> MessageDigest {
        match *self {
            Self::Ecdsa { digest, .. } | Self::RsaPss { digest, .. } => digest,
        }
    }

    fn failure_message(&self) -> &'static str {
        match self {
            Self::Ecdsa { .. } => "ECDSA signature verification failed",
            Self::RsaPss { .. } => "RSA-PSS signature verification failed",
        }
    }
}

impl Signature {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm, .. } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
        }
    }

    fn as_openssl_bytes(&self) -> &[u8] {
        match self {
            Self::Ecdsa { der, .. } => der,
            Self::RsaPss { raw, .. } => raw,
        }
    }
}

fn ec_component_from_bytes(
    name: &str,
    component: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<BigNum> {
    let max_len = algorithm.scalar_byte_len();
    if component.is_empty() || component.len() > max_len {
        return Err(format!(
            "Invalid ECDSA {} {name} component length: expected 1..={}, got {}",
            algorithm.name(),
            max_len,
            component.len()
        )
        .into());
    }

    Ok(BigNum::from_slice(component)?)
}

fn message_digest(digest: DigestAlgorithm) -> MessageDigest {
    match digest {
        DigestAlgorithm::Sha256 => MessageDigest::sha256(),
        DigestAlgorithm::Sha384 => MessageDigest::sha384(),
        DigestAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

fn ec_curve_nid(algorithm: EcSignatureKeyAlgorithm) -> Nid {
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => Nid::X9_62_PRIME256V1,
        EcSignatureKeyAlgorithm::P384 => Nid::SECP384R1,
        EcSignatureKeyAlgorithm::P521 => Nid::SECP521R1,
    }
}
