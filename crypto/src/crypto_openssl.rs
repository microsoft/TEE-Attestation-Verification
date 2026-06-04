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
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier as OpenSslVerifier};
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;
use openssl_sys::{
    ASN1_STRING_get0_data, ASN1_STRING_length, X509_EXTENSION_get_data, X509_get_ext,
    X509_get_ext_by_OBJ,
};

use super::signature as signature_types;
use super::{
    CertificateBackend, CryptoBackend, DigestAlgorithm, EcSignatureKeyAlgorithm, Result,
    RsaPssSignatureKeyAlgorithm, Signature, SignatureBackend, SignatureEncoding,
    SignatureKeyAlgorithm,
};

pub struct Crypto;

type Certificate = openssl::x509::X509;

pub struct Key {
    key: PKey<Public>,
    verification: OpenSslKeyVerification,
}

enum OpenSslKeyVerification {
    EcdsaP384 { digest: MessageDigest },
    RsaPssSha384 { digest: MessageDigest },
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
    pub fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let key = PKey::public_key_from_der(spki_der)?;
        let verification = OpenSslKeyVerification::from_key_algorithm(&key, algorithm)?;

        Ok(Key { key, verification })
    }

    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.verification.algorithm()
    }

    pub fn verify(&self, signed_bytes: &[u8], signature: &Signature<'_>) -> Result<()> {
        let signature = self.verification.signature_bytes(&signature)?;
        let mut verifier = self.verification.verifier(&self.key)?;

        match verifier.verify_oneshot(signature.as_ref(), signed_bytes) {
            Ok(true) => Ok(()),
            Ok(false) => Err(self.verification.failure_message().into()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl OpenSslKeyVerification {
    fn from_key_algorithm(key: &PKey<Public>, algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => {
                key.ec_key()
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Self::EcdsaP384 {
                    digest: message_digest(EcSignatureKeyAlgorithm::P384.digest()),
                })
            }
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
                key.rsa()
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Self::RsaPssSha384 {
                    digest: message_digest(RsaPssSignatureKeyAlgorithm::Ps384.digest()),
                })
            }
            _ => Err(format!("Unsupported OpenSSL signature key algorithm: {algorithm:?}").into()),
        }
    }

    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::EcdsaP384 { .. } => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Self::RsaPssSha384 { .. } => {
                SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384)
            }
        }
    }

    fn signature_bytes<'a>(
        &self,
        signature: &'a Signature<'_>,
    ) -> Result<std::borrow::Cow<'a, [u8]>> {
        match self {
            Self::EcdsaP384 { .. } => signature.as_openssl_ecdsa_p384_der(),
            Self::RsaPssSha384 { .. } => Ok(std::borrow::Cow::Borrowed(
                signature.as_openssl_rsa_pss_raw()?,
            )),
        }
    }

    fn verifier<'key>(&self, key: &'key PKey<Public>) -> Result<OpenSslVerifier<'key>> {
        let digest = self.digest();
        let mut verifier = OpenSslVerifier::new(digest, key)?;

        if matches!(self, Self::RsaPssSha384 { .. }) {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            verifier.set_rsa_mgf1_md(digest)?;
        }

        Ok(verifier)
    }

    fn digest(&self) -> MessageDigest {
        match *self {
            Self::EcdsaP384 { digest } | Self::RsaPssSha384 { digest } => digest,
        }
    }

    fn failure_message(&self) -> &'static str {
        match self {
            Self::EcdsaP384 { .. } => "ECDSA signature verification failed",
            Self::RsaPssSha384 { .. } => "RSA-PSS signature verification failed",
        }
    }
}

impl<'a> signature_types::Signature<'a> {
    fn as_openssl_ecdsa_p384_der(&self) -> Result<std::borrow::Cow<'_, [u8]>> {
        match self.encoding() {
            SignatureEncoding::Der => Ok(std::borrow::Cow::Borrowed(self.bytes())),
            SignatureEncoding::EcdsaFixed => Ok(std::borrow::Cow::Owned(ecdsa_p384_fixed_to_der(
                self.as_openssl_ecdsa_p384_fixed()?,
            )?)),
            SignatureEncoding::Raw => {
                Err("ECDSA verification requires DER or fixed-width signature encoding".into())
            }
        }
    }

    fn as_openssl_ecdsa_p384_fixed(&self) -> Result<&[u8]> {
        if self.encoding() != SignatureEncoding::EcdsaFixed {
            return Err("ECDSA verification requires DER or fixed-width signature encoding".into());
        }

        if self.bytes().len() != 96 {
            return Err(format!(
                "Invalid ECDSA P-384 fixed signature length: expected 96, got {}",
                self.bytes().len()
            )
            .into());
        }

        Ok(self.bytes())
    }

    fn as_openssl_rsa_pss_raw(&self) -> Result<&[u8]> {
        if self.encoding() != SignatureEncoding::Raw {
            return Err("RSA-PSS verification requires raw signature encoding".into());
        }

        Ok(self.bytes())
    }
}

fn ecdsa_p384_fixed_to_der(fixed: &[u8]) -> Result<Vec<u8>> {
    if fixed.len() != 96 {
        return Err(format!(
            "Invalid ECDSA P-384 fixed signature length: expected 96, got {}",
            fixed.len()
        )
        .into());
    }

    let ecdsa_sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&fixed[..48])?,
        BigNum::from_slice(&fixed[48..])?,
    )?;

    Ok(ecdsa_sig.to_der()?)
}

fn message_digest(digest: DigestAlgorithm) -> MessageDigest {
    match digest {
        DigestAlgorithm::Sha256 => MessageDigest::sha256(),
        DigestAlgorithm::Sha384 => MessageDigest::sha384(),
        DigestAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}
