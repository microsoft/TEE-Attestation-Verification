// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native OpenSSL-backed cryptographic backend.
//!
//! This backend uses OpenSSL for X.509 certificate parsing and encoding,
//! certificate-chain verification, and SEV-SNP attestation report signature
//! verification. It is the native backend selected when `crypto_openssl` is
//! enabled for a non-`wasm32` target.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1Object, Asn1ObjectRef, Asn1Time};
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::Id as PKeyId;
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;
use openssl_sys::{
    ASN1_STRING_get0_data, ASN1_STRING_length, X509_EXTENSION_get_critical,
    X509_EXTENSION_get_data, X509_EXTENSION_get_object, X509_get_ext, X509_get_ext_by_OBJ,
    X509_get_ext_count,
};
use std::cmp::Ordering;

use super::verifier::{Async as AsyncVerifier, Sync as Verifier};
use super::{CertificateBackend, CryptoBackend, ReportSignatureVerifier, Result};

pub struct Crypto;

type Certificate = openssl::x509::X509;

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

    fn public_key_algorithm(cert: &Self::Certificate) -> Result<String> {
        Ok(match cert.public_key()?.id() {
            PKeyId::RSA => "RSA".to_string(),
            PKeyId::EC => "EC".to_string(),
            other => format!("EVP_PKEY:{}", other.as_raw()),
        })
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

    fn subject_name(cert: &Self::Certificate) -> String {
        format!("{:?}", cert.subject_name())
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        format!("{:?}", cert.issuer_name())
    }

    fn issuer_name_matches_subject(
        cert: &Self::Certificate,
        issuer: &Self::Certificate,
    ) -> Result<bool> {
        Ok(cert
            .issuer_name()
            .try_cmp(issuer.subject_name())
            .map(|ordering| ordering == Ordering::Equal)?)
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        let unix_time = unix_time
            .as_secs()
            .try_into()
            .map_err(|_| "Unix time does not fit OpenSSL time_t")?;
        let unix_time = Asn1Time::from_unix(unix_time)?;

        Ok(cert.not_before().compare(&unix_time)? != Ordering::Greater
            && cert.not_after().compare(&unix_time)? != Ordering::Less)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        cert.version()
            .try_into()
            .map_err(|_| "OpenSSL returned a negative certificate version".into())
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
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

            Ok(Some(X509_EXTENSION_get_critical(extension) != 0))
        }
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        let count = unsafe { X509_get_ext_count(cert.as_ptr()) };
        if count <= 0 {
            return Vec::new();
        }

        (0..count)
            .filter_map(|index| {
                let extension = unsafe { X509_get_ext(cert.as_ptr(), index) };
                if extension.is_null() {
                    return None;
                }

                let critical = unsafe { X509_EXTENSION_get_critical(extension) != 0 };
                if !critical {
                    return None;
                }

                let object = unsafe { X509_EXTENSION_get_object(extension) };
                if object.is_null() {
                    return None;
                }

                Some(unsafe { Asn1ObjectRef::from_ptr(object) }.to_string())
            })
            .collect()
    }
}

impl CryptoBackend for Crypto {
    fn verify_chain(
        trusted_certs: &[&Certificate],
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
    ) -> Result<()> {
        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        for cert in trusted_certs {
            store_builder.add_cert((*cert).to_owned())?;
        }
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

impl Verifier<Certificate> for Certificate {
    fn verify(&self, other: &Certificate) -> Result<()> {
        <Crypto as CryptoBackend>::verify_chain(&[self], &[], other)
    }
}

impl AsyncVerifier<Certificate> for Certificate {
    async fn verify(&self, other: &Certificate) -> Result<()> {
        Verifier::verify(self, other)
    }
}

fn verify_report_sig_ecdsa_p384_sha384(
    cert: &Certificate,
    signed_bytes: &[u8],
    mut r: [u8; 72],
    mut s: [u8; 72],
) -> Result<()> {
    let msg_hash = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), signed_bytes)?;

    // reverse to bring into big-endian format
    r.reverse();
    s.reverse();

    let ecdsa_sig = EcdsaSig::from_private_components(
        openssl::bn::BigNum::from_slice(&r)?,
        openssl::bn::BigNum::from_slice(&s)?,
    )?;

    let pub_key = cert.public_key()?;
    let ec_key = pub_key.ec_key()?;
    match ecdsa_sig.verify(&msg_hash, &ec_key) {
        Ok(true) => Ok(()),
        Ok(false) => Err("ECDSA signature verification failed".into()),
        Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
    }
}

impl ReportSignatureVerifier for Crypto {
    fn verify_ecdsa_p384_sha384_signature(
        cert: &Self::Certificate,
        signed_bytes: &[u8],
        r: [u8; 72],
        s: [u8; 72],
    ) -> Result<()> {
        verify_report_sig_ecdsa_p384_sha384(cert, signed_bytes, r, s)
    }
}
