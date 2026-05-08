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
use openssl::ecdsa::EcdsaSig;
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;
use openssl_sys::{
    ASN1_STRING_get0_data, ASN1_STRING_length, X509_EXTENSION_get_data, X509_get_ext,
    X509_get_ext_by_OBJ,
};

use super::verifier::Sync as Verifier;
use super::{CertificateBackend, CryptoBackend, Result};
use crate::snp::report::{AttestationReport, Signature};

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

fn verify_report_sig_ecdsa_p384_sha384(
    cert: &Certificate,
    signed_bytes: &[u8],
    signature: Signature,
) -> Result<()> {
    let msg_hash = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), signed_bytes)?;

    let mut r = signature.r;
    let mut s = signature.s;
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

impl Verifier<AttestationReport> for Certificate {
    fn verify(&self, report: &AttestationReport) -> Result<()> {
        let signed_bytes = report.signed_bytes();
        match report.signature_algo.get() {
            0x0001 => verify_report_sig_ecdsa_p384_sha384(self, signed_bytes, report.signature),
            _ => Err(format!(
                "Unsupported signature algorithm: 0x{:04X}",
                report.signature_algo.get()
            )
            .into()),
        }
    }
}
