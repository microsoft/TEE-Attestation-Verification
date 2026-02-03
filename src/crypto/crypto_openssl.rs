use std::vec;

use openssl::ecdsa::EcdsaSig;
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;

use super::{CryptoBackend, Result, Verifier};
use crate::snp::report::{AttestationReport, Signature};

pub struct Crypto;

type Certificate = openssl::x509::X509;

impl CryptoBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_pem(pem).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_der(der).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn verify_chain(
        trusted_certs: Vec<Certificate>,
        untrusted_chain: Vec<Certificate>,
        leaf: Certificate,
    ) -> Result<()> {
        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        for cert in trusted_certs {
            store_builder.add_cert(cert)?;
        }
        store_builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        let store = store_builder.build();
        let mut ctx = openssl::x509::X509StoreContext::new()?;
        let mut chain = Stack::new()?;
        for cert in untrusted_chain.iter() {
            chain.push(cert.to_owned())?;
        }
        match ctx.init(&store, &leaf.to_owned(), &chain, |c| c.verify_cert()) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Certificate verification failed".into()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl Verifier<Certificate> for Certificate {
    fn verify(&self, other: &Certificate) -> Result<()> {
        Crypto::verify_chain(vec![self.to_owned()], vec![], other.to_owned())
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
