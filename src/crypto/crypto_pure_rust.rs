// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable pure-Rust cryptographic backend.
//!
//! This backend is selected when `crypto_pure_rust` is enabled and no
//! target-preferred backend is enabled. It uses pure-Rust crates for X.509
//! certificate parsing, certificate-chain signature checks, and SEV-SNP
//! attestation report signature verification.

use p384::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use rsa::{
    pkcs8::DecodePublicKey,
    pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    RsaPublicKey,
};
use sha2::Sha384;

use super::verifier::Sync as Verifier;
use super::x509_certificate::{Certificate, SignatureAlgorithm};
use super::{CertificateBackend, CryptoBackend, Result};
use crate::snp::report::{AttestationReport, Signature};

pub struct Crypto;

impl Verifier<Certificate> for Certificate {
    fn verify(&self, subject: &Certificate) -> Result<()> {
        let tbs_bytes = subject.tbs_certificate_der()?;
        let sig_bytes = subject.signature_bytes();
        let issuer_spki = self.public_key_spki_der()?;

        match subject.signature_algorithm()? {
            SignatureAlgorithm::RsaPss => {
                use rsa::signature::Verifier;

                let rsa_pub = RsaPublicKey::from_public_key_der(&issuer_spki)
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;

                let verifying_key = PssVerifyingKey::<Sha384>::new(rsa_pub);

                let sig = PssSignature::try_from(sig_bytes)
                    .map_err(|e| format!("Failed to parse RSA-PSS signature: {:?}", e))?;

                verifying_key
                    .verify(&tbs_bytes, &sig)
                    .map_err(|e| format!("RSA-PSS signature verification failed: {:?}", e))?;

                Ok(())
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
}

impl CryptoBackend for Crypto {
    fn verify_chain(
        trusted_certs: &[&Certificate],
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
    ) -> Result<()> {
        let untrusted_chain = untrusted_chain.iter().chain(std::iter::once(&leaf));
        let mut prev: Option<&Certificate> = None;
        for cert in untrusted_chain {
            if let Some(issuer) = prev {
                issuer.verify(*cert)?;
            } else {
                trusted_certs
                    .iter()
                    .find(|trusted| trusted.verify(*cert).is_ok())
                    .ok_or("Failed to verify certificate: no matching trusted issuer")?;
            }
            prev = Some(cert);
        }
        Ok(())
    }
}

fn verify_report_sig_ecdsa_p384_sha384(
    vcek: &Certificate,
    signed_bytes: &[u8],
    signature: Signature,
) -> Result<()> {
    let vcek_pub = vcek.subject_public_key_bytes();

    let vk = EcdsaVerifyingKey::from_sec1_bytes(vcek_pub)
        .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;

    if signature.r[48..].iter().any(|byte| *byte != 0) {
        return Err(
            "Invalid r scalar padding: upper 24 bytes must be zero for P-384 signatures".into(),
        );
    }
    let mut r_bytes: [u8; 48] = signature.r[..48]
        .try_into()
        .map_err(|_| "Invalid r scalar length")?;
    r_bytes.reverse();
    if signature.s[48..].iter().any(|byte| *byte != 0) {
        return Err(
            "Invalid s scalar padding: upper 24 bytes must be zero for P-384 signatures".into(),
        );
    }
    let mut s_bytes: [u8; 48] = signature.s[..48]
        .try_into()
        .map_err(|_| "Invalid s scalar length")?;
    s_bytes.reverse();

    let sig = p384::ecdsa::Signature::from_scalars(r_bytes, s_bytes)
        .map_err(|e| format!("Failed to parse ECDSA signature from scalars: {:?}", e))?;

    use p384::ecdsa::signature::Verifier;
    vk.verify(signed_bytes, &sig)
        .map_err(|e| format!("Attestation report signature verification failed: {:?}", e))?;
    Ok(())
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
