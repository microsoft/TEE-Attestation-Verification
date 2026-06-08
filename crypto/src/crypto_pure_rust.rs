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

use super::verifier::{Async as AsyncVerifier, Sync as Verifier};
use super::x509_certificate::{Certificate, SignatureAlgorithm};
use super::{CertificateBackend, CryptoBackend, ReportSignatureVerifier, Result};

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

impl AsyncVerifier<Certificate> for Certificate {
    async fn verify(&self, subject: &Certificate) -> Result<()> {
        Verifier::verify(self, subject)
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

    fn public_key_algorithm(cert: &Self::Certificate) -> Result<String> {
        Ok(cert.public_key_algorithm())
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

    fn issuer_name_matches_subject(
        cert: &Self::Certificate,
        issuer: &Self::Certificate,
    ) -> Result<bool> {
        cert.issuer_name_matches_subject(issuer)
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        cert.is_valid_at(unix_time)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        Ok(cert.version())
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        cert.extension_criticality(oid)
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        cert.critical_extension_oids()
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
                <Certificate as Verifier<Certificate>>::verify(issuer, *cert)?;
            } else {
                trusted_certs
                    .iter()
                    .find(|trusted| {
                        <Certificate as Verifier<Certificate>>::verify(*trusted, *cert).is_ok()
                    })
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
    r: [u8; 72],
    s: [u8; 72],
) -> Result<()> {
    let vcek_pub = vcek.subject_public_key_bytes();

    let vk = EcdsaVerifyingKey::from_sec1_bytes(vcek_pub)
        .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;

    if r[48..].iter().any(|byte| *byte != 0) {
        return Err(
            "Invalid r scalar padding: upper 24 bytes must be zero for P-384 signatures".into(),
        );
    }
    let mut r_bytes: [u8; 48] = r[..48].try_into().map_err(|_| "Invalid r scalar length")?;
    r_bytes.reverse();
    if s[48..].iter().any(|byte| *byte != 0) {
        return Err(
            "Invalid s scalar padding: upper 24 bytes must be zero for P-384 signatures".into(),
        );
    }
    let mut s_bytes: [u8; 48] = s[..48].try_into().map_err(|_| "Invalid s scalar length")?;
    s_bytes.reverse();

    let sig = p384::ecdsa::Signature::from_scalars(r_bytes, s_bytes)
        .map_err(|e| format!("Failed to parse ECDSA signature from scalars: {:?}", e))?;

    use p384::ecdsa::signature::Verifier;
    vk.verify(signed_bytes, &sig)
        .map_err(|e| format!("Attestation report signature verification failed: {:?}", e))?;
    Ok(())
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
