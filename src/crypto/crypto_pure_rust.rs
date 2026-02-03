use p384::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use rsa::{
    pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    RsaPublicKey,
};
use sha2::Sha384;
use x509_cert::der::{referenced::OwnedToRef, Encode};

use super::{CryptoBackend, Result, Verifier};
use crate::snp::report::{AttestationReport, Signature};

pub struct Crypto;

type Certificate = x509_cert::Certificate;

mod oid {
    use x509_cert::der::oid::ObjectIdentifier;

    // RSA-PSS (1.2.840.113549.1.1.10)
    pub const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
}

impl Verifier<Certificate> for Certificate {
    fn verify(&self, subject: &Certificate) -> Result<()> {
        // Encode the TBS (to-be-signed) portion of the subject certificate
        let tbs_bytes = subject
            .tbs_certificate
            .to_der()
            .map_err(|e| format!("Failed to encode TBS certificate: {:?}", e))?;

        let sig_bytes = subject.signature.raw_bytes();
        let sig_algo_oid = &subject.signature_algorithm.oid;
        let issuer_spki = &self.tbs_certificate.subject_public_key_info;

        if *sig_algo_oid == oid::RSA_PSS {
            // RSA-PSS with SHA-384
            use rsa::signature::Verifier;

            let rsa_pub = RsaPublicKey::try_from(issuer_spki.owned_to_ref())
                .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;

            let verifying_key = PssVerifyingKey::<Sha384>::new(rsa_pub);

            let sig = PssSignature::try_from(sig_bytes)
                .map_err(|e| format!("Failed to parse RSA-PSS signature: {:?}", e))?;

            verifying_key
                .verify(&tbs_bytes, &sig)
                .map_err(|e| format!("RSA-PSS signature verification failed: {:?}", e))?;

            Ok(())
        } else {
            Err(format!("Unsupported signature algorithm OID: {}", sig_algo_oid).into())
        }
    }
}

impl CryptoBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        use x509_cert::der::DecodePem;
        let pem_str =
            std::str::from_utf8(pem).map_err(|e| format!("Invalid UTF-8 in PEM data: {:?}", e))?;
        Certificate::from_pem(pem_str)
            .map_err(|e| format!("Failed to parse PEM certificate: {:?}", e).into())
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        use x509_cert::der::Decode;
        Certificate::from_der(der)
            .map_err(|e| format!("Failed to parse DER certificate: {:?}", e).into())
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
            .map_err(|e| format!("Failed to encode certificate as DER: {:?}", e).into())
    }

    fn verify_chain(
        trusted_certs: Vec<Certificate>,
        untrusted_chain: Vec<Certificate>,
        leaf: Certificate,
    ) -> Result<()> {
        let untrusted_chain = untrusted_chain.iter().chain(std::iter::once(&leaf));
        let mut prev: Option<&x509_cert::certificate::CertificateInner> = None;
        for cert in untrusted_chain {
            if let Some(issuer) = prev {
                issuer.verify(cert)?;
            } else {
                trusted_certs
                    .iter()
                    .find(|trusted| trusted.verify(cert).is_ok())
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
    let vcek_pub = vcek
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let vk = EcdsaVerifyingKey::from_sec1_bytes(vcek_pub)
        .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;

    // P-384 scalars are 48 bytes each, extract from the 72-byte arrays
    let mut r_bytes: [u8; 48] = signature.r[..48]
        .try_into()
        .map_err(|_| "Invalid r scalar length")?;
    r_bytes.reverse();
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
