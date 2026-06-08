// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use x509_cert::der::{
    oid::ObjectIdentifier, pem::LineEnding, referenced::OwnedToRef, Decode, DecodePem, Encode,
    EncodePem,
};
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::Result;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    inner: x509_cert::Certificate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    RsaPss,
}

impl Certificate {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: x509_cert::Certificate::from_pem(pem)?,
        })
    }

    pub fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self>> {
        x509_cert::Certificate::load_pem_chain(pem)?
            .into_iter()
            .map(|inner| Ok(Self { inner }))
            .collect()
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: x509_cert::Certificate::from_der(der)?,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.to_der()?)
    }

    pub fn to_pem(&self) -> Result<String> {
        Ok(self.inner.to_pem(LineEnding::LF)?)
    }

    pub fn public_key_spki_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .to_der()?)
    }

    pub fn public_key_algorithm(&self) -> String {
        let oid = self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string();

        match oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            "1.2.840.113549.1.1.10" => "RSA-PSS".to_string(),
            "1.2.840.10045.2.1" => "EC".to_string(),
            "1.3.101.112" => "Ed25519".to_string(),
            "1.3.101.113" => "Ed448".to_string(),
            _ => oid,
        }
    }

    pub fn get_extension_value_by_oid(&self, oid: &str) -> Result<Option<Vec<u8>>> {
        let oid = ObjectIdentifier::new(oid)?;

        let extensions = match self.inner.tbs_certificate.extensions.as_ref() {
            Some(extensions) => extensions,
            None => return Ok(None),
        };

        Ok(extensions
            .iter()
            .find(|extension| extension.extn_id == oid)
            .map(|extension| extension.extn_value.as_bytes().to_vec()))
    }

    pub fn tbs_certificate_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.tbs_certificate.to_der()?)
    }

    pub fn signature_bytes(&self) -> &[u8] {
        self.inner.signature.raw_bytes()
    }

    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm> {
        parse_signature_algorithm(&self.inner.signature_algorithm)
    }

    #[cfg(feature = "crypto_pure_rust")]
    pub fn subject_public_key_bytes(&self) -> &[u8] {
        self.inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
    }
    pub fn subject_name(&self) -> String {
        self.inner.tbs_certificate.subject.to_string()
    }

    pub fn issuer_name(&self) -> String {
        self.inner.tbs_certificate.issuer.to_string()
    }

    pub fn issuer_name_matches_subject(&self, issuer: &Self) -> Result<bool> {
        Ok(self.inner.tbs_certificate.issuer == issuer.inner.tbs_certificate.subject)
    }

    pub fn is_valid_at(&self, unix_time: std::time::Duration) -> Result<bool> {
        let validity = self.inner.tbs_certificate.validity;
        Ok(validity.not_before.to_unix_duration() <= unix_time
            && unix_time <= validity.not_after.to_unix_duration())
    }

    pub fn version(&self) -> u8 {
        self.inner.tbs_certificate.version as u8
    }

    pub fn extension_criticality(&self, oid: &str) -> Result<Option<bool>> {
        let oid = ObjectIdentifier::new(oid)?;

        Ok(self
            .inner
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .find(|extension| extension.extn_id == oid)
            .map(|extension| extension.critical))
    }

    pub fn critical_extension_oids(&self) -> Vec<String> {
        self.inner
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|extension| extension.critical.then(|| extension.extn_id.to_string()))
            .collect()
    }
}

fn parse_signature_algorithm(algorithm: &AlgorithmIdentifierOwned) -> Result<SignatureAlgorithm> {
    let algorithm_ref = algorithm.owned_to_ref();

    if algorithm_ref.oid == oid::RSA_PSS {
        return Ok(SignatureAlgorithm::RsaPss);
    }

    Err(format!("Unsupported signature algorithm OID: {}", algorithm_ref.oid).into())
}

mod oid {
    use x509_cert::der::oid::ObjectIdentifier;

    pub const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
}

#[cfg(test)]
mod test {
    use x509_cert::der::Encode;

    use super::{Certificate, SignatureAlgorithm};

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");

    fn cert(pem: &[u8]) -> Certificate {
        Certificate::from_pem(pem).unwrap()
    }

    #[test]
    fn from_der_round_trips_from_pem_certificate() {
        let cert = cert(MILAN_VCEK);
        let der = cert.to_der().expect("DER encoding should succeed");
        let reparsed = Certificate::from_der(&der).expect("DER should parse");

        assert_eq!(reparsed.to_der().expect("Reparsed DER should encode"), der);
    }

    #[test]
    fn get_public_key_returns_subject_public_key_info_der() {
        let cert = cert(MILAN_ARK);

        assert_eq!(
            cert.public_key_spki_der()
                .expect("SPKI extraction should succeed"),
            cert.inner
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("SPKI DER should encode")
        );
    }

    #[test]
    fn extension_lookup_returns_expected_bootloader_value() {
        let vcek = cert(MILAN_VCEK);

        let bootloader = vcek
            .get_extension_value_by_oid("1.3.6.1.4.1.3704.1.3.1")
            .expect("BootLoader OID lookup should succeed")
            .expect("BootLoader OID should be present in Milan VCEK");

        assert_eq!(bootloader, vec![0x02, 0x01, 0x04]);
    }

    #[test]
    fn extension_lookup_returns_expected_hwid_value() {
        let vcek = cert(MILAN_VCEK);

        let hwid = vcek
            .get_extension_value_by_oid("1.3.6.1.4.1.3704.1.4")
            .expect("HWID OID lookup should succeed")
            .expect("HWID OID should be present in Milan VCEK");

        assert_eq!(
            hwid,
            [
                79, 251, 92, 180, 253, 89, 79, 63, 238, 101, 40, 252, 63, 177, 3, 112, 187, 56,
                171, 232, 157, 205, 91, 162, 207, 10, 182, 161, 29, 242, 202, 40, 42, 221, 81, 107,
                239, 69, 168, 144, 168, 201, 249, 115, 43, 220, 166, 143, 159, 63, 22, 196, 46,
                132, 96, 48, 168, 0, 41, 93, 190, 177, 155, 165,
            ]
        );
    }

    #[test]
    fn extension_lookup_returns_none_for_missing_oid() {
        let vcek = cert(MILAN_VCEK);

        let missing = vcek
            .get_extension_value_by_oid("1.2.3.4.5.6.7.8.9")
            .expect("Missing OID lookup should not fail");

        assert!(missing.is_none());
    }

    #[test]
    fn extension_lookup_rejects_malformed_oid() {
        let vcek = cert(MILAN_VCEK);

        vcek.get_extension_value_by_oid("not-an-oid")
            .expect_err("Malformed OID should fail");
    }

    #[test]
    fn pem_chain_parsing_preserves_input_order() {
        let mut pem_chain = Vec::new();
        pem_chain.extend_from_slice(MILAN_ASK);
        pem_chain.push(b'\n');
        pem_chain.extend_from_slice(MILAN_ARK);

        let chain = Certificate::from_pem_chain(&pem_chain).expect("PEM chain should parse");

        assert_eq!(chain.len(), 2);
        assert_eq!(
            chain[0].to_der().expect("ASK DER should encode"),
            cert(MILAN_ASK)
                .to_der()
                .expect("ASK fixture DER should encode")
        );
        assert_eq!(
            chain[1].to_der().expect("ARK DER should encode"),
            cert(MILAN_ARK)
                .to_der()
                .expect("ARK fixture DER should encode")
        );
    }

    #[test]
    fn pem_encoding_round_trips_through_from_pem() {
        let cert = cert(MILAN_VCEK);
        let pem = cert.to_pem().expect("PEM encoding should succeed");
        let reparsed = Certificate::from_pem(pem.as_bytes()).expect("PEM should parse");

        assert_eq!(
            reparsed.to_der().expect("Reparsed DER should encode"),
            cert.to_der().expect("Original DER should encode")
        );
    }

    #[test]
    fn signature_algorithm_reports_rsa_pss() {
        let cert = cert(MILAN_VCEK);

        assert_eq!(
            cert.signature_algorithm()
                .expect("Signature algorithm should parse"),
            SignatureAlgorithm::RsaPss
        );
    }
}
