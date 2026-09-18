// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate metadata decoding for the WebCrypto backend.

use crate::{
    x509::{Attribute, CertificateDetails, PublicKey, SubjectAlternativeName},
    CertificateBackend, Result,
};
use x509_cert::certificate::{CertificateInner, Profile};
use x509_cert::der::{
    asn1::{Any, BmpString, Ia5StringRef, ObjectIdentifier, PrintableStringRef, Utf8StringRef},
    Decode, Encode, Tag, Tagged,
};
use x509_cert::time::Time;

use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};

/// An untrusted certificate decoded without changing its signed time encoding.
pub struct Certificate(CertificateInner<PreserveTime>);

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct PreserveTime;

impl Profile for PreserveTime {
    fn time_encoding(time: Time) -> x509_cert::der::Result<Time> {
        Ok(time)
    }
}

impl Certificate {
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let inner = CertificateInner::<PreserveTime>::from_der(der)?;
        if inner.signature_algorithm() != inner.tbs_certificate().signature() {
            return Err("Certificate signature algorithms disagree".into());
        }
        if inner.to_der()? != der {
            return Err("Certificate is not canonical DER".into());
        }
        let extensions = inner
            .tbs_certificate()
            .extensions()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for (index, extension) in extensions.iter().enumerate() {
            if extensions[..index]
                .iter()
                .any(|other| other.extn_id == extension.extn_id)
            {
                return Err("Duplicate certificate extension".into());
            }
        }
        Ok(Self(inner))
    }

    pub fn from_backend<B: CertificateBackend>(certificate: &B::Certificate) -> Result<Self> {
        Self::from_der(&B::to_der(certificate)?)
    }

    pub fn details(&self) -> Result<CertificateDetails> {
        Ok(CertificateDetails {
            subject: self.subject()?,
            subject_alt_names: self.extension::<SubjectAltName>()?.map(|(_, names)| {
                names
                    .0
                    .into_iter()
                    .map(|name| match name {
                        GeneralName::Rfc822Name(value) => {
                            SubjectAlternativeName::Email(value.as_str().to_owned())
                        }
                        GeneralName::DnsName(value) => {
                            SubjectAlternativeName::Dns(value.as_str().to_owned())
                        }
                        GeneralName::UniformResourceIdentifier(value) => {
                            SubjectAlternativeName::Uri(value.as_str().to_owned())
                        }
                        _ => SubjectAlternativeName::Other,
                    })
                    .collect()
            }),
            extended_key_usage: self
                .extension::<ExtendedKeyUsage>()?
                .map(|(_, usages)| usages.0.into_iter().map(|oid| oid.to_string()).collect()),
        })
    }

    /// Preserve RDN grouping and repeated attributes; interpretation belongs to the caller.
    pub fn subject(&self) -> Result<Vec<Vec<Attribute>>> {
        self.0
            .tbs_certificate()
            .subject()
            .iter_rdn()
            .map(|rdn| {
                rdn.iter()
                    .map(|attribute| {
                        Ok(Attribute {
                            oid: attribute.oid.to_string(),
                            value: attribute_string(&attribute.value)?,
                        })
                    })
                    .collect()
            })
            .collect()
    }

    /// Decode any extension type carrying its ASN.1 OID.
    pub fn extension<'a, T: Decode<'a> + AssociatedOid>(&'a self) -> Result<Option<(bool, T)>> {
        self.0
            .tbs_certificate()
            .extensions()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .find(|extension| extension.extn_id == T::OID)
            .map(|extension| {
                Ok((
                    extension.critical,
                    T::from_der(extension.extn_value.as_bytes())?,
                ))
            })
            .transpose()
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let spki = self.0.tbs_certificate().subject_public_key_info();
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or("Public key has unused bits")?;
        match spki.algorithm.oid.to_string().as_str() {
            "1.2.840.113549.1.1.1" => {
                if spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .is_some_and(|value| !value.is_null())
                {
                    return Err("Invalid RSA public key parameters".into());
                }
                let key = pkcs1::RsaPublicKey::from_der(bytes)?;
                let n = key.modulus.as_bytes().to_vec();
                let e = key.public_exponent.as_bytes().to_vec();
                if n.iter().all(|byte| *byte == 0) || e.iter().all(|byte| *byte == 0) {
                    return Err("RSA key components must be positive".into());
                }
                Ok(PublicKey::Rsa { n, e })
            }
            "1.2.840.10045.2.1" => {
                let oid = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or("EC key requires a named curve")?
                    .decode_as::<ObjectIdentifier>()?;
                let (curve, width) = match oid.to_string().as_str() {
                    "1.2.840.10045.3.1.7" => ("P-256", 32),
                    "1.3.132.0.34" => ("P-384", 48),
                    "1.3.132.0.35" => ("P-521", 66),
                    _ => return Err("Unsupported EC curve".into()),
                };
                if bytes.first() != Some(&4) || bytes.len() != 1 + 2 * width {
                    return Err("Expected an uncompressed EC public key".into());
                }
                Ok(PublicKey::Ec {
                    curve,
                    x: bytes[1..1 + width].to_vec(),
                    y: bytes[1 + width..].to_vec(),
                })
            }
            _ => Err("Unsupported public key algorithm".into()),
        }
    }
}

fn attribute_string(value: &Any) -> Result<String> {
    match value.tag() {
        Tag::Utf8String => Ok(value.decode_as::<Utf8StringRef<'_>>()?.as_str().to_owned()),
        Tag::PrintableString => Ok(value
            .decode_as::<PrintableStringRef<'_>>()?
            .as_str()
            .to_owned()),
        Tag::Ia5String => Ok(value.decode_as::<Ia5StringRef<'_>>()?.as_str().to_owned()),
        Tag::BmpString => Ok(value.decode_as::<BmpString>()?.chars().collect()),
        Tag::TeletexString if value.value().is_ascii() => {
            Ok(std::str::from_utf8(value.value())?.to_owned())
        }
        _ => Err("Unsupported distinguished-name string encoding".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Crypto;
    use x509_cert::ext::pkix::KeyUsage;

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
    fn typed_certificate_decodes_backend_der_and_rejects_trailing_bytes() {
        let cert = Crypto::from_pem(include_bytes!("test_data/milan_ark.pem")).unwrap();
        let mut der = Crypto::to_der(&cert).unwrap();
        let decoded = Certificate::from_der(&der).unwrap();
        assert!(!decoded.subject().unwrap().is_empty());
        assert!(matches!(
            decoded.public_key().unwrap(),
            PublicKey::Rsa { .. }
        ));
        assert!(decoded.extension::<KeyUsage>().unwrap().is_some());
        der.push(0);
        assert!(Certificate::from_der(&der).is_err());
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test::wasm_bindgen_test)]
    fn distinguished_name_strings_preserve_unicode_and_nuls() {
        for (tag, bytes, expected) in [
            (Tag::Utf8String, b"caf\xc3\xa9".as_slice(), "caf\u{e9}"),
            (
                Tag::Utf8String,
                b"trusted\0evil".as_slice(),
                "trusted\0evil",
            ),
            (
                Tag::Ia5String,
                b"user@example.com".as_slice(),
                "user@example.com",
            ),
            (
                Tag::BmpString,
                b"\x00c\x00a\x00f\x00\xe9".as_slice(),
                "caf\u{e9}",
            ),
        ] {
            assert_eq!(
                attribute_string(&Any::new(tag, bytes).unwrap()).unwrap(),
                expected
            );
        }
        for (tag, bytes) in [
            (Tag::Utf8String, b"\xff".as_slice()),
            (Tag::Ia5String, b"\xff".as_slice()),
            (Tag::BmpString, b"\xd8\x00".as_slice()),
            (Tag::TeletexString, b"\xe9".as_slice()),
        ] {
            assert!(attribute_string(&Any::new(tag, bytes).unwrap()).is_err());
        }
    }
}
