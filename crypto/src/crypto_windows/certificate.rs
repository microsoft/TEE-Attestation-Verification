// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crypt32 decodes every length and value. Schema adapters change only a checked
//! single-octet tag on a copy of a complete native-decoded value.

use super::NativeCertificate;
use super::{
    decode, decode_canonical as canonical, encode, native_slice, Crypto32, DecodeType, Result,
};
use crate::x509::{Attribute, CertificateDetails, PublicKey, SubjectAlternativeName};
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::FILETIME;

impl DecodeType for Crypto32::CRYPT_SEQUENCE_OF_ANY {
    const KIND: PCSTR = Crypto32::X509_SEQUENCE_OF_ANY;
}

impl DecodeType for Crypto32::CERT_NAME_VALUE {
    const KIND: PCSTR = Crypto32::X509_NAME_VALUE;
}

impl DecodeType for FILETIME {
    const KIND: PCSTR = Crypto32::X509_CHOICE_OF_TIME;
}

impl DecodeType for PSTR {
    const KIND: PCSTR = Crypto32::X509_OBJECT_IDENTIFIER;
}

impl DecodeType for Crypto32::CRYPT_INTEGER_BLOB {
    const KIND: PCSTR = Crypto32::X509_MULTI_BYTE_INTEGER;
}

fn octets(input: &[u8], tag: u8) -> Result<Vec<u8>> {
    let value = canonical::<Crypto32::CERT_NAME_VALUE>(&retag(input, tag, 0x04)?)?;
    Ok(blob(&value.Value, &value)?.to_vec())
}

fn oid(input: &[u8]) -> Result<String> {
    let value = canonical::<PSTR>(input)?;
    if input.len() > 41 || value.is_null() {
        return Err("OID exceeds the supported representation".into());
    }
    // SAFETY: Crypt32 owns and terminates the dotted-decimal OID.
    let text = unsafe { value.to_string()? };
    for (index, arc) in text.split('.').enumerate() {
        let value: u32 = arc.parse().map_err(|_| "OID arc exceeds u32")?;
        if (index == 0 && value > 2) || (index == 1 && value > 39) {
            return Err("Unsupported OID root arcs".into());
        }
    }
    Ok(text)
}

fn algorithm(input: &[u8]) -> Result<()> {
    let fields = sequence(input)?;
    match fields.as_slice() {
        [id] => {
            oid(id)?;
        }
        [id, parameters] => {
            oid(id)?;
            any(parameters)?;
        }
        _ => return Err("Invalid AlgorithmIdentifier".into()),
    }
    Ok(())
}

fn any(input: &[u8]) -> Result<()> {
    let tag = *input.first().ok_or("Missing ASN.1 value")?;
    if tag & 0xc0 == 0
        && !matches!(
            tag,
            0x01..=0x06
                | 0x09
                | 0x0a
                | 0x0c
                | 0x0d
                | 0x12..=0x18
                | 0x1a
                | 0x1b
                | 0x1e
                | 0x30
                | 0x31
        )
    {
        return Err("Unsupported ASN.1 universal tag".into());
    }
    octets(input, tag)?;
    Ok(())
}

fn bits(input: &[u8]) -> Result<()> {
    let value = canonical::<Crypto32::CRYPT_BIT_BLOB>(input)?;
    // SAFETY: value owns the native bit string.
    let bytes = unsafe { native_slice(value.pbData, value.cbData, &value)? };
    super::validate_bit_blob(&value, bytes)
}

type Name = Vec<Vec<(String, Vec<u8>)>>;

fn name(input: &[u8]) -> Result<Name> {
    sequence(input)?
        .iter()
        .map(|rdn| {
            let attributes = tagged_sequence(rdn, 0x31)?;
            if attributes.windows(2).any(|pair| pair[0] > pair[1]) {
                return Err("Noncanonical RDN attribute order".into());
            }
            attributes
                .iter()
                .map(|attribute| {
                    let fields = sequence(attribute)?;
                    let [id, value] = fields.as_slice() else {
                        return Err("Invalid distinguished-name attribute".into());
                    };
                    any(value)?;
                    Ok((oid(id)?, value.clone()))
                })
                .collect()
        })
        .collect()
}

struct Extension {
    oid: String,
    value: Vec<u8>,
}

fn extensions(input: &[u8]) -> Result<Vec<Extension>> {
    let wrapper = tagged_sequence(input, 0xa3)?;
    let [encoded] = wrapper.as_slice() else {
        return Err("Invalid extensions wrapper".into());
    };
    let mut result: Vec<Extension> = Vec::new();
    for encoded in sequence(encoded)? {
        let fields = sequence(&encoded)?;
        let (id, value) = match fields.as_slice() {
            [id, value] => (id, value),
            [id, critical, value] if critical == b"\x01\x01\xff" => (id, value),
            _ => return Err("Invalid extension or noncanonical critical flag".into()),
        };
        let id = oid(id)?;
        if result.iter().any(|other| other.oid == id) {
            return Err("Duplicate certificate extension".into());
        }
        result.push(Extension {
            oid: id,
            value: octets(value, 0x04)?,
        });
    }
    Ok(result)
}

pub(super) fn certificate_details(context: &NativeCertificate) -> Result<CertificateDetails> {
    let certificate = sequence(context.der()?)?;
    let [tbs, outer_algorithm, signature] = certificate.as_slice() else {
        return Err("Invalid certificate fields".into());
    };
    algorithm(outer_algorithm)?;
    bits(signature)?;
    let fields = sequence(tbs)?;
    let fields = if fields
        .first()
        .is_some_and(|field| field.first() == Some(&0xa0))
    {
        let version = tagged_sequence(&fields[0], 0xa0)?;
        if !matches!(version.as_slice(), [value] if value == b"\x02\x01\x01" || value == b"\x02\x01\x02")
        {
            return Err("Unsupported or noncanonical certificate version".into());
        }
        &fields[1..]
    } else {
        fields.as_slice()
    };
    let [serial, inner_algorithm, issuer, validity, subject, spki, rest @ ..] = fields else {
        return Err("Missing certificate fields".into());
    };
    canonical::<Crypto32::CRYPT_INTEGER_BLOB>(serial)?;
    if octets(serial, 0x02)?.len() > 21 {
        return Err("Certificate serial number exceeds 21 octets".into());
    }
    if inner_algorithm != outer_algorithm {
        return Err("Certificate signature algorithms disagree".into());
    }
    name(issuer)?;
    let validity = sequence(validity)?;
    let [not_before, not_after] = validity.as_slice() else {
        return Err("Invalid certificate validity".into());
    };
    time(not_before)?;
    time(not_after)?;
    let spki = sequence(spki)?;
    let [key_algorithm, key_bits] = spki.as_slice() else {
        return Err("Invalid SubjectPublicKeyInfo".into());
    };
    algorithm(key_algorithm)?;
    bits(key_bits)?;

    let mut remaining = rest;
    for tag in [0x81, 0x82] {
        if remaining
            .first()
            .is_some_and(|value| value.first() == Some(&tag))
        {
            bits(&retag(&remaining[0], tag, 0x03)?)?;
            remaining = &remaining[1..];
        }
    }
    let extensions = match remaining {
        [] => Vec::new(),
        [value] => extensions(value)?,
        _ => return Err("Unexpected certificate fields".into()),
    };
    let subject = name(subject)?
        .into_iter()
        .map(|rdn| {
            rdn.into_iter()
                .map(|(oid, value)| {
                    Ok(Attribute {
                        oid,
                        value: string(&value)?,
                    })
                })
                .collect()
        })
        .collect::<Result<_>>()?;
    let extension = |id: &str| extensions.iter().find(|extension| extension.oid == id);
    Ok(CertificateDetails {
        subject,
        subject_alt_names: extension("2.5.29.17")
            .map(|extension| subject_alt_names(&extension.value))
            .transpose()?,
        extended_key_usage: extension("2.5.29.37")
            .map(|extension| {
                sequence(&extension.value)?
                    .iter()
                    .map(|value| oid(value))
                    .collect()
            })
            .transpose()?,
    })
}

fn subject_alt_names(input: &[u8]) -> Result<Vec<SubjectAlternativeName>> {
    sequence(input)?
        .iter()
        .map(|value| {
            Ok(match value.first().copied() {
                Some(tag @ (0x81 | 0x82 | 0x86)) => {
                    let text = string(&retag(value, tag, 0x16)?)?;
                    match tag {
                        0x81 => SubjectAlternativeName::Email(text),
                        0x82 => SubjectAlternativeName::Dns(text),
                        _ => SubjectAlternativeName::Uri(text),
                    }
                }
                Some(0xa0) => {
                    let fields = tagged_sequence(value, 0xa0)?;
                    let [id, wrapped] = fields.as_slice() else {
                        return Err("Invalid otherName".into());
                    };
                    oid(id)?;
                    let wrapped = tagged_sequence(wrapped, 0xa0)?;
                    let [value] = wrapped.as_slice() else {
                        return Err("Invalid otherName value".into());
                    };
                    any(value)?;
                    SubjectAlternativeName::Other
                }
                Some(0xa4) => {
                    let wrapped = tagged_sequence(value, 0xa4)?;
                    let [value] = wrapped.as_slice() else {
                        return Err("Invalid directoryName".into());
                    };
                    name(value)?;
                    SubjectAlternativeName::Other
                }
                Some(0xa5) => {
                    let fields = tagged_sequence(value, 0xa5)?;
                    let strings = match fields.as_slice() {
                        [party] => vec![(party, 0xa1)],
                        [assigner, party] => vec![(assigner, 0xa0), (party, 0xa1)],
                        _ => return Err("Invalid ediPartyName".into()),
                    };
                    for (value, tag) in strings {
                        let wrapped = tagged_sequence(value, tag)?;
                        let [value] = wrapped.as_slice() else {
                            return Err("Invalid EDI DirectoryString".into());
                        };
                        if !matches!(value.first(), Some(0x0c | 0x13 | 0x14 | 0x1e)) {
                            return Err("Unsupported EDI DirectoryString encoding".into());
                        }
                        string(value)?;
                    }
                    SubjectAlternativeName::Other
                }
                Some(0x87) => {
                    octets(value, 0x87)?;
                    SubjectAlternativeName::Other
                }
                Some(0x88) => {
                    oid(&retag(value, 0x88, 0x06)?)?;
                    SubjectAlternativeName::Other
                }
                _ => return Err("Unsupported subject alternative name".into()),
            })
        })
        .collect()
}

pub(super) fn public_key_components(context: &NativeCertificate) -> Result<PublicKey> {
    let info = &context.info()?.SubjectPublicKeyInfo;
    if info.PublicKey.cUnusedBits != 0 {
        return Err("Public key has unused bits".into());
    }
    // SAFETY: context owns the SPKI bit string and the algorithm identifier.
    let bytes = unsafe { native_slice(info.PublicKey.pbData, info.PublicKey.cbData, context)? };
    let parameters = blob(&info.Algorithm.Parameters, context)?;
    if info.Algorithm.pszObjId.is_null() {
        return Err("Missing public key algorithm".into());
    }
    let id = unsafe { info.Algorithm.pszObjId.to_string()? };
    match id.as_str() {
        "1.2.840.113549.1.1.1" => {
            if !parameters.is_empty() && parameters != b"\x05\x00" {
                return Err("Invalid RSA public key parameters".into());
            }
            // The documented ECC_SIGNATURE/DH_PARAMETERS codec is a SEQUENCE
            // of two unsigned, arbitrary-width INTEGERs, also the PKCS#1 shape.
            let key = canonical::<Crypto32::CERT_ECC_SIGNATURE>(bytes)?;
            let positive = |value: &Crypto32::CRYPT_INTEGER_BLOB| -> Result<Vec<u8>> {
                let little_endian = blob(value, &key)?;
                let mut big_endian = little_endian.iter().rev().copied().collect::<Vec<_>>();
                let first = big_endian
                    .iter()
                    .position(|byte| *byte != 0)
                    .ok_or("RSA key components must be positive")?;
                big_endian.drain(..first);
                Ok(big_endian)
            };
            Ok(PublicKey::Rsa {
                n: positive(&key.r)?,
                e: positive(&key.s)?,
            })
        }
        "1.2.840.10045.2.1" => {
            let (curve, width) = match oid(parameters)?.as_str() {
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

fn blob<'a, O>(value: &Crypto32::CRYPT_INTEGER_BLOB, owner: &'a O) -> Result<&'a [u8]> {
    // SAFETY: callers supply a blob and its owning native allocation.
    unsafe { native_slice(value.pbData, value.cbData, owner) }
}

fn retag(input: &[u8], expected: u8, replacement: u8) -> Result<Vec<u8>> {
    if expected & 0x1f == 0x1f || replacement & 0x1f == 0x1f {
        return Err("Unsupported multi-octet ASN.1 schema tag".into());
    }
    if input.first() != Some(&expected) {
        return Err("Unexpected ASN.1 schema tag".into());
    }
    let mut copy = input.to_vec();
    copy[0] = replacement;
    Ok(copy)
}

fn sequence(input: &[u8]) -> Result<Vec<Vec<u8>>> {
    let value = canonical::<Crypto32::CRYPT_SEQUENCE_OF_ANY>(input)?;
    // SAFETY: the native allocation owns the array and every returned blob.
    unsafe { native_slice(value.rgValue, value.cValue, &value)? }
        .iter()
        .map(|item| Ok(blob(item, &value)?.to_vec()))
        .collect()
}

fn tagged_sequence(input: &[u8], tag: u8) -> Result<Vec<Vec<u8>>> {
    sequence(&retag(input, tag, 0x30)?)
}

fn string(input: &[u8]) -> Result<String> {
    let tag = *input.first().ok_or("Missing string")?;
    // OCTET STRING prevents Crypt32's UTF-8/UTF-16 conversion from replacing
    // invalid characters or losing their original representation.
    let value = canonical::<Crypto32::CERT_NAME_VALUE>(&retag(input, tag, 0x04)?)?;
    let bytes = blob(&value.Value, &value)?;
    match tag {
        0x0c => Ok(std::str::from_utf8(bytes)?.to_owned()),
        0x13 if bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b)) =>
        {
            Ok(std::str::from_utf8(bytes)?.to_owned())
        }
        0x16 | 0x14 if bytes.is_ascii() => Ok(std::str::from_utf8(bytes)?.to_owned()),
        0x1e if bytes.len() % 2 == 0 => bytes
            .chunks_exact(2)
            .map(|pair| {
                let point = u16::from_be_bytes([pair[0], pair[1]]);
                char::from_u32(u32::from(point))
                    .filter(|_| point != u16::MAX)
                    .ok_or_else(|| "Invalid BMPString character".into())
            })
            .collect(),
        _ => Err("Unsupported or invalid distinguished-name string encoding".into()),
    }
}

fn time(input: &[u8]) -> Result<()> {
    let tag = *input.first().ok_or("Missing certificate time")?;
    let length = match tag {
        0x17 => 13,
        0x18 => 15,
        _ => return Err("Unsupported certificate time encoding".into()),
    };
    let text = string(&retag(input, tag, 0x16)?)?;
    if text.len() != length
        || !text.ends_with('Z')
        || !text.as_bytes()[..length - 1].iter().all(u8::is_ascii_digit)
    {
        return Err("Certificate time is not canonical DER".into());
    }
    let value = decode::<FILETIME>(input)?;
    let ticks = u64::from(value.dwLowDateTime) | (u64::from(value.dwHighDateTime) << 32);
    if ticks < super::FILETIME_UNIX_EPOCH_OFFSET_TICKS {
        return Err("Certificate time precedes the supported Unix epoch".into());
    }
    let normalized = encode(Crypto32::X509_CHOICE_OF_TIME, &*value)?;
    let normalized_tag = *normalized
        .first()
        .ok_or("Missing encoded certificate time")?;
    let normalized = string(&retag(&normalized, normalized_tag, 0x16)?)?;
    let expected = if tag == 0x18 && normalized_tag == 0x17 {
        let century = if normalized.as_bytes()[0] >= b'5' {
            "19"
        } else {
            "20"
        };
        format!("{century}{normalized}")
    } else {
        normalized
    };
    if text != expected {
        return Err("Invalid or normalized certificate time".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_schema_adapter_preserves_string_bytes_and_empty_sequences() {
        assert_eq!(sequence(b"\x30\x00").unwrap(), Vec::<Vec<u8>>::new());
        for (input, expected) in [
            (b"\x0c\x04a\0bc".as_slice(), "a\0bc"),
            (b"\x16\x03a\0b", "a\0b"),
            (b"\x14\x03a\0b", "a\0b"),
            (b"\x1e\x04\0a\0\xe9", "a\u{e9}"),
            (b"\x0c\x02\xc3\xa9", "\u{e9}"),
        ] {
            assert_eq!(string(input).unwrap(), expected);
        }
        let nodes = sequence(b"\x30\x05\x82\x03a\0b").unwrap();
        assert_eq!(
            string(&retag(&nodes[0], 0x82, 0x16).unwrap()).unwrap(),
            "a\0b"
        );
        assert!(tagged_sequence(b"\x31\x00", 0x31).unwrap().is_empty());
    }

    #[test]
    fn native_roundtrips_reject_noncanonical_lengths_and_trailing_bytes() {
        for input in [b"\x30\x00\0".as_slice(), b"\x30\x81\x00", b"\x30\x80\0\0"] {
            assert!(sequence(input).is_err(), "{input:x?}");
        }
        for input in [b"\x16\x01a\0".as_slice(), b"\x16\x81\x01a", b"\x16\x01\xff"] {
            assert!(string(input).is_err(), "{input:x?}");
        }
    }

    #[test]
    fn native_time_validation_preserves_generalized_time_before_2050() {
        for input in [
            b"\x17\x0d250101000000Z".as_slice(),
            b"\x18\x0f20250101000000Z",
            b"\x18\x0f20500101000000Z",
        ] {
            time(input).unwrap();
        }
        for input in [
            b"\x18\x0f19690101000000Z".as_slice(),
            b"\x18\x0f20250230000000Z",
            b"\x18\x0d202501010000Z",
            b"\x18\x1320250101000000+0000",
            b"\x18\x0f20250101000000Z\0",
        ] {
            assert!(time(input).is_err(), "{input:x?}");
        }
    }
}
