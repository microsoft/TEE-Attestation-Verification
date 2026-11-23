// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(async_crypto)]
use crypto::AsyncCryptoBackend;
#[cfg(sync_crypto)]
use crypto::CryptoBackend;

use crate::AciError;
use crypto::base64::base64_encode_no_padding;
use crypto::CertificateBackend;

#[cfg(sync_crypto)]
pub(crate) fn verify_didx509_root(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let trusted = parse_didx509(trusted_didx509)?;
    verify_issuer_and_eku(&trusted, issuer, leaf)?;

    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64(root)?;
    verify_didx509_fingerprint(&trusted, &actual_fingerprint)
}

#[cfg(async_crypto)]
pub(crate) async fn verify_didx509_root_async(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let trusted = parse_didx509(trusted_didx509)?;
    verify_issuer_and_eku(&trusted, issuer, leaf)?;

    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64_async(root).await?;
    verify_didx509_fingerprint(&trusted, &actual_fingerprint)
}

fn verify_issuer_and_eku(
    trusted: &ParsedDidX509<'_>,
    issuer: &str,
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    if issuer != trusted.raw {
        return Err(AciError::DidX509(format!(
            "issuer DID {issuer} does not match trusted DID {}",
            trusted.raw
        )));
    }

    // RFC 5280 section 4.2.1.12: id-ce-extKeyUsage.
    let has_eku = crypto::Crypto::get_extension_value_by_oid(leaf, "2.5.29.37")
        .map_err(|e| AciError::Certificate(e.to_string()))?
        .and_then(|extension| extended_key_usage_contains(&extension, &trusted.eku));
    if has_eku != Some(true) {
        return Err(AciError::DidX509(format!(
            "x5chain leaf certificate does not have the extended key usage required by trusted DID {}",
            trusted.raw
        )));
    }

    Ok(())
}

fn verify_didx509_fingerprint(
    trusted: &ParsedDidX509<'_>,
    actual_fingerprint: &str,
) -> Result<(), AciError> {
    if actual_fingerprint != trusted.fingerprint {
        return Err(AciError::DidX509(format!(
            "x5chain root certificate fingerprint does not match trusted DID {}",
            trusted.raw
        )));
    }

    Ok(())
}

pub(crate) struct ParsedDidX509<'a> {
    pub(crate) fingerprint: &'a str,
    /// DER contents octets of the `eku` predicate's OID.
    pub(crate) eku: Vec<u8>,
    pub(crate) raw: &'a str,
}

/// Only `did:x509:0:sha256:<fingerprint>::eku:<oid>` is supported.
pub(crate) fn parse_didx509(did: &str) -> Result<ParsedDidX509<'_>, AciError> {
    let syntax_error =
        || AciError::DidX509("expected did:x509:0:sha256:<fingerprint>::eku:<oid>".to_string());
    let (prefix, predicate) = did.split_once("::").ok_or_else(syntax_error)?;
    let eku = predicate
        .strip_prefix("eku:")
        .and_then(encode_oid)
        .ok_or_else(syntax_error)?;
    let mut tokens = prefix.split(':');
    let scheme = tokens.next();
    let method = tokens.next();
    let version = tokens.next();
    let hash = tokens.next();
    let fingerprint = tokens.next();
    if tokens.next().is_some()
        || scheme != Some("did")
        || method != Some("x509")
        || version != Some("0")
        || hash != Some("sha256")
    {
        return Err(syntax_error());
    }

    let fingerprint =
        fingerprint.ok_or_else(|| AciError::DidX509("missing fingerprint".to_string()))?;
    if fingerprint.is_empty() {
        return Err(AciError::DidX509("empty fingerprint".to_string()));
    }

    Ok(ParsedDidX509 {
        fingerprint,
        eku,
        raw: did,
    })
}

/// Encodes a dotted-decimal OID as DER OBJECT IDENTIFIER contents octets.
fn encode_oid(oid: &str) -> Option<Vec<u8>> {
    let mut arcs = oid.split('.').map(|arc| {
        let canonical = arc == "0" || !arc.starts_with(['0', '+']);
        canonical.then(|| arc.parse::<u128>().ok()).flatten()
    });
    let (first, second) = (arcs.next()??, arcs.next()??);
    if first > 2 || (first < 2 && second >= 40) {
        return None;
    }

    let mut encoded = Vec::new();
    for subidentifier in std::iter::once((first * 40).checked_add(second)).chain(arcs) {
        let subidentifier = subidentifier?;
        let groups = (u128::BITS - subidentifier.leading_zeros())
            .max(1)
            .div_ceil(7);
        encoded.extend((0..groups).rev().map(|group| {
            (subidentifier >> (7 * group)) as u8 & 0x7f | if group > 0 { 0x80 } else { 0 }
        }));
    }
    Some(encoded)
}

/// Returns whether a DER `SEQUENCE OF OBJECT IDENTIFIER` contains `oid`, or
/// `None` if it is malformed.
fn extended_key_usage_contains(extension: &[u8], oid: &[u8]) -> Option<bool> {
    let (mut key_purposes, []) = der_tlv(extension, 0x30)? else {
        return None;
    };
    let mut found = false;
    while !key_purposes.is_empty() {
        let (key_purpose, rest) = der_tlv(key_purposes, 0x06)?;
        found |= key_purpose == oid;
        key_purposes = rest;
    }
    Some(found)
}

/// Splits a DER value with a short-form length (under 128 bytes) off `input`,
/// returning its contents and the rest.
fn der_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&[actual_tag, length], input) = input.split_first_chunk()?;
    (actual_tag == tag && length < 0x80)
        .then(|| input.split_at_checked(length.into()))
        .flatten()
}

#[cfg(sync_crypto)]
pub(crate) fn sha256_base64(bytes: &[u8]) -> Result<String, AciError> {
    let digest = <crypto::Crypto as CryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, bytes)
        .map_err(|e| {
            AciError::DidX509(format!(
                "failed to compute DID x509 SHA-256 fingerprint: {e}"
            ))
        })?;
    Ok(base64_encode_no_padding(&digest))
}

#[cfg(async_crypto)]
async fn sha256_base64_async(bytes: &[u8]) -> Result<String, AciError> {
    let digest =
        <crypto::Crypto as AsyncCryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, bytes)
            .await
            .map_err(|e| {
                AciError::DidX509(format!(
                    "failed to compute DID x509 SHA-256 fingerprint: {e}"
                ))
            })?;
    Ok(base64_encode_no_padding(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1.3.6.1.4.1.311.76.59.1.2
    const EKU: [u8; 11] = [
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4c, 0x3b, 0x01, 0x02,
    ];

    #[test]
    fn encode_oid_produces_der_contents_octets() {
        assert_eq!(encode_oid("1.3.6.1.4.1.311.76.59.1.2").unwrap(), EKU);
        assert_eq!(encode_oid("0.0").unwrap(), [0x00]);
        // X.690 section 8.19.5 example.
        assert_eq!(encode_oid("2.100.3").unwrap(), [0x81, 0x34, 0x03]);

        for oid in [
            "", "1", "1.", "1..2", "3.1", "1.40", "01.3", "1.03", "1.+3", "1.-3", "1.3 ", "1.a",
        ] {
            assert_eq!(encode_oid(oid), None, "{oid:?}");
        }
    }

    #[test]
    fn parse_didx509_supports_only_a_single_eku_predicate() {
        let parsed = parse_didx509("did:x509:0:sha256:abc::eku:1.3.6.1.4.1.311.76.59.1.2").unwrap();
        assert_eq!((parsed.fingerprint, &parsed.eku[..]), ("abc", &EKU[..]));

        for did in [
            "did:x509:0:sha256:abc",
            "did:x509:0:sha256:abc::eku:",
            "did:x509:0:sha256:abc::eku:1.3::eku:1.4",
            "did:x509:0:sha256:abc::subject:CN:x",
            "did:x509:0:sha256:::eku:1.3",
            "did:x509:0:sha384:abc::eku:1.3",
            "did:x509:1:sha256:abc::eku:1.3",
        ] {
            assert!(parse_didx509(did).is_err(), "{did}");
        }
    }

    #[test]
    fn extended_key_usage_contains_compares_whole_oids() {
        let extension = [0x30, 7, 0x06, 2, 0x2a, 0x03, 0x06, 1, 0x2b];
        assert_eq!(
            extended_key_usage_contains(&extension, &[0x2a, 0x03]),
            Some(true)
        );
        assert_eq!(extended_key_usage_contains(&extension, &[0x2b]), Some(true));
        assert_eq!(
            extended_key_usage_contains(&extension, &[0x2a]),
            Some(false)
        );
        assert_eq!(
            extended_key_usage_contains(&extension, &[0x03]),
            Some(false)
        );

        let malformed: [&[u8]; 6] = [
            &[],
            // Not a SEQUENCE.
            &[0x31, 3, 0x06, 1, 0x2a],
            // Element is not an OBJECT IDENTIFIER.
            &[0x30, 3, 0x04, 1, 0x2a],
            // Trailing bytes.
            &[0x30, 3, 0x06, 1, 0x2a, 0x00],
            // Truncated.
            &[0x30, 4, 0x06, 1, 0x2a],
            // Long-form length.
            &[0x30, 0x81, 3, 0x06, 1, 0x2a],
        ];
        for der in malformed {
            assert_eq!(extended_key_usage_contains(der, &[0x2a]), None, "{der:x?}");
        }
    }
}
