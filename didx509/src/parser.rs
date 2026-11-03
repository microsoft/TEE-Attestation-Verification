// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[derive(Debug)]
pub(crate) struct ParsedDid<'a> {
    pub id: &'a str,
    pub algorithm: FingerprintAlgorithm,
    pub fingerprint: Vec<u8>,
    pub predicates: Vec<Predicate>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FingerprintAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug)]
pub(crate) enum Predicate {
    Subject(Vec<(String, String)>),
    San { kind: SanKind, value: String },
    Eku(String),
    FulcioIssuer(String),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SanKind {
    Email,
    Dns,
    Uri,
}

impl SanKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Dns => "dns",
            Self::Uri => "uri",
        }
    }
}

pub(crate) fn parse(did: &str) -> Result<ParsedDid<'_>, String> {
    let (id, fragment) = did.split_once('#').unwrap_or((did, ""));
    validate_fragment(fragment)?;
    if id.bytes().any(|byte| matches!(byte, b'/' | b'?')) {
        return Err("paths and queries are not supported".into());
    }
    let (prefix, predicates) = id.split_once("::").ok_or("missing predicates")?;
    let mut prefix = prefix.split(':');
    if prefix.next() != Some("did") || prefix.next() != Some("x509") || prefix.next() != Some("0") {
        return Err("expected did:x509 version 0".into());
    }
    let (algorithm, length) = match prefix.next() {
        Some("sha256") => (FingerprintAlgorithm::Sha256, 32),
        Some("sha384") => (FingerprintAlgorithm::Sha384, 48),
        Some("sha512") => (FingerprintAlgorithm::Sha512, 64),
        _ => return Err("unsupported fingerprint algorithm".into()),
    };
    let fingerprint = decode_base64url(prefix.next().ok_or("missing fingerprint")?)?;
    if prefix.next().is_some() || fingerprint.len() != length {
        return Err("fingerprint does not match its algorithm".into());
    }
    Ok(ParsedDid {
        id,
        algorithm,
        fingerprint,
        predicates: predicates
            .split("::")
            .map(parse_predicate)
            .collect::<Result<_, _>>()?,
    })
}

fn parse_predicate(input: &str) -> Result<Predicate, String> {
    let parts: Vec<_> = input.split(':').collect();
    match parts.as_slice() {
        ["subject", fields @ ..] if !fields.is_empty() && fields.len() % 2 == 0 => {
            let mut attributes = Vec::new();
            for pair in fields.chunks_exact(2) {
                let oid = subject_oid(pair[0]).ok_or("unknown subject key")?;
                if attributes.iter().any(|(key, _)| key == oid) {
                    return Err("duplicate subject field".into());
                }
                attributes.push((oid.to_owned(), decode_component(pair[1])?));
            }
            Ok(Predicate::Subject(attributes))
        }
        ["san", kind, value] => {
            let kind = match *kind {
                "email" => SanKind::Email,
                "dns" => SanKind::Dns,
                "uri" => SanKind::Uri,
                _ => return Err("unsupported SAN type".into()),
            };
            Ok(Predicate::San {
                kind,
                value: decode_component(value)?,
            })
        }
        ["eku", oid] if is_oid(oid) => Ok(Predicate::Eku((*oid).to_owned())),
        ["fulcio-issuer", issuer] => Ok(Predicate::FulcioIssuer(decode_component(issuer)?)),
        _ => Err("unknown or malformed predicate".into()),
    }
}

fn subject_oid(key: &str) -> Option<&str> {
    match key {
        "CN" => Some("2.5.4.3"),
        "C" => Some("2.5.4.6"),
        "L" => Some("2.5.4.7"),
        "ST" => Some("2.5.4.8"),
        "STREET" => Some("2.5.4.9"),
        "O" => Some("2.5.4.10"),
        "OU" => Some("2.5.4.11"),
        oid if is_oid(oid) => Some(oid),
        _ => None,
    }
}

fn is_oid(input: &str) -> bool {
    let mut arcs = input.split('.');
    let first = arcs.next();
    let second = arcs.next();
    let canonical_arc = |arc: &str| {
        !arc.is_empty()
            && (arc.len() == 1 || !arc.starts_with('0'))
            && arc.bytes().all(|byte| byte.is_ascii_digit())
    };
    match (first, second) {
        (Some(first @ ("0" | "1" | "2")), Some(second)) if canonical_arc(second) => {
            (first == "2" || second.parse::<u8>().is_ok_and(|arc| arc <= 39))
                && arcs.all(canonical_arc)
        }
        _ => false,
    }
}

fn decode_component(input: &str) -> Result<String, String> {
    if input.is_empty() {
        return Err("predicate value is empty".into());
    }
    let mut bytes = input.bytes();
    let mut output = Vec::with_capacity(input.len());
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(hex)
                    .ok_or("malformed percent escape")?;
                let low = bytes
                    .next()
                    .and_then(hex)
                    .ok_or("malformed percent escape")?;
                output.push(high << 4 | low);
            }
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') => {
                output.push(byte);
            }
            _ => return Err("predicate value requires percent encoding".into()),
        }
    }
    String::from_utf8(output).map_err(|_| "predicate value is not UTF-8".into())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_fragment(fragment: &str) -> Result<(), String> {
    let mut bytes = fragment.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                bytes
                    .next()
                    .and_then(hex)
                    .ok_or("invalid fragment escape")?;
                bytes
                    .next()
                    .and_then(hex)
                    .ok_or("invalid fragment escape")?;
            }
            byte if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&byte) => {}
            _ => return Err("invalid URI fragment".into()),
        }
    }
    Ok(())
}

pub(crate) fn decode_base64url(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() || input.len() % 4 == 1 {
        return Err("malformed base64url".into());
    }
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err("malformed base64url".into()),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if accumulator != 0 {
        return Err("non-canonical base64url".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s";

    #[test]
    fn strict_predicate_grammar() {
        for suffix in [
            "::subject:CN:",
            "::san:dns:",
            "::fulcio-issuer:",
            "::subject:S:WA",
            "::subject:CN:a:2.5.4.3:b",
            "::subject:%43N:a",
            "::eku:1%2E2",
            "::eku:1.02",
            "::subject:CN:%FF",
            "::subject:CN:raw~tilde",
            "::san:email:a@b",
            "::eku:1.2:",
            "::subject:CN:a#bad%",
            "::subject:CN:a?query",
        ] {
            assert!(parse(&format!("{PREFIX}{suffix}")).is_err(), "{suffix}");
        }
    }

    #[test]
    fn fragment_is_not_part_of_document_id() {
        let did = format!("{PREFIX}::subject:CN:example%2ecom#key/1?x");
        let parsed = parse(&did).unwrap();
        assert_eq!(parsed.id, format!("{PREFIX}::subject:CN:example%2ecom"));
        assert!(matches!(&parsed.predicates[0], Predicate::Subject(values)
            if values == &[("2.5.4.3".to_owned(), "example.com".to_owned())]));
    }

    #[test]
    fn fingerprints_are_canonical_and_length_checked() {
        for fingerprint in ["", "AA", "AA==", "A", "AB", "A+A_"] {
            let did = format!("did:x509:0:sha256:{fingerprint}::eku:1.2");
            assert!(parse(&did).is_err(), "{fingerprint}");
        }
        assert_eq!(decode_base64url("Zg").unwrap(), b"f");
        assert!(decode_base64url("Zh").is_err());
    }
}
