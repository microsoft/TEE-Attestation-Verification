// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use attestation::snp::report::{AttestationReport, TryFromBytes};
use cose::CborValue;
use crypto::CertificateBackend;
use std::time::Duration;

use crate::{AciError, MEASUREMENT_LEN};

// https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#host-amd-cert-base64
pub(crate) const AMD_ENDORSEMENT_COUNT: usize = 3;
// RFC 9052, Section 4.2: tagged COSE_Sign1 is CBOR tag 18.
pub(crate) const COSE_SIGN1_TAG: u64 = 18;
// IANA COSE Header Parameters registry / RFC 9052, Section 3.1.
pub(crate) const COSE_HEADER_ALG: i64 = 1;
pub(crate) const COSE_HEADER_CONTENT_TYPE: i64 = 3;
// IANA COSE Header Parameters registry / RFC 9597, Section 2.
pub(crate) const COSE_HEADER_CWT_CLAIMS: i64 = 15;
// IANA COSE Header Parameters registry / RFC 9360, Section 2.
pub(crate) const COSE_HEADER_X5CHAIN: i64 = 33;
// Legacy ACI preimage content-type label. The current IANA COSE Header
// Parameters registry assigns "preimage-content-type" to label 259.
pub(crate) const COSE_HEADER_PREIMAGE_CONTENT_TYPE: i64 = 300;
// IANA CWT Claims registry / RFC 8392, Section 3.1.
pub(crate) const CWT_ISS: i64 = 1;
pub(crate) const CWT_SUB: i64 = 2;
// https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64
pub(crate) const CWT_SVN: &str = "svn";
// https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64
pub(crate) const SIGNING_TIME: &str = "signingtime";
// IANA media type registry / RFC 8259.
const CONTENT_TYPE_JSON: &str = "application/json";
// https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64
const JSON_LAUNCH_MEASUREMENT: &str = "x-ms-sevsnpvm-launchmeasurement";
const JSON_GUEST_SVN: &str = "x-ms-sevsnpvm-guestsvn";
const JSON_GUEST_SVN_INT: &str = "x-ms-sevsnpvm-guestsvn-int";

pub(crate) fn parse_attestation(attestation: &[u8]) -> Result<AttestationReport, AciError> {
    AttestationReport::try_read_from_bytes(attestation)
        .map_err(|e| AciError::InvalidAttestation(format!("{e:?}")))
}

pub(crate) fn parse_amd_endorsements(
    amd_endorsements: &[&[u8]],
) -> Result<[crypto::Certificate; AMD_ENDORSEMENT_COUNT], AciError> {
    if amd_endorsements.len() != AMD_ENDORSEMENT_COUNT {
        return Err(AciError::InvalidAmdEndorsements(format!(
            "expected [vcek, ask, ark], got {} certificate(s)",
            amd_endorsements.len()
        )));
    }

    Ok([
        parse_certificate(amd_endorsements[0])?,
        parse_certificate(amd_endorsements[1])?,
        parse_certificate(amd_endorsements[2])?,
    ])
}

/// Parsed ACI COSE endorsement.
///
/// The enum is versioned so future ACI reference-info formats can be added
/// without changing the shape of existing parsed data.
#[derive(Clone, Debug)]
pub enum ParsedAciCose {
    /// Current Confidential ACI UVM reference-info format.
    V1(ParsedAciCoseV1),
}

/// Parsed V1 ACI COSE endorsement fields.
#[derive(Clone, Debug)]
pub struct ParsedAciCoseV1 {
    /// Serialized COSE protected header map.
    pub protected: Vec<u8>,
    /// COSE payload bytes.
    pub payload: Vec<u8>,
    /// COSE signature bytes.
    pub signature: Vec<u8>,
    /// COSE algorithm identifier from the protected header.
    pub alg: i64,
    /// Payload content type from the protected header.
    pub content_type: String,
    /// X.509 certificate chain from the protected header, leaf first.
    pub x5chain: Vec<Vec<u8>>,
    /// DID x509 issuer claim from the protected header.
    pub issuer: String,
    /// Feed/subject claim from the protected header, when present.
    pub feed: Option<String>,
    /// SVN claim from the protected header, when present.
    pub svn: Option<String>,
    /// COSE signing time used for certificate validity, when present.
    pub signing_time: Option<Duration>,
}

pub fn parse_aci_cose(aci_cose: &[u8]) -> Result<ParsedAciCose, AciError> {
    let envelope = CborValue::from_bytes(aci_cose).map_err(AciError::Cose)?;
    let sign1 = match &envelope {
        // RFC 9052, Section 4.2: COSE_Sign1 may be encoded as CBOR tag 18
        // wrapping the underlying COSE_Sign1 array.
        CborValue::Tagged { tag, payload } if *tag == COSE_SIGN1_TAG => payload.as_ref(),
        // RFC 9052, Section 4.2: COSE_Sign1 itself is a CBOR array.
        CborValue::Array(_) => &envelope,
        _ => {
            return Err(AciError::Cose(
                "expected tagged COSE_Sign1 envelope".to_string(),
            ))
        }
    };
    if sign1.len().map_err(AciError::Cose)? != 4 {
        return Err(AciError::Cose(
            "COSE_Sign1 envelope must contain 4 items".to_string(),
        ));
    }

    let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
    let payload = required_bstr(sign1.array_at(2).map_err(AciError::Cose)?, "payload")?;
    let signature = required_bstr(sign1.array_at(3).map_err(AciError::Cose)?, "signature")?;
    let protected_header = CborValue::from_bytes(&protected).map_err(AciError::Cose)?;

    let alg = required_int(
        protected_header
            .map_at_int(COSE_HEADER_ALG)
            .map_err(AciError::Cose)?,
        "protected alg",
    )?;
    let content_type = protected_header
        .map_at_int(COSE_HEADER_CONTENT_TYPE)
        .or_else(|_| protected_header.map_at_int(COSE_HEADER_PREIMAGE_CONTENT_TYPE))
        .map_err(|_| AciError::Cose("protected content type not found".to_string()))
        .and_then(|value| required_text(value, "protected content type"))?;
    let x5chain = parse_x5chain(
        protected_header
            .map_at_int(COSE_HEADER_X5CHAIN)
            .map_err(AciError::Cose)?,
    )?;
    let signing_time = protected_header
        .map_at_str(SIGNING_TIME)
        .ok()
        .map(parse_signing_time)
        .transpose()?;

    let (issuer, feed, svn) = parse_claims(&protected_header)?;

    Ok(ParsedAciCose::V1(ParsedAciCoseV1 {
        protected,
        payload,
        signature,
        alg,
        content_type,
        x5chain,
        issuer,
        feed,
        svn,
        signing_time,
    }))
}

pub(crate) fn parse_x5chain_certs(
    x5chain: &[Vec<u8>],
) -> Result<
    (
        crypto::Certificate,
        Vec<crypto::Certificate>,
        crypto::Certificate,
    ),
    AciError,
> {
    if x5chain.is_empty() {
        return Err(AciError::Certificate(
            "x5chain must contain at least one certificate".to_string(),
        ));
    }

    let leaf =
        crypto::Crypto::from_der(&x5chain[0]).map_err(|e| AciError::Certificate(e.to_string()))?;
    let root = crypto::Crypto::from_der(x5chain.last().unwrap())
        .map_err(|e| AciError::Certificate(e.to_string()))?;
    let intermediate_certs = if x5chain.len() > 1 {
        &x5chain[1..x5chain.len() - 1]
    } else {
        &[]
    };
    let intermediates = intermediate_certs
        .iter()
        .map(|cert| {
            crypto::Crypto::from_der(cert).map_err(|e| AciError::Certificate(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((root, intermediates, leaf))
}

pub(crate) fn parse_certificates(certs: &[Vec<u8>]) -> Result<Vec<crypto::Certificate>, AciError> {
    certs
        .iter()
        .map(|cert| {
            crypto::Crypto::from_der(cert).map_err(|e| AciError::Certificate(e.to_string()))
        })
        .collect()
}

pub(crate) fn measurement_from_payload(
    payload: &[u8],
    content_type: &str,
) -> Result<ReferenceInfoPayload, AciError> {
    match content_type {
        // https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64
        CONTENT_TYPE_JSON => {
            let json: serde_json::Value = serde_json::from_slice(payload)
                .map_err(|e| AciError::Measurement(e.to_string()))?;
            let object = json.as_object().ok_or_else(|| {
                AciError::Measurement("ReferenceInfo payload must be a JSON object".into())
            })?;

            let measurement = required_json_string(object, JSON_LAUNCH_MEASUREMENT)?;
            if !is_lower_hex(measurement) {
                return Err(AciError::Measurement(format!(
                    "{JSON_LAUNCH_MEASUREMENT} must match ^[0-9a-f]+$"
                )));
            }
            let measurement = hex_to_bytes(measurement).map_err(AciError::Measurement)?;
            let measurement = measurement.try_into().map_err(|bytes: Vec<u8>| {
                AciError::Measurement(format!(
                    "{JSON_LAUNCH_MEASUREMENT} must be {MEASUREMENT_LEN} bytes, got {}",
                    bytes.len()
                ))
            })?;

            let svn = required_json_string(object, JSON_GUEST_SVN)?;
            if svn.is_empty() || !svn.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(AciError::Measurement(format!(
                    "{JSON_GUEST_SVN} must match ^[0-9]+$"
                )));
            }

            let svn_int = object
                .get(JSON_GUEST_SVN_INT)
                .and_then(|value| value.as_u64())
                .ok_or_else(|| {
                    AciError::Measurement(format!("{JSON_GUEST_SVN_INT} must be a JSON integer"))
                })?;
            if svn_int.to_string() != svn {
                return Err(AciError::Measurement(format!(
                    "{JSON_GUEST_SVN_INT} does not match {JSON_GUEST_SVN}"
                )));
            }

            Ok(ReferenceInfoPayload {
                measurement,
                svn: Some(svn.to_string()),
            })
        }
        other => Err(AciError::Measurement(format!(
            "unsupported ACI payload content type {other}"
        ))),
    }
}

#[derive(Debug)]
pub(crate) struct ReferenceInfoPayload {
    pub(crate) measurement: [u8; MEASUREMENT_LEN],
    pub(crate) svn: Option<String>,
}

fn required_json_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, AciError> {
    object
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| AciError::Measurement(format!("ReferenceInfo payload missing {key}")))
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn parse_certificate(cert: &[u8]) -> Result<crypto::Certificate, AciError> {
    crypto::Crypto::from_pem(cert)
        .or_else(|_| crypto::Crypto::from_der(cert))
        .map_err(|e| AciError::Certificate(e.to_string()))
}

fn parse_signing_time(value: &CborValue) -> Result<Duration, AciError> {
    match value {
        CborValue::Tagged { tag: 1, payload } => {
            let signing_time = required_int(payload, SIGNING_TIME)?
                .try_into()
                .map_err(|_| AciError::Cose("signingtime must be non-negative".to_string()))?;
            Ok(Duration::from_secs(signing_time))
        }
        _ => Err(AciError::Cose(
            "signingtime must be a CBOR tag 1 epoch timestamp".to_string(),
        )),
    }
}

fn parse_claims(phdr: &CborValue) -> Result<(String, Option<String>, Option<String>), AciError> {
    if let Ok(cwt) = phdr.map_at_int(COSE_HEADER_CWT_CLAIMS) {
        let issuer = required_text(cwt.map_at_int(CWT_ISS).map_err(AciError::Cose)?, "CWT iss")?;
        let feed = cwt
            .map_at_int(CWT_SUB)
            .ok()
            .map(|value| required_text(value, "CWT sub"))
            .transpose()?;
        let svn = cwt
            .map_at_str(CWT_SVN)
            .ok()
            .map(svn_to_string)
            .transpose()?;
        return Ok((issuer, feed, svn));
    }

    let issuer = required_text(phdr.map_at_str("iss").map_err(AciError::Cose)?, "iss")?;
    let feed = phdr
        .map_at_str("feed")
        .ok()
        .map(|value| required_text(value, "feed"))
        .transpose()?;
    Ok((issuer, feed, None))
}

fn parse_x5chain(value: &CborValue) -> Result<Vec<Vec<u8>>, AciError> {
    match value {
        CborValue::ByteString(cert) => Ok(vec![cert.clone()]),
        CborValue::Array(certs) => {
            if certs.len() < 2 {
                return Err(AciError::Cose(
                    "x5chain array must contain at least two certificates".to_string(),
                ));
            }
            certs
                .iter()
                .map(|value| required_bstr(value, "x5chain certificate"))
                .collect()
        }
        _ => Err(AciError::Cose(
            "x5chain must be a byte string or array of byte strings".to_string(),
        )),
    }
}

fn required_bstr(value: &CborValue, name: &str) -> Result<Vec<u8>, AciError> {
    match value {
        CborValue::ByteString(bytes) => Ok(bytes.clone()),
        _ => Err(AciError::Cose(format!("{name} must be a byte string"))),
    }
}

fn required_text(value: &CborValue, name: &str) -> Result<String, AciError> {
    match value {
        CborValue::TextString(text) => Ok(text.clone()),
        _ => Err(AciError::Cose(format!("{name} must be a text string"))),
    }
}

fn required_int(value: &CborValue, name: &str) -> Result<i64, AciError> {
    match value {
        CborValue::Int(i) => Ok(*i),
        _ => Err(AciError::Cose(format!("{name} must be an integer"))),
    }
}

fn svn_to_string(value: &CborValue) -> Result<String, AciError> {
    match value {
        CborValue::TextString(text) => Ok(text.clone()),
        CborValue::Int(i) if *i >= 0 => Ok(i.to_string()),
        _ => Err(AciError::Cose(
            "CWT svn must be a text string or non-negative integer".to_string(),
        )),
    }
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit {}", byte as char)),
    }
}
