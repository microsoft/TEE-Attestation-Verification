// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{parse, AciError, CborValue};
use didx509::{PolicyConfig, ValidationError, ValidationTime};
use std::time::{Duration, UNIX_EPOCH};

pub(crate) fn issuer_and_time(
    protected_header: &CborValue<'_>,
) -> Result<(String, ValidationTime), AciError> {
    let content_type = protected_header
        .map_at_int(cose::COSE_HEADER_CONTENT_TYPE)
        .or_else(|_| protected_header.map_at_int(cose::COSE_HEADER_PREIMAGE_CONTENT_TYPE))
        .map_err(|_| AciError::Cose("protected content type not found".to_string()))
        .and_then(|value| parse::required_text(value, "protected content type"))?;
    let (issuer, signing_time) = match content_type.as_str() {
        "application/json" if protected_header.map_at_str("iss").is_ok() => {
            let issuer = parse::required_text(
                protected_header.map_at_str("iss").map_err(AciError::Cose)?,
                "iss",
            )?;
            let signing_time = protected_header
                .map_at_str("signingtime")
                .ok()
                .map(parse::parse_signing_time)
                .transpose()?;
            (issuer, signing_time)
        }
        "application/octet-stream"
            if protected_header
                .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                .is_ok() =>
        {
            let claims = protected_header
                .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                .map_err(AciError::Cose)?;
            let issuer = parse::required_text(
                claims
                    .map_at_int(cose::CWT_CLAIMS_ISSUER)
                    .map_err(AciError::Cose)?,
                "CWT iss",
            )?;
            let signing_time = claims
                .map_at_int(cose::CWT_CLAIMS_IAT)
                .ok()
                .map(|value| {
                    let seconds = match value {
                        CborValue::Tagged { tag: 1, payload } => {
                            parse::required_int(payload, "CWT iat").map_err(|_| ())
                        }
                        CborValue::Int(seconds) => Ok(*seconds),
                        _ => Err(()),
                    }
                    .and_then(|seconds| seconds.try_into().map_err(|_| ()))
                    .map_err(|_| AciError::Cose(format!("CWT iat invalid {value:?}")))?;
                    Ok(Duration::from_secs(seconds))
                })
                .transpose()?;
            (issuer, signing_time)
        }
        other => {
            return Err(AciError::Measurement(format!(
                "unsupported ACI payload content type {other}"
            )));
        }
    };
    Ok((issuer, validation_time(signing_time)?))
}

fn validation_time(signing_time: Option<Duration>) -> Result<ValidationTime, AciError> {
    match signing_time {
        Some(duration) => UNIX_EPOCH
            .checked_add(duration)
            .map(ValidationTime::At)
            .ok_or_else(|| AciError::Cose("signing time is outside the supported range".into())),
        None => Ok(ValidationTime::Now),
    }
}

fn verify_did_linkage(trusted: &str, issuer: &str) -> Result<(), AciError> {
    // Linkage alone is not validation; callers also validate both complete DIDs.
    let trusted_prefix = trusted
        .split_once("::")
        .map_or(trusted, |(prefix, _)| prefix);
    let issuer_prefix = issuer.split_once("::").map_or(issuer, |(prefix, _)| prefix);
    if issuer_prefix != trusted_prefix {
        return Err(AciError::DidX509(format!(
            "issuer DID prefix {issuer_prefix} does not match trusted DID prefix {trusted_prefix}"
        )));
    }
    Ok(())
}

fn validation_error(error: ValidationError, identity: &str) -> AciError {
    match error {
        ValidationError::InvalidPem { .. }
        | ValidationError::InvalidInput { .. }
        | ValidationError::InvalidChain { .. }
        | ValidationError::InvalidKey { .. } => AciError::Certificate(error.to_string()),
        _ => AciError::DidX509(format!("{identity} DID: {error}")),
    }
}

#[cfg(sync_crypto)]
pub(crate) fn verify_dids(
    trusted: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    time: ValidationTime,
) -> Result<(), AciError> {
    let chain: Vec<_> = x5chain.iter().map(Vec::as_slice).collect();
    didx509::validation_sync::validate_der(trusted, &chain, time, PolicyConfig::default())
        .map_err(|error| validation_error(error, "trusted"))?;
    verify_did_linkage(trusted, issuer)?;
    if issuer != trusted {
        didx509::validation_sync::validate_der(issuer, &chain, time, PolicyConfig::default())
            .map_err(|error| validation_error(error, "issuer"))?;
    }
    Ok(())
}

#[cfg(async_crypto)]
pub(crate) async fn verify_dids_async(
    trusted: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    time: ValidationTime,
) -> Result<(), AciError> {
    let chain: Vec<_> = x5chain.iter().map(Vec::as_slice).collect();
    didx509::validation_async::validate_der(trusted, &chain, time, PolicyConfig::default())
        .await
        .map_err(|error| validation_error(error, "trusted"))?;
    verify_did_linkage(trusted, issuer)?;
    if issuer != trusted {
        didx509::validation_async::validate_der(issuer, &chain, time, PolicyConfig::default())
            .await
            .map_err(|error| validation_error(error, "issuer"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn signing_time_conversion_is_checked() {
        assert_eq!(validation_time(None).unwrap(), ValidationTime::Now);
        for duration in [
            Duration::ZERO,
            Duration::from_secs(1_700_000_000),
            Duration::from_secs(i64::MAX as u64),
            Duration::MAX,
        ] {
            match UNIX_EPOCH.checked_add(duration) {
                Some(time) => assert_eq!(
                    validation_time(Some(duration)).unwrap(),
                    ValidationTime::At(time)
                ),
                None => assert!(matches!(
                    validation_time(Some(duration)),
                    Err(AciError::Cose(message))
                        if message == "signing time is outside the supported range"
                )),
            }
        }
    }
}
