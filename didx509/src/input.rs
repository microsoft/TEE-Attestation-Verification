// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tee_attestation_verification_crypto::{
    base64::{base64_encode_no_padding, base64_standard_decode},
    Certificate, CertificateBackend, Crypto,
};

use crate::{parser::decode_base64url, ValidationError};

#[derive(Clone, Copy)]
pub(crate) enum Chain<'a> {
    Pem(&'a str),
    X509(&'a str),
    Der(&'a [&'a [u8]]),
}

impl Chain<'_> {
    pub fn parse(self) -> Result<Vec<Certificate>, ValidationError> {
        let parsed = match self {
            Self::Pem(input) => parse_pem(input),
            Self::X509(input) => input
                .split(',')
                .map(|item| decode_base64url(item).and_then(|der| parse_der(&der)))
                .collect(),
            Self::Der(input) => input.iter().map(|der| parse_der(der)).collect(),
        };
        let certificates = parsed.map_err(|message| match self {
            Self::Pem(chain_pem) => ValidationError::InvalidPem {
                chain_pem: chain_pem.to_owned(),
                message,
            },
            _ => ValidationError::InvalidInput { message },
        })?;
        if certificates.is_empty() {
            return Err(match self {
                Self::Pem(chain_pem) => ValidationError::InvalidPem {
                    chain_pem: chain_pem.to_owned(),
                    message: "bundle contains no certificates".into(),
                },
                _ => ValidationError::InvalidInput {
                    message: "chain contains no certificates".into(),
                },
            });
        }
        Ok(certificates)
    }

    pub fn diagnostic(self) -> String {
        match self {
            Self::Pem(input) | Self::X509(input) => input.to_owned(),
            Self::Der(input) => input
                .iter()
                .map(|der| base64_encode_no_padding(der))
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

fn parse_der(der: &[u8]) -> Result<Certificate, String> {
    let certificate = Crypto::from_der(der).map_err(|error| error.to_string())?;
    let encoded = Crypto::to_der(&certificate).map_err(|error| error.to_string())?;
    if encoded != der {
        return Err("expected one complete DER certificate without trailing data".into());
    }
    Ok(certificate)
}

fn parse_pem(mut input: &str) -> Result<Vec<Certificate>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    loop {
        input = input.trim_start_matches(|character: char| character.is_ascii_whitespace());
        if input.is_empty() {
            return Ok(certificates);
        }
        input = input
            .strip_prefix(BEGIN)
            .ok_or("expected certificate PEM block")?;
        let (body, remainder) = input.split_once(END).ok_or("missing PEM end marker")?;
        let body: String = body
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let der = base64_standard_decode(&body)?;
        let canonical = base64_encode_no_padding(&der)
            .replace('-', "+")
            .replace('_', "/");
        if canonical != body.trim_end_matches('=') {
            return Err("non-canonical PEM base64".into());
        }
        certificates.push(parse_der(&der)?);
        input = remainder;
    }
}
