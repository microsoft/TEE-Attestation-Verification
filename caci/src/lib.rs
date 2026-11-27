// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
#![doc(test(attr(deny(warnings), allow(dead_code))))]

//! CACI attestation, UVM endorsement, and TCB endorsement verification.
//!
//! This crate verifies an ACI COSE_Sign1 endorsement against a verified
//! SEV-SNP attestation report and a caller-pinned `did:x509` root of trust.
//!
//! Verification is split into two independent stages plus a final binding step:
//!
//! 1. Verify the SEV-SNP attestation report and AMD endorsements.
//! 2. Authenticate each endorsement and check its issuer, subject, and SVN.
//! 3. Bind the verified artifacts by checking the UVM launch measurement and
//!    the TCB endorsement's watermark against the attestation report.
//!
//! The UVM endorsement is parsed before anything authenticates it, and its
//! size is unchecked: bound untrusted input before calling.
//!

mod didx509;
mod parse;
mod tcb_info;

use attestation::snp::report::{AttestationReport, TcbVersionForGeneration, TcbVersionRaw};
use attestation::snp::verify::{ChainVerification, VerificationError};
use attestation::Generation;
use crypto::CertificateBackend;
#[cfg(async_crypto)]
use crypto::{AsyncCryptoBackend, AsyncKeyBackend};
#[cfg(sync_crypto)]
use crypto::{CryptoBackend, KeyBackend};
use std::collections::BTreeSet;

#[cfg(sync_crypto)]
use didx509::verify_didx509;
#[cfg(async_crypto)]
use didx509::verify_didx509_async;
use parse::{parse_attestation, parse_x5chain_certs, required_bstr, required_int, required_text};

pub use attestation::snp;
pub use cose::CborValue;
pub use tcb_info::AmdSevSnpWatermark;

const fn attestation_report_field_len<const N: usize>(
    _: fn(&AttestationReport) -> &[u8; N],
) -> usize {
    N
}

const SNP_MEASUREMENT_LEN: usize = attestation_report_field_len(|report| &report.measurement);
/// Length of the SNP `HOST_DATA` field.
pub const SNP_HOST_DATA_LEN: usize = attestation_report_field_len(|report| &report.host_data);
/// Length of the SNP `REPORT_DATA` field.
pub const SNP_REPORT_DATA_LEN: usize = attestation_report_field_len(|report| &report.report_data);
const MAX_GUEST_VMPL: u32 = 3;
const JSON_LAUNCH_MEASUREMENT: &str = "x-ms-sevsnpvm-launchmeasurement";
const JSON_GUEST_SVN: &str = "x-ms-sevsnpvm-guestsvn";
const JSON_GUEST_SVN_INT: &str = "x-ms-sevsnpvm-guestsvn-int";

/// Relying-party policy for a UVM or TCB endorsement.
#[derive(Debug, Clone, Copy)]
pub struct EndorsementPolicy<'a> {
    /// Full expected `iss` claim, including the `did:x509` EKU policy.
    pub trusted_iss: &'a str,
    /// Expected signed `sub` claim (the signed `feed` for legacy UVM endorsements).
    pub expected_sub: &'a str,
    /// Minimum signed SVN for this endorsement, not a CPU TCB watermark.
    pub minimum_svn: u64,
}

/// A UVM endorsement authenticated and accepted under its endorsement policy.
#[derive(Debug)]
pub struct VerifiedUvmEndorsement<'a> {
    cose: &'a [u8],
    measurement: [u8; SNP_MEASUREMENT_LEN],
}

impl<'a> VerifiedUvmEndorsement<'a> {
    /// Return the original signed COSE_Sign1 bytes.
    pub fn cose_bytes(&self) -> &'a [u8] {
        self.cose
    }
}

/// A TCB endorsement authenticated and accepted under its endorsement policy.
#[derive(Debug)]
pub struct VerifiedTcbEndorsement<'a> {
    cose: &'a [u8],
    watermarks: Vec<AmdSevSnpWatermark>,
}

impl<'a> VerifiedTcbEndorsement<'a> {
    /// Return the original signed COSE_Sign1 bytes.
    pub fn cose_bytes(&self) -> &'a [u8] {
        self.cose
    }

    /// Return the authenticated SNP entries in the TCB reference info manifest.
    pub fn watermarks(&self) -> &[AmdSevSnpWatermark] {
        &self.watermarks
    }
}

#[derive(Clone, Copy)]
enum SignedDocument {
    UvmEndorsement,
    TcbInfo,
}

fn verified_tcb_endorsement<'a>(
    bytes: &'a [u8],
    document: &CborValue<'_>,
    payload: &[u8],
    policy: &EndorsementPolicy<'_>,
) -> Result<VerifiedTcbEndorsement<'a>, AciError> {
    let sign1 = cose::cose_sign1(document).map_err(AciError::Cose)?;
    let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
    let header = CborValue::parse_nondet(&protected).map_err(AciError::Cose)?;
    let claims = header
        .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
        .map_err(AciError::Cose)?;
    let sub = required_text(
        claims
            .map_at_int(cose::CWT_CLAIMS_SUBJECT)
            .map_err(AciError::Cose)?,
        "TCB sub",
    )?;
    if sub != policy.expected_sub {
        return Err(AciError::Policy(format!(
            "TCB subject {sub:?} does not match expected subject {:?}",
            policy.expected_sub
        )));
    }
    let svn = cwt_svn(claims, "TCB")?;
    if svn < policy.minimum_svn {
        return Err(AciError::Policy(format!(
            "TCB SVN {svn} is below trusted minimum {}",
            policy.minimum_svn
        )));
    }
    Ok(VerifiedTcbEndorsement {
        cose: bytes,
        watermarks: tcb_info::parse_manifest(payload)?,
    })
}

fn cwt_svn(claims: &CborValue<'_>, endorsement: &str) -> Result<u64, AciError> {
    required_int(claims.map_at_str("svn").map_err(AciError::Cose)?, "CWT svn")?
        .try_into()
        .map_err(|_| AciError::Policy(format!("{endorsement} SVN is not a non-negative integer")))
}

fn protected_content_type(protected: &CborValue<'_>) -> Result<String, AciError> {
    protected
        .map_at_int(cose::COSE_HEADER_CONTENT_TYPE)
        .or_else(|_| protected.map_at_int(cose::COSE_HEADER_PREIMAGE_CONTENT_TYPE))
        .map_err(|_| AciError::Cose("protected content type not found".to_string()))
        .and_then(|value| required_text(value, "protected content type"))
}

fn signer_claims(
    protected: &CborValue<'_>,
    document: SignedDocument,
) -> Result<(String, Option<std::time::Duration>), AciError> {
    use std::time::Duration;

    let content_type = protected_content_type(protected)?;
    match (document, content_type.as_str()) {
        (SignedDocument::UvmEndorsement, "application/json")
            if protected.map_at_str("iss").is_ok()
                && protected.map_at_str("signingtime").is_ok() =>
        {
            let issuer =
                required_text(protected.map_at_str("iss").map_err(AciError::Cose)?, "iss")?;
            let signing_time = parse::parse_signing_time(
                protected
                    .map_at_str("signingtime")
                    .map_err(AciError::Cose)?,
            )?;
            Ok((issuer, Some(signing_time)))
        }
        (SignedDocument::UvmEndorsement, "application/octet-stream")
        | (SignedDocument::TcbInfo, tcb_info::CONTENT_TYPE)
            if protected.map_at_int(cose::COSE_HEADER_CWT_CLAIMS).is_ok() =>
        {
            let claims = protected
                .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                .map_err(AciError::Cose)?;
            let issuer = required_text(
                claims
                    .map_at_int(cose::CWT_CLAIMS_ISSUER)
                    .map_err(AciError::Cose)?,
                "CWT iss",
            )?;
            let signing_time = claims
                .map_at_int(cose::CWT_CLAIMS_IAT)
                .ok()
                .map(|iat| {
                    let seconds = match iat {
                        CborValue::Tagged { tag: 1, payload } => {
                            required_int(payload, "CWT iat").ok()
                        }
                        CborValue::Int(seconds) => Some(*seconds),
                        _ => None,
                    };
                    seconds
                        .and_then(|seconds| u64::try_from(seconds).ok())
                        .map(Duration::from_secs)
                        .ok_or_else(|| AciError::Cose(format!("CWT iat invalid {iat:?}")))
                })
                .transpose()?;
            Ok((issuer, signing_time))
        }
        _ => Err(match document {
            SignedDocument::UvmEndorsement => AciError::Measurement(format!(
                "unsupported ACI payload content type {content_type}"
            )),
            SignedDocument::TcbInfo => AciError::Cose(format!(
                "expected protected content type {} and CWT claims for TCB info",
                tcb_info::CONTENT_TYPE
            )),
        }),
    }
}

#[cfg(sync_crypto)]
/// Synchronous staged CACI verification.
///
/// Use this module when the active crypto backend supports synchronous
/// verification:
///
/// ```no_run
/// use tee_attestation_verification_caci::{synchronous as tav, EndorsementPolicy, SNP_HOST_DATA_LEN};
///
/// # fn example(
/// #     attestation: &[u8],
/// #     amd_endorsements: &[&[u8]],
/// #     aci_cose: &[u8],
/// #     tcb_cose: &[u8],
/// #     uvm_policy: &EndorsementPolicy<'_>,
/// #     tcb_policy: &EndorsementPolicy<'_>,
/// #     trusted_caci_execution_policy: [u8; SNP_HOST_DATA_LEN],
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// let report = tav::verify_attestation(
///     attestation,
///     amd_endorsements,
/// )?;
/// let uvm = tav::verify_uvm_endorsement(aci_cose, uvm_policy)?;
/// let tcb = tav::verify_tcb_endorsement(tcb_cose, tcb_policy)?;
/// let verified_report_data = tav::verify_caci_attestation(
///     report,
///     &tcb,
///     vec![trusted_caci_execution_policy],
///     &uvm,
/// )?;
/// # let _ = verified_report_data;
/// # Ok(())
/// # }
/// ```
pub mod synchronous {
    use super::*;

    /// Verify the SEV-SNP attestation report and its AMD endorsements.
    ///
    /// `amd_endorsements` must contain certificate bytes ordered as `[vcek,
    /// ask, ark]`. Successful verification authenticates the report signature,
    /// validates the AMD certificate chain, vcek -> ask -> ark, and checks report
    ///  TCB values against the VCEK certificate.
    pub fn verify_attestation(
        report: &[u8],
        amd_endorsements: &[&[u8]],
    ) -> Result<AttestationReport, AciError> {
        let report = parse_attestation(report)?;
        if amd_endorsements.len() != attestation::snp::AMD_ENDORSEMENT_COUNT {
            return Err(AciError::InvalidAmdEndorsements(format!(
                "expected [vcek, ask, ark], got {} certificate(s)",
                amd_endorsements.len()
            )));
        }
        let [vcek, ask, ark] = amd_endorsements
            .iter()
            .map(|cert| parse::parse_certificate(cert))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| AciError::InvalidAmdEndorsements("".to_string()))?;
        attestation::snp::verify::sync::verify_attestation(
            &report,
            &vcek,
            &ChainVerification::WithProvidedArk {
                ask: &ask,
                ark: &ark,
            },
        )
        .map_err(AciError::AttestationVerification)?;
        Ok(report)
    }

    /// Verify an ACI/UVM endorsement independently of the attestation report.
    ///
    /// This verifies the COSE_Sign1 signature, the `x5chain`, and that the
    /// issuer, chain root, and leaf EKU match `trusted_didx509`. The endorsement size is
    /// unchecked: bound untrusted input before calling.
    pub fn verify_uvm_endorsement_with_root_pin<'a>(
        uvm_endorsement: &'a [u8],
        trusted_didx509: &str,
    ) -> Result<CborValue<'a>, AciError> {
        verify_signed_document(
            uvm_endorsement,
            trusted_didx509,
            SignedDocument::UvmEndorsement,
        )
        .map(|(document, _)| document)
    }

    /// Authenticate the UVM endorsement and enforce its issuer, subject, and SVN.
    /// Bound the size of untrusted input before calling.
    pub fn verify_uvm_endorsement<'a>(
        cose: &'a [u8],
        policy: &EndorsementPolicy<'_>,
    ) -> Result<VerifiedUvmEndorsement<'a>, AciError> {
        let (document, _) =
            verify_signed_document(cose, policy.trusted_iss, SignedDocument::UvmEndorsement)?;
        let measurement = uvm_measurement(&document, policy.expected_sub, policy.minimum_svn)?;
        Ok(VerifiedUvmEndorsement { cose, measurement })
    }

    /// Authenticate the TCB endorsement and enforce its issuer, subject, and SVN.
    /// Does not verify SCITT receipts. Bound untrusted input before calling.
    pub fn verify_tcb_endorsement<'a>(
        cose: &'a [u8],
        policy: &EndorsementPolicy<'_>,
    ) -> Result<VerifiedTcbEndorsement<'a>, AciError> {
        let (document, payload) =
            verify_signed_document(cose, policy.trusted_iss, SignedDocument::TcbInfo)?;
        verified_tcb_endorsement(cose, &document, &payload, policy)
    }

    fn verify_signed_document<'a>(
        bytes: &'a [u8],
        trusted_didx509: &str,
        document: SignedDocument,
    ) -> Result<(CborValue<'a>, Vec<u8>), AciError> {
        let parsed = CborValue::parse_nondet(bytes).map_err(AciError::Cose)?;
        let sign1 = cose::cose_sign1(&parsed).map_err(AciError::Cose)?;
        // sign1 fields
        let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
        let _unprotected = sign1.array_at(1).map_err(AciError::Cose)?;
        let payload = required_bstr(sign1.array_at(2).map_err(AciError::Cose)?, "payload")?;
        let signature = required_bstr(sign1.array_at(3).map_err(AciError::Cose)?, "signature")?;

        let protected_header = CborValue::parse_nondet(&protected).map_err(AciError::Cose)?;
        let x5chain = parse::parse_x5chain(
            protected_header
                .map_at_int(cose::COSE_HEADER_X5CHAIN)
                .map_err(AciError::Cose)?,
        )?;

        let (root, intermediates, leaf) = parse_x5chain_certs(&x5chain)?;
        let intermediate_refs = intermediates.iter().collect::<Vec<_>>();
        let (issuer, signing_time) = signer_claims(&protected_header, document)?;
        verify_didx509(trusted_didx509, &issuer, &x5chain)?;
        <crypto::Crypto as CryptoBackend>::verify_chain(
            &root,
            &intermediate_refs,
            &leaf,
            signing_time,
        )
        .map_err(|e| AciError::Certificate(e.to_string()))?;

        // Verify signature
        let algorithm = cose::signature_key_algorithm_for_cose_alg(required_int(
            protected_header
                .map_at_int(cose::COSE_HEADER_ALG)
                .map_err(AciError::Cose)?,
            "protected alg",
        )?)
        .map_err(AciError::Cose)?;
        let spki = crypto::Crypto::get_public_key(&leaf)
            .map_err(|e| AciError::Certificate(e.to_string()))?;
        let key =
            <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(&spki, algorithm)
                .map_err(|e| AciError::Certificate(e.to_string()))?;
        cose::synchronous::cose_verify1(&key, algorithm, &protected, &payload, &signature)
            .map_err(AciError::Signature)?;

        Ok((parsed, payload))
    }

    /// Verify Confidential CACI relying-party policy over staged verified artifacts.
    ///
    /// [`verify_attestation`] must be used to authenticate the SNP report before
    /// calling this function. Pass endorsements from [`verify_uvm_endorsement`]
    /// and [`verify_tcb_endorsement`].
    ///
    /// `trusted_caci_execution_policy` is the expected SHA-256 digest of the Confidential
    /// ACI security policy loaded into `SNP_HOST_DATA`. The returned value is the
    /// verified `SNP_REPORT_DATA` from the SNP report.
    pub fn verify_caci_attestation(
        attestation: AttestationReport,
        tcb_endorsement: &VerifiedTcbEndorsement<'_>,
        trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
        uvm_endorsement: &VerifiedUvmEndorsement<'_>,
    ) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
        verify_endorsed_caci_attestation(
            attestation,
            tcb_endorsement,
            &trusted_caci_execution_policy,
            uvm_endorsement,
        )
    }

    /// Compatibility path using caller-supplied TCB minima and a separately authenticated UVM COSE.
    pub fn verify_caci_attestation_with_minimum_tcb(
        attestation: AttestationReport,
        minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
        trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
        uvm_endorsement: &CborValue<'_>,
        uvm_feed: &str,
        minimum_svn: u64,
    ) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
        verify_caci_attestation_impl(
            attestation,
            minimum_tcb,
            trusted_caci_execution_policy,
            uvm_endorsement,
            uvm_feed,
            minimum_svn,
        )
    }
}

#[cfg(async_crypto)]
/// Asynchronous staged CACI verification.
///
/// Use this module when the active crypto backend is asynchronous, such as
/// WebCrypto:
///
/// ```no_run
/// use tee_attestation_verification_caci::{asynchronous as tav, EndorsementPolicy, SNP_HOST_DATA_LEN};
///
/// # async fn example(
/// #     attestation: &[u8],
/// #     amd_endorsements: &[&[u8]],
/// #     aci_cose: &[u8],
/// #     tcb_cose: &[u8],
/// #     uvm_policy: &EndorsementPolicy<'_>,
/// #     tcb_policy: &EndorsementPolicy<'_>,
/// #     trusted_caci_execution_policy: [u8; SNP_HOST_DATA_LEN],
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// let report = tav::verify_attestation(
///     attestation,
///     amd_endorsements,
/// ).await?;
/// let uvm = tav::verify_uvm_endorsement(aci_cose, uvm_policy).await?;
/// let tcb = tav::verify_tcb_endorsement(tcb_cose, tcb_policy).await?;
/// let verified_report_data = tav::verify_caci_attestation(
///     report,
///     &tcb,
///     vec![trusted_caci_execution_policy],
///     &uvm,
/// ).await?;
/// # let _ = verified_report_data;
/// # Ok(())
/// # }
/// ```
pub mod asynchronous {
    use super::*;

    /// Verify the SEV-SNP attestation report and its AMD endorsements.
    ///
    /// `amd_endorsements` must contain certificate bytes ordered as `[vcek,
    /// ask, ark]`. Successful verification authenticates the report signature,
    /// validates the AMD certificate chain, and checks report TCB values against
    /// the VCEK certificate. This is stage 1 of the ACI flow.
    pub async fn verify_attestation(
        report: &[u8],
        amd_endorsements: &[&[u8]],
    ) -> Result<AttestationReport, AciError> {
        let report = parse_attestation(report)?;
        let amd_endorsements: &[&[u8]] = amd_endorsements;
        if amd_endorsements.len() != attestation::snp::AMD_ENDORSEMENT_COUNT {
            return Err(AciError::InvalidAmdEndorsements(format!(
                "expected [vcek, ask, ark], got {} certificate(s)",
                amd_endorsements.len()
            )));
        }
        let [vcek, ask, ark] = amd_endorsements
            .iter()
            .map(|cert| parse::parse_certificate(cert))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| AciError::InvalidAmdEndorsements("".to_string()))?;
        attestation::snp::verify::asynchronous::verify_attestation(
            &report,
            &vcek,
            &ChainVerification::WithProvidedArk {
                ask: &ask,
                ark: &ark,
            },
        )
        .await
        .map_err(AciError::AttestationVerification)?;
        Ok(report)
    }

    /// Verify an ACI/UVM endorsement independently of the attestation report.
    ///
    /// This verifies the COSE_Sign1 signature, the `x5chain`, and that the
    /// issuer, chain root, and leaf EKU match `trusted_didx509`. This is stage 2 of the ACI flow;
    /// call [`verify_caci_attestation`] afterwards to bind the UVM
    /// endorsement to the verified attestation report and relying-party policy.
    /// The endorsement size is unchecked: bound untrusted input before
    /// calling.
    pub async fn verify_uvm_endorsement_with_root_pin<'a>(
        uvm_endorsement: &'a [u8],
        trusted_didx509: &str,
    ) -> Result<CborValue<'a>, AciError> {
        verify_signed_document(
            uvm_endorsement,
            trusted_didx509,
            SignedDocument::UvmEndorsement,
        )
        .await
        .map(|(document, _)| document)
    }

    /// Authenticate the UVM endorsement and enforce its issuer, subject, and SVN.
    /// Bound the size of untrusted input before calling.
    pub async fn verify_uvm_endorsement<'a>(
        cose: &'a [u8],
        policy: &EndorsementPolicy<'_>,
    ) -> Result<VerifiedUvmEndorsement<'a>, AciError> {
        let (document, _) =
            verify_signed_document(cose, policy.trusted_iss, SignedDocument::UvmEndorsement)
                .await?;
        let measurement = uvm_measurement(&document, policy.expected_sub, policy.minimum_svn)?;
        Ok(VerifiedUvmEndorsement { cose, measurement })
    }

    /// Authenticate the TCB endorsement and enforce its issuer, subject, and SVN.
    /// Does not verify SCITT receipts. Bound untrusted input before calling.
    pub async fn verify_tcb_endorsement<'a>(
        cose: &'a [u8],
        policy: &EndorsementPolicy<'_>,
    ) -> Result<VerifiedTcbEndorsement<'a>, AciError> {
        let (document, payload) =
            verify_signed_document(cose, policy.trusted_iss, SignedDocument::TcbInfo).await?;
        verified_tcb_endorsement(cose, &document, &payload, policy)
    }

    async fn verify_signed_document<'a>(
        bytes: &'a [u8],
        trusted_didx509: &str,
        document: SignedDocument,
    ) -> Result<(CborValue<'a>, Vec<u8>), AciError> {
        let parsed = CborValue::parse_nondet(bytes).map_err(AciError::Cose)?;
        let sign1 = cose::cose_sign1(&parsed).map_err(AciError::Cose)?;
        // Sign1 fields
        let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
        let _unprotected = sign1.array_at(1).map_err(AciError::Cose)?;
        let payload = required_bstr(sign1.array_at(2).map_err(AciError::Cose)?, "payload")?;
        let signature = required_bstr(sign1.array_at(3).map_err(AciError::Cose)?, "signature")?;

        let protected_header = CborValue::parse_nondet(&protected).map_err(AciError::Cose)?;
        let x5chain = parse::parse_x5chain(
            protected_header
                .map_at_int(cose::COSE_HEADER_X5CHAIN)
                .map_err(AciError::Cose)?,
        )?;
        let (root, intermediates, leaf) = parse_x5chain_certs(&x5chain)?;
        let intermediate_refs = intermediates.iter().collect::<Vec<_>>();
        let (issuer, signing_time) = signer_claims(&protected_header, document)?;
        verify_didx509_async(trusted_didx509, &issuer, &x5chain).await?;
        <crypto::Crypto as AsyncCryptoBackend>::verify_chain(
            &root,
            &intermediate_refs,
            &leaf,
            signing_time,
        )
        .await
        .map_err(|e| AciError::Certificate(e.to_string()))?;

        // Verify signature
        let algorithm = cose::signature_key_algorithm_for_cose_alg(required_int(
            protected_header
                .map_at_int(cose::COSE_HEADER_ALG)
                .map_err(AciError::Cose)?,
            "protected alg",
        )?)
        .map_err(AciError::Cose)?;
        let spki = crypto::Crypto::get_public_key(&leaf)
            .map_err(|e| AciError::Certificate(e.to_string()))?;
        let key = <<crypto::Crypto as AsyncCryptoBackend>::Key as AsyncKeyBackend>::from_spki_der(
            &spki, algorithm,
        )
        .await
        .map_err(|e| AciError::Certificate(e.to_string()))?;
        cose::asynchronous::cose_verify1(&key, algorithm, &protected, &payload, &signature)
            .await
            .map_err(AciError::Signature)?;

        Ok((parsed, payload))
    }

    /// Verify Confidential CACI relying-party policy over staged verified artifacts.
    ///
    /// [`verify_attestation`] must be used to authenticate the SNP report before
    /// calling this function. Pass endorsements from [`verify_uvm_endorsement`]
    /// and [`verify_tcb_endorsement`].
    ///
    /// `trusted_caci_execution_policy` is the expected SHA-256 digest of the Confidential
    /// ACI security policy loaded into `SNP_HOST_DATA`. The returned value is the
    /// verified `SNP_REPORT_DATA` from the SNP report.
    pub async fn verify_caci_attestation(
        attestation: AttestationReport,
        tcb_endorsement: &VerifiedTcbEndorsement<'_>,
        trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
        uvm_endorsement: &VerifiedUvmEndorsement<'_>,
    ) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
        verify_endorsed_caci_attestation(
            attestation,
            tcb_endorsement,
            &trusted_caci_execution_policy,
            uvm_endorsement,
        )
    }

    /// Compatibility path using caller-supplied TCB minima and a separately authenticated UVM COSE.
    pub async fn verify_caci_attestation_with_minimum_tcb(
        attestation: AttestationReport,
        minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
        trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
        uvm_endorsement: &CborValue<'_>,
        uvm_feed: &str,
        minimum_svn: u64,
    ) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
        verify_caci_attestation_impl(
            attestation,
            minimum_tcb,
            trusted_caci_execution_policy,
            uvm_endorsement,
            uvm_feed,
            minimum_svn,
        )
    }
}

fn verify_caci_attestation_impl(
    attestation: AttestationReport,
    minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
    trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
    uvm_endorsement: &CborValue<'_>,
    uvm_feed: &str,
    minimum_svn: u64,
) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
    let mut minimum_tcb_cpuids = BTreeSet::new();
    for (cpuid, _) in &minimum_tcb {
        if !minimum_tcb_cpuids.insert(cpuid.0) {
            return Err(AciError::Policy(format!(
                "duplicate minimum TCB CPUID 0x{}",
                cpuid.hex_str()
            )));
        }
    }

    verify_snp_policy(&attestation, minimum_tcb, false)?;
    let measurement = uvm_measurement(uvm_endorsement, uvm_feed, minimum_svn)?;
    verify_binding(&attestation, &trusted_caci_execution_policy, measurement)
}

fn verify_endorsed_caci_attestation(
    attestation: AttestationReport,
    tcb_endorsement: &VerifiedTcbEndorsement<'_>,
    trusted_caci_execution_policy: &[[u8; SNP_HOST_DATA_LEN]],
    uvm_endorsement: &VerifiedUvmEndorsement<'_>,
) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
    verify_snp_policy(
        &attestation,
        tcb_endorsement.watermarks.iter().map(|w| (w.cpuid, w.tcb)),
        true,
    )?;
    verify_binding(
        &attestation,
        trusted_caci_execution_policy,
        uvm_endorsement.measurement,
    )
}

fn verify_snp_policy(
    attestation: &AttestationReport,
    minimum_tcb: impl IntoIterator<Item = (snp::Cpuid, TcbVersionRaw)>,
    require_watermark: bool,
) -> Result<(), AciError> {
    if attestation.policy().debug() {
        return Err(AciError::Policy(
            "SNP guest policy allows debug mode".to_string(),
        ));
    }

    if attestation.vmpl.get() > MAX_GUEST_VMPL {
        return Err(AciError::Policy(
            "SNP report VMPL is outside the guest range".to_string(),
        ));
    }

    let mut minimum_tcb = minimum_tcb.into_iter().peekable();
    if require_watermark || minimum_tcb.peek().is_some() {
        let generation = attestation
            .cpu_generation()
            .map_err(|e| AciError::Policy(format!("Unsupported SNP CPU generation: {e}")))?;

        let mut matched = false;
        for (cpuid, minimum_tcb) in minimum_tcb {
            let minimum_generation = Generation::from_cpuid(&cpuid).map_err(|e| {
                AciError::Policy(format!("Unsupported minimum TCB CPUID {cpuid:?}: {e}"))
            })?;
            if minimum_generation != generation {
                continue;
            }
            matched = true;
            let minimum_tcb = TcbVersionForGeneration::new(minimum_tcb, generation);
            let reported_tcb = TcbVersionForGeneration::new(attestation.reported_tcb, generation);
            if !matches!(
                minimum_tcb.partial_cmp(&reported_tcb),
                Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
            ) {
                return Err(AciError::Policy(format!(
                    "SNP reported TCB {:?} for generation {} is below trusted minimum {:?}",
                    attestation.reported_tcb, generation, minimum_tcb.tcb
                )));
            }
        }
        if require_watermark && !matched {
            return Err(AciError::Policy(format!(
                "TCB endorsement has no watermark for SNP CPU generation {generation}"
            )));
        }
    }
    Ok(())
}

fn uvm_measurement(
    uvm_endorsement: &CborValue<'_>,
    uvm_feed: &str,
    minimum_svn: u64,
) -> Result<[u8; SNP_MEASUREMENT_LEN], AciError> {
    let sign1 = cose::cose_sign1(uvm_endorsement).map_err(AciError::Cose)?;
    let payload = parse::cose_payload(sign1)?;
    let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
    let protected_header = CborValue::parse_nondet(&protected).map_err(AciError::Cose)?;

    let content_type = protected_content_type(&protected_header)?;
    match content_type.as_str() {
        // Legacy UVM endorsements carry claims in protected headers and a JSON payload.
        "application/json" if protected_header.map_at_str("feed").is_ok() => {
            // feed matches
            let feed = protected_header
                .map_at_str("feed")
                .map_err(|err| AciError::Cose(format!("failed to get feed: {err}")))
                .and_then(|value| required_text(value, "feed"))?;
            if feed != uvm_feed {
                return Err(AciError::Policy(format!(
                    "UVM feed {:?} does not match trusted feed {}",
                    feed, uvm_feed
                )));
            }

            let reference_info = serde_json::from_slice::<serde_json::Value>(&payload)
                .map_err(|e| AciError::Measurement(e.to_string()))?;
            reference_info.as_object().ok_or_else(|| {
                AciError::Measurement("ReferenceInfo payload must be a JSON object".into())
            })?;

            // svn matches
            let svn = parse::json::required_str(&reference_info, JSON_GUEST_SVN)?;
            if svn.is_empty() || !svn.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(AciError::Policy(format!(
                    "UVM SVN {svn:?} is not a non-negative integer"
                )));
            }
            let svn_int = parse::json::required_u64(&reference_info, JSON_GUEST_SVN_INT)?;
            if svn_int < minimum_svn {
                return Err(AciError::Policy(format!(
                    "UVM SVN {svn_int} is below trusted minimum {minimum_svn}"
                )));
            }

            parse::json::required_hex::<SNP_MEASUREMENT_LEN>(
                &reference_info,
                JSON_LAUNCH_MEASUREMENT,
            )
        }
        "application/octet-stream"
            if protected_header
                .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                .is_ok() =>
        {
            let cwt_claims = protected_header
                .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                .map_err(AciError::Cose)?;
            let feed = required_text(
                cwt_claims
                    .map_at_int(cose::CWT_CLAIMS_SUBJECT)
                    .map_err(AciError::Cose)?,
                "CWT sub",
            )?;
            if feed != uvm_feed {
                return Err(AciError::Policy(format!(
                    "UVM feed {:?} does not match trusted feed {}",
                    feed, uvm_feed
                )));
            }

            let svn = cwt_svn(cwt_claims, "UVM")?;
            if svn < minimum_svn {
                return Err(AciError::Policy(format!(
                    "UVM SVN {svn} is below trusted minimum {minimum_svn}"
                )));
            }

            payload.try_into().map_err(|payload: Vec<u8>| {
                AciError::Measurement(format!(
                    "ACI payload measurement must be {SNP_MEASUREMENT_LEN} bytes, got {}",
                    payload.len()
                ))
            })
        }
        other => Err(AciError::Measurement(format!(
            "unsupported ACI payload content type {other}"
        ))),
    }
}

fn verify_binding(
    attestation: &AttestationReport,
    trusted_caci_execution_policy: &[[u8; SNP_HOST_DATA_LEN]],
    measurement: [u8; SNP_MEASUREMENT_LEN],
) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
    if measurement != attestation.measurement {
        return Err(AciError::Measurement(
            "ACI payload measurement does not match attestation measurement".to_string(),
        ));
    }
    if !trusted_caci_execution_policy.contains(&attestation.host_data) {
        return Err(AciError::Policy(
            "SNP HOST_DATA does not match trusted policy".to_string(),
        ));
    }

    Ok(attestation.report_data)
}

/// Error returned when CACI verification fails.
#[derive(Debug)]
pub enum AciError {
    /// The caller did not provide exactly `[vcek, ask, ark]`.
    InvalidAmdEndorsements(String),
    /// The attestation report could not be parsed.
    InvalidAttestation(String),
    /// SEV-SNP attestation verification failed.
    AttestationVerification(VerificationError),
    /// Certificate parsing or verification failed.
    Certificate(String),
    /// DID x509 parsing or root pinning failed.
    DidX509(String),
    /// COSE envelope/header parsing failed.
    Cose(String),
    /// COSE signature verification failed.
    Signature(String),
    /// ACI payload measurement did not match the attestation measurement.
    Measurement(String),
    /// Relying-party policy did not match the verified claims.
    Policy(String),
}

impl std::fmt::Display for AciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAmdEndorsements(e) => write!(f, "Invalid AMD endorsements: {e}"),
            Self::InvalidAttestation(e) => write!(f, "Invalid attestation: {e}"),
            Self::AttestationVerification(e) => write!(f, "Attestation verification failed: {e}"),
            Self::Certificate(e) => write!(f, "Certificate error: {e}"),
            Self::DidX509(e) => write!(f, "DID x509 policy error: {e}"),
            Self::Cose(e) => write!(f, "COSE error: {e}"),
            Self::Signature(e) => write!(f, "COSE signature verification failed: {e}"),
            Self::Measurement(e) => write!(f, "Measurement verification failed: {e}"),
            Self::Policy(e) => write!(f, "Relying-party policy verification failed: {e}"),
        }
    }
}

impl std::error::Error for AciError {}

#[cfg(test)]
mod tests;
