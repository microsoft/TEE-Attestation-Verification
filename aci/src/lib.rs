// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ACI/UVM endorsement verification.
//!
//! This crate verifies an ACI COSE_Sign1 endorsement against a verified
//! SEV-SNP attestation report and a caller-pinned `did:x509` root of trust.
//!
//! Verification is split into two independent stages plus a final binding step:
//!
//! 1. Verify the SEV-SNP attestation report and AMD endorsements.
//! 2. Verify the UVM endorsement COSE, its `x5chain`, and its `did:x509` root.
//! 3. Bind the two verified artifacts by checking that the UVM launch
//!    measurement matches the attestation report measurement.
//!

mod base64;
mod didx509;
#[cfg(target_family = "wasm")]
pub mod ffi;
mod parse;

use attestation::snp::report::{AttestationReport, TcbVersionForGeneration, TcbVersionRaw};
use attestation::snp::verify::{ChainVerification, VerificationError};
use attestation::{snp, Generation};
use crypto::CertificateBackend;
#[cfg(async_crypto)]
use crypto::{AsyncCryptoBackend, AsyncKeyBackend};
#[cfg(sync_crypto)]
use crypto::{CryptoBackend, KeyBackend};

#[cfg(sync_crypto)]
use didx509::verify_didx509_root;
#[cfg(async_crypto)]
use didx509::verify_didx509_root_async;
use parse::{
    measurement_from_payload, parse_amd_endorsements, parse_attestation, parse_x5chain_certs,
};

pub use parse::{parse_aci_cose, CaciUvmEndorsement, CaciUvmEndorsementV1};

const fn attestation_report_field_len<const N: usize>(
    _: fn(&AttestationReport) -> &[u8; N],
) -> usize {
    N
}

const MEASUREMENT_LEN: usize = attestation_report_field_len(|report| &report.measurement);
/// Length of the SNP `HOST_DATA` field.
pub const HOST_DATA_LEN: usize = attestation_report_field_len(|report| &report.host_data);
/// Length of the SNP `REPORT_DATA` field.
pub const REPORT_DATA_LEN: usize = attestation_report_field_len(|report| &report.report_data);
const MAX_GUEST_VMPL: u32 = 3;

#[cfg(sync_crypto)]
/// Synchronous staged ACI verification.
///
/// Use this module when the active crypto backend supports synchronous
/// verification:
///
/// ```no_run
/// # fn example(
/// #     attestation: &[u8],
/// #     amd_endorsements: &[&[u8]],
/// #     aci_cose: &[u8],
/// #     trusted_didx509: &str,
/// #     trusted_c_aci_policy: [u8; tee_attestation_verification_aci::HOST_DATA_LEN],
/// #     minimum_uvm_svn: u64,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// let report = tee_attestation_verification_aci::sync::verify_attestation(
///     attestation,
///     amd_endorsements,
/// )?;
/// let uvm = tee_attestation_verification_aci::sync::verify_uvm_endorsement(
///     aci_cose,
///     trusted_didx509,
/// )?;
/// let verified_report_data = tee_attestation_verification_aci::verify_c_aci_attestation(
///     report,
///     vec![],
///     vec![trusted_c_aci_policy],
///     uvm,
///     "ContainerPlat-AMD-UVM",
///     minimum_uvm_svn,
/// )?;
/// # let _ = verified_report_data;
/// # Ok(())
/// # }
/// ```
pub mod sync {
    use super::*;

    /// Verify the SEV-SNP attestation report and its AMD endorsements.
    ///
    /// `amd_endorsements` must contain certificate bytes ordered as `[vcek,
    /// ask, ark]`. Successful verification authenticates the report signature,
    /// validates the AMD certificate chain, and checks report TCB values against
    /// the VCEK certificate.
    pub fn verify_attestation(
        report: &[u8],
        amd_endorsements: &[&[u8]],
    ) -> Result<AttestationReport, AciError> {
        let report = parse_attestation(report)?;
        let [vcek, ask, ark] = parse_amd_endorsements(amd_endorsements)?;
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
    /// chain root matches `trusted_didx509`.
    pub fn verify_uvm_endorsement(
        aci_cose: &[u8],
        trusted_didx509: &str,
    ) -> Result<CaciUvmEndorsement, AciError> {
        let parsed = parse_aci_cose(aci_cose)?;
        match parsed {
            CaciUvmEndorsement::V1(parsed) => {
                verify_didx509_root(trusted_didx509, &parsed.issuer, &parsed.x5chain)?;

                let (root, intermediates, leaf) = parse_x5chain_certs(&parsed.x5chain)?;
                let intermediate_refs = intermediates.iter().collect::<Vec<_>>();
                if let Some(signing_time) = parsed.signing_time {
                    <crypto::Crypto as CryptoBackend>::verify_chain(
                        &root,
                        &intermediate_refs,
                        &leaf,
                        Some(signing_time),
                    )
                    .map_err(|e| AciError::Certificate(e.to_string()))?;
                } else {
                    <crypto::Crypto as CryptoBackend>::verify_chain(
                        &root,
                        &intermediate_refs,
                        &leaf,
                        None,
                    )
                    .map_err(|e| AciError::Certificate(e.to_string()))?;
                }

                let algorithm = cose::signature_key_algorithm_for_cose_alg(parsed.alg)
                    .map_err(AciError::Cose)?;
                let spki = crypto::Crypto::get_public_key(&leaf)
                    .map_err(|e| AciError::Certificate(e.to_string()))?;
                let key = <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(
                    &spki, algorithm,
                )
                .map_err(|e| AciError::Certificate(e.to_string()))?;
                cose::cose_verify1(
                    &key,
                    algorithm,
                    &parsed.protected,
                    &parsed.payload,
                    &parsed.signature,
                )
                .map_err(AciError::Signature)?;

                Ok(CaciUvmEndorsement::V1(parsed))
            }
            #[allow(unreachable_patterns)]
            _ => Err(AciError::Cose("Unsupported ACI COSE structure".to_string())),
        }
    }
}

#[cfg(async_crypto)]
/// Asynchronous staged ACI verification.
///
/// Use this module when the active crypto backend is asynchronous, such as
/// WebCrypto:
///
/// ```no_run
/// # async fn example(
/// #     attestation: &[u8],
/// #     amd_endorsements: &[&[u8]],
/// #     aci_cose: &[u8],
/// #     trusted_didx509: &str,
/// #     trusted_c_aci_policy: [u8; tee_attestation_verification_aci::HOST_DATA_LEN],
/// #     minimum_uvm_svn: u64,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// let report = tee_attestation_verification_aci::asynchronous::verify_attestation(
///     attestation,
///     amd_endorsements,
/// ).await?;
/// let uvm = tee_attestation_verification_aci::asynchronous::verify_uvm_endorsement(
///     aci_cose,
///     trusted_didx509,
/// ).await?;
/// let verified_report_data = tee_attestation_verification_aci::verify_c_aci_attestation(
///     report,
///     vec![],
///     vec![trusted_c_aci_policy],
///     uvm,
///     "ContainerPlat-AMD-UVM",
///     minimum_uvm_svn,
/// )?;
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
        let [vcek, ask, ark] = parse_amd_endorsements(amd_endorsements)?;
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
    /// chain root matches `trusted_didx509`. This is stage 2 of the ACI flow;
    /// call [`crate::verify_c_aci_attestation`] afterwards to bind the UVM
    /// endorsement to the verified attestation report and relying-party policy.
    pub async fn verify_uvm_endorsement(
        aci_cose: &[u8],
        trusted_didx509: &str,
    ) -> Result<CaciUvmEndorsement, AciError> {
        let parsed = parse_aci_cose(aci_cose)?;
        match parsed {
            CaciUvmEndorsement::V1(parsed) => {
                verify_didx509_root_async(trusted_didx509, &parsed.issuer, &parsed.x5chain).await?;

                let (root, intermediates, leaf) = parse_x5chain_certs(&parsed.x5chain)?;
                let intermediate_refs = intermediates.iter().collect::<Vec<_>>();
                if let Some(signing_time) = parsed.signing_time {
                    <crypto::Crypto as AsyncCryptoBackend>::verify_chain(
                        &root,
                        &intermediate_refs,
                        &leaf,
                        Some(signing_time),
                    )
                    .await
                    .map_err(|e| AciError::Certificate(e.to_string()))?;
                } else {
                    <crypto::Crypto as AsyncCryptoBackend>::verify_chain(
                        &root,
                        &intermediate_refs,
                        &leaf,
                        None,
                    )
                    .await
                    .map_err(|e| AciError::Certificate(e.to_string()))?;
                }

                let algorithm = cose::signature_key_algorithm_for_cose_alg(parsed.alg)
                    .map_err(AciError::Cose)?;
                let spki = crypto::Crypto::get_public_key(&leaf)
                    .map_err(|e| AciError::Certificate(e.to_string()))?;
                let key =
                    <<crypto::Crypto as AsyncCryptoBackend>::Key as AsyncKeyBackend>::from_spki_der(
                        &spki, algorithm,
                    )
                    .await
                    .map_err(|e| AciError::Certificate(e.to_string()))?;
                cose::cose_verify1_async(
                    &key,
                    algorithm,
                    &parsed.protected,
                    &parsed.payload,
                    &parsed.signature,
                )
                .await
                .map_err(AciError::Signature)?;

                Ok(CaciUvmEndorsement::V1(parsed))
            }
            #[allow(unreachable_patterns)]
            _ => Err(AciError::Cose("Unsupported ACI COSE structure".to_string())),
        }
    }
}

/// Verify Confidential ACI relying-party policy over staged verified artifacts.
///
/// `sync::verify_attestation` or `asynchronous::verify_attestation` must be used
/// to authenticate the SNP report before calling this function, and
/// `sync::verify_uvm_endorsement` or `asynchronous::verify_uvm_endorsement`
/// must be used to authenticate the UVM reference info and its did:x509 root.
///
/// `trusted_c_aci_policy` is the expected SHA-256 digest of the Confidential
/// ACI security policy loaded into `HOST_DATA`. The returned value is the
/// verified `REPORT_DATA` from the SNP report.
pub fn verify_c_aci_attestation(
    attestation: AttestationReport,
    minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
    trusted_c_aci_policy: Vec<[u8; HOST_DATA_LEN]>,
    uvm_endorsement: CaciUvmEndorsement,
    uvm_feed: &str,
    minimum_svn: u64,
) -> Result<[u8; REPORT_DATA_LEN], AciError> {
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

    if !minimum_tcb.is_empty() {
        let generation = attestation
            .cpu_generation()
            .map_err(|e| AciError::Policy(format!("unsupported SNP CPU generation: {e}")))?;
        let matching_minimum_tcb = minimum_tcb
            .iter()
            .map(|(cpuid, minimum_tcb)| {
                Ok::<_, AciError>((
                    Generation::from_cpuid(cpuid).map_err(|e| {
                        AciError::Policy(format!("unsupported minimum TCB CPUID {cpuid:?}: {e}"))
                    })?,
                    minimum_tcb,
                ))
            })
            .find_map(|entry| match entry {
                Ok((minimum_generation, minimum_tcb)) if minimum_generation == generation => {
                    Some(Ok(minimum_tcb))
                }
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .transpose()?;

        if let Some(minimum_tcb) = matching_minimum_tcb {
            let minimum_tcb = TcbVersionForGeneration::new(*minimum_tcb, generation);
            let reported_tcb = TcbVersionForGeneration::new(attestation.reported_tcb, generation);
            if !(minimum_tcb <= reported_tcb) {
                return Err(AciError::Policy(format!(
                    "SNP reported TCB {:?} for generation {} is below trusted minimum {:?}",
                    attestation.reported_tcb, generation, minimum_tcb.tcb
                )));
            }
        } else {
            return Err(AciError::Policy(format!(
                "Minimum TCB specified but no entry matches SNP CPU generation {}",
                generation
            )));
        }
    }

    match uvm_endorsement {
        CaciUvmEndorsement::V1(uvm_endorsement) => {
            let reference_info =
                measurement_from_payload(&uvm_endorsement.payload, &uvm_endorsement.content_type)?;
            if reference_info.measurement != attestation.measurement {
                return Err(AciError::Measurement(
                    "ACI payload measurement does not match attestation measurement".to_string(),
                ));
            }

            if uvm_endorsement.feed.as_deref() != Some(uvm_feed) {
                return Err(AciError::Policy(format!(
                    "UVM feed {:?} does not match trusted feed {}",
                    uvm_endorsement.feed, uvm_feed
                )));
            }

            let svn = parse_uvm_svn(
                reference_info
                    .svn
                    .as_deref()
                    .or(uvm_endorsement.svn.as_deref()),
            )?;
            if svn < minimum_svn {
                return Err(AciError::Policy(format!(
                    "UVM SVN {svn} is below trusted minimum {minimum_svn}"
                )));
            }
        }
        #[allow(unreachable_patterns)]
        _ => return Err(AciError::Cose("Unsupported ACI COSE structure".to_string())),
    }

    if !trusted_c_aci_policy.contains(&attestation.host_data) {
        return Err(AciError::Policy(
            "SNP HOST_DATA does not match trusted policy".to_string(),
        ));
    }

    Ok(attestation.report_data)
}

/// Error returned when ACI verification fails.
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

fn parse_uvm_svn(svn: Option<&str>) -> Result<u64, AciError> {
    let svn = svn.ok_or_else(|| AciError::Policy("UVM SVN is missing".to_string()))?;
    if svn.is_empty() || !svn.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AciError::Policy(format!(
            "UVM SVN {svn:?} is not a non-negative integer"
        )));
    }
    svn.parse::<u64>()
        .map_err(|e| AciError::Policy(format!("UVM SVN {svn:?} is out of range: {e}")))
}

#[cfg(test)]
mod tests;
