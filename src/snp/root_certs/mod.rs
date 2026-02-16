// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pinned AMD Root Key (ARK) certificates for SEV-SNP verification.
//!
//! These certificates are embedded at compile time and used for offline verification
//! without requiring network access to AMD's KDS.

use crate::crypto::{Certificate, Crypto, CryptoBackend};
use crate::snp::model::Generation;

pub const MILAN_ARK: &[u8] = include_bytes!("milan_ark.pem");
pub const GENOA_ARK: &[u8] = include_bytes!("genoa_ark.pem");
pub const TURIN_ARK: &[u8] = include_bytes!("turin_ark.pem");

/// Get the pinned ARK certificate for a given processor generation.
pub fn get_ark(generation: &Generation) -> Certificate {
    let pem_bytes = match generation {
        Generation::Milan => MILAN_ARK,
        Generation::Genoa => GENOA_ARK,
        Generation::Turin => TURIN_ARK,
    };
    // As we vendor the ARKs as PEM files, they are guaranteed to be valid
    Crypto::from_pem(pem_bytes).unwrap()
}
