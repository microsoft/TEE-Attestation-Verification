// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AMD SEV-SNP attestation report types and verification APIs.
//!
//! This module contains the zero-copy report representation in
//! [`crate::snp::report`], verification APIs in [`crate::snp::verify`], and
//! FFI/WASM-oriented bindings in [`crate::snp::ffi`].

/// FFI error types and target-specific bindings for SEV-SNP verification.
pub mod ffi;
pub(crate) mod model;
/// SEV-SNP attestation report structures
pub mod report;
pub(crate) mod utils;
/// SEV-SNP attestation verification with caller-provided certificates.
pub mod verify;
