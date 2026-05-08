// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AMD SEV-SNP attestation report types and verification APIs.
//!
//! This module contains the zero-copy report representation in
//! [`crate::snp::report`], verification APIs in [`crate::snp::verify`], and
//! FFI/WASM-oriented bindings in [`crate::snp::ffi`].

pub mod ffi;
pub(crate) mod model;
pub mod report;
pub(crate) mod utils;
pub mod verify;
