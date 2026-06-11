// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AMD SEV-SNP attestation report types and verification APIs.

pub mod ffi;
pub(crate) mod model;
pub mod report;
pub(crate) mod utils;
pub mod verify;

pub use model::{Cpuid, Generation};
