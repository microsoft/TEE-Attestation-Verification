// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Validation policy shared by all input formats and crypto backends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyConfig {
    /// Request full RFC 5280 processing, including certificate-policy constraints.
    ///
    /// Disabled by default. Enabling this currently returns
    /// [`crate::ValidationError::UnsupportedPolicy`] on every backend.
    /// Disabling it preserves the existing certificate-signature, path,
    /// validity-time, extension, fingerprint, and DID-predicate checks.
    pub rfc5280_validation: bool,
}
