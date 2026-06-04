// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::borrow::Cow;

#[cfg(any(
    crypto_backend = "crypto_pure_rust",
    crypto_backend = "crypto_webcrypto"
))]
use crate::Result;

#[cfg(any(
    crypto_backend = "crypto_pure_rust",
    crypto_backend = "crypto_webcrypto"
))]
const P384_SCALAR_SIZE: usize = 48;

/// Digest algorithm used by a signature operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub fn byte_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Elliptic-curve signature key algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcSignatureKeyAlgorithm {
    P256,
    P384,
    P521,
}

impl EcSignatureKeyAlgorithm {
    pub fn digest(self) -> DigestAlgorithm {
        match self {
            Self::P256 => DigestAlgorithm::Sha256,
            Self::P384 => DigestAlgorithm::Sha384,
            Self::P521 => DigestAlgorithm::Sha512,
        }
    }
}

/// RSA-PSS signature key algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaPssSignatureKeyAlgorithm {
    Ps256,
    Ps384,
    Ps512,
}

impl RsaPssSignatureKeyAlgorithm {
    pub fn digest(self) -> DigestAlgorithm {
        match self {
            Self::Ps256 => DigestAlgorithm::Sha256,
            Self::Ps384 => DigestAlgorithm::Sha384,
            Self::Ps512 => DigestAlgorithm::Sha512,
        }
    }

    pub fn salt_len(self) -> usize {
        self.digest().byte_len()
    }
}

/// A key algorithm bound to the signature operation it is used to verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureKeyAlgorithm {
    Ec(EcSignatureKeyAlgorithm),
    RsaPss(RsaPssSignatureKeyAlgorithm),
}

impl SignatureKeyAlgorithm {
    pub fn digest(self) -> DigestAlgorithm {
        match self {
            Self::Ec(algorithm) => algorithm.digest(),
            Self::RsaPss(algorithm) => algorithm.digest(),
        }
    }
}

/// Signature byte representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureEncoding {
    /// ASN.1 DER-encoded signature bytes.
    Der,
    /// Raw signature bytes with no additional signature-structure encoding.
    Raw,
    /// Fixed-width big-endian ECDSA scalars: `r || s`.
    EcdsaFixed,
}

/// Signature bytes plus their representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature<'a> {
    bytes: Cow<'a, [u8]>,
    encoding: SignatureEncoding,
}

impl<'a> Signature<'a> {
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>, encoding: SignatureEncoding) -> Self {
        Self {
            bytes: bytes.into(),
            encoding,
        }
    }

    pub fn der(bytes: &'a [u8]) -> Self {
        Self::new(bytes, SignatureEncoding::Der)
    }

    pub fn raw(bytes: &'a [u8]) -> Self {
        Self::new(bytes, SignatureEncoding::Raw)
    }

    pub fn ecdsa_fixed(bytes: &'a [u8]) -> Self {
        Self::new(bytes, SignatureEncoding::EcdsaFixed)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn encoding(&self) -> SignatureEncoding {
        self.encoding
    }

    #[cfg(any(
        crypto_backend = "crypto_pure_rust",
        crypto_backend = "crypto_webcrypto"
    ))]
    pub(crate) fn ecdsa_p384_fixed_bytes(&self) -> Result<&[u8]> {
        match self.encoding {
            SignatureEncoding::EcdsaFixed => {
                if self.bytes.len() != P384_SCALAR_SIZE * 2 {
                    return Err(format!(
                        "Invalid ECDSA P-384 fixed signature length: expected {}, got {}",
                        P384_SCALAR_SIZE * 2,
                        self.bytes.len()
                    )
                    .into());
                }

                Ok(&self.bytes)
            }
            _ => Err(
                "ECDSA P-384 verification requires DER or fixed-width signature encoding".into(),
            ),
        }
    }
}
