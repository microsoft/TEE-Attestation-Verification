use crate::TavErrorCode;
use attestation::snp::verify::VerificationError;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// An error returned by the SNP verify function.
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Debug)]
pub struct VerifyError {
    code: TavErrorCode,
    message: String,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl VerifyError {
    /// The error category.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(getter))]
    pub fn code(&self) -> TavErrorCode {
        self.code
    }

    /// The human-readable error message.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(getter))]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl VerifyError {
    pub(crate) fn new(code: TavErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    pub(crate) fn invalid_argument(message: String) -> Self {
        Self::new(TavErrorCode::InvalidArgument, message)
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifyError {}

impl From<VerificationError> for VerifyError {
    fn from(e: VerificationError) -> Self {
        let code = match &e {
            VerificationError::UnsupportedProcessor(_) => TavErrorCode::UnsupportedProcessor,
            VerificationError::InvalidRootCertificate(_) => TavErrorCode::InvalidRootCertificate,
            VerificationError::CertificateChainError(_) => TavErrorCode::CertificateChainError,
            VerificationError::SignatureVerificationError(_) => {
                TavErrorCode::SignatureVerificationError
            }
            VerificationError::TcbVerificationError(_) => TavErrorCode::TcbVerificationError,
        };
        Self::new(code, e.to_string())
    }
}