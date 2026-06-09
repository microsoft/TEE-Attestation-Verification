mod cbor;
mod cose;

pub use cbor::CborValue;
pub use cose::signature_key_algorithm_for_cose_alg;

#[cfg(sync_crypto)]
pub use cose::cose_verify1;

#[cfg(async_crypto)]
pub use cose::cose_verify1_async;

pub use crypto::{
    EcSignatureKeyAlgorithm, Key, KeyBackend, RsaPssSignatureKeyAlgorithm, SignatureKeyAlgorithm,
};
