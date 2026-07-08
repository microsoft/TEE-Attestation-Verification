//! `wasm_bindgen` bindings exposing TEE attestation verification to JavaScript.
//!
//! > **Note:** an exported `async fn` runs its body at first poll (a microtask
//! > after the `Promise` is returned), not synchronously. Owned args (`Vec<u8>`,
//! > `&str`) are copied at the boundary and always safe; live JS arrays and
//! > borrowed wasm handles are read only then, so callers must not mutate those
//! > arrays or free those handles until the promise resolves.

#[cfg(target_family = "wasm")]
pub(crate) mod caci;
#[cfg(target_family = "wasm")]
pub(crate) mod cose;
#[cfg(target_family = "wasm")]
pub(crate) mod snp;
pub(crate) mod utils;
