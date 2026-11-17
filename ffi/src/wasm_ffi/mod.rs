// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `wasm_bindgen` bindings exposing TEE attestation verification to JavaScript.
//!
//! See `README.md` in this directory for build/consume instructions and
//! worked SNP/CACI examples.
//!
//! See `ffi/tests/wasm-consumer` for the Node-based consumer test suite that
//! imports the generated package exactly as an external JS consumer would,
//! and `demos/web-verify-kernel` / `demos/caci-attestation-verify` for
//! runnable browser demos.
//!
//! > **Note:** an exported `async fn` runs its body at first poll (a microtask
//! > after the `Promise` is returned), not synchronously. Owned args (`Vec<u8>`,
//! > `&str`) are copied at the boundary and always safe; a live JS array is read
//! > only then, so callers must not mutate it until the promise settles. No
//! > exported `async fn` borrows a wasm handle: an export that takes handles is
//! > a plain `fn` that copies what it needs before it returns its `Promise`, so
//! > a handle may be freed as soon as the call returns.

#[cfg(target_family = "wasm")]
pub(crate) mod caci;
#[cfg(target_family = "wasm")]
pub(crate) mod cose;
#[cfg(target_family = "wasm")]
pub(crate) mod snp;
pub(crate) mod utils;
