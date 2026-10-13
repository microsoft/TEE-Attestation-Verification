# TAV sync and async macro

`tee-attestation-verification-maybe-async` generates sibling sync and async
modules from one inline module. TAV crates use the `maybe-async-attr` dependency
alias to import `maybe_async_attr::maybe_async`.

```toml
[dependencies]
maybe-async-attr = { package = "tee-attestation-verification-maybe-async", version = "1.0.8" }
```

`#[maybe_async(sync: { ... }, async: { ... })]` emits `<name>_sync` under
`cfg(sync_crypto)` and `<name>_async` under `cfg(async_crypto)`. The consuming
crate must declare these configuration names and enable the appropriate modes.
TAV's DID crate reads these capabilities from crypto build metadata in
[`build.rs`](../build.rs).

The macro removes `#[maybe_async_fn]` in both copies and adds `async` in the
async copy. `mb_await!(expression)` awaits the expression only in the async copy.
Marked functions must be ordinary, non-const, safe Rust-ABI functions.
Module depth, relative paths, visibility, inner attributes, and macro-definition
bodies retain their source meaning.

The DID crate's [`macro_semantics.rs`](../tests/macro_semantics.rs) exercises
both modes.
