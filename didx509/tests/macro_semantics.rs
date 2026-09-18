// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use maybe_async_attr::maybe_async;

fn parent_value() -> usize {
    42
}

#[cfg(sync_crypto)]
fn synchronous_value() -> usize {
    7
}

#[cfg(async_crypto)]
async fn asynchronous_value() -> usize {
    7
}

#[maybe_async(
    sync: {
        use crate::synchronous_value as value;
    },
    async: {
        use crate::asynchronous_value as value;
    },
)]
mod semantics {
    #![allow(dead_code)]
    #![allow(unused_macros)]

    use super as parent_module;
    use super::parent_value as imported_parent;

    #[maybe_async_fn]
    pub(super) fn parent_relative() -> usize {
        super::parent_value()
    }

    pub fn imported_parent_relative() -> usize {
        imported_parent()
    }

    pub fn renamed_parent_relative() -> usize {
        parent_module::parent_value()
    }

    pub mod child {
        pub fn parent_relative() -> usize {
            super::super::parent_value()
        }
    }

    macro_rules! preserve_marker_tokens {
        (#[maybe_async_fn] $item:item) => {};
    }

    #[maybe_async_fn]
    pub fn marker_expressions() -> usize {
        mb_await!(value());
        mb_await!(value())
    }
}

#[maybe_async(sync: {}, async: {})]
mod r#type {
    pub fn value() -> usize {
        42
    }
}

#[cfg(sync_crypto)]
#[test]
fn synchronous_mode_preserves_source_module_semantics() {
    assert_eq!(semantics_sync::parent_relative(), 42);
    assert_eq!(semantics_sync::imported_parent_relative(), 42);
    assert_eq!(semantics_sync::renamed_parent_relative(), 42);
    assert_eq!(semantics_sync::child::parent_relative(), 42);
    assert_eq!(semantics_sync::marker_expressions(), 7);
    assert_eq!(type_sync::value(), 42);
}

#[cfg(async_crypto)]
#[test]
fn asynchronous_mode_preserves_source_module_semantics() {
    assert_eq!(block_on(semantics_async::parent_relative()), 42);
    assert_eq!(semantics_async::imported_parent_relative(), 42);
    assert_eq!(semantics_async::renamed_parent_relative(), 42);
    assert_eq!(semantics_async::child::parent_relative(), 42);
    assert_eq!(block_on(semantics_async::marker_expressions()), 7);
    assert_eq!(type_async::value(), 42);
}

#[cfg(async_crypto)]
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};

    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}
