// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared immutable CBOR document views for the native and WebAssembly FFIs.
//!
//! A view keeps an [`Arc`] to the parsed document and a pointer to either its
//! root or one of its nodes. The document is never exposed mutably, so moving
//! or reallocating descendants after a view is created is impossible.

use std::sync::Arc;

use cose::CborValue as NativeCborValue;

#[derive(Clone)]
pub(crate) struct CborView {
    document: Arc<NativeCborValue>,
    node: *const NativeCborValue,
}

impl CborView {
    pub(crate) fn new(value: NativeCborValue) -> Self {
        let document = Arc::new(value);
        let node = Arc::as_ptr(&document);
        Self { document, node }
    }

    pub(crate) fn as_native(&self) -> &NativeCborValue {
        // SAFETY: `node` is initialized from `document` or by `try_child` from
        // a reference whose lifetime is tied to the current node. CBOR values
        // reachable through an immutable `NativeCborValue` cannot move because
        // this type never exposes mutable access. `document` keeps the complete
        // allocation graph alive for at least as long as this view.
        unsafe { &*self.node }
    }

    pub(crate) fn try_child<E>(
        &self,
        project: impl for<'a> FnOnce(&'a NativeCborValue) -> Result<&'a NativeCborValue, E>,
    ) -> Result<Self, E> {
        let node = project(self.as_native())? as *const NativeCborValue;
        Ok(Self {
            document: Arc::clone(&self.document),
            node,
        })
    }

    pub(crate) fn try_children<E>(
        &self,
        project: impl for<'a> FnOnce(
            &'a NativeCborValue,
        ) -> Result<(&'a NativeCborValue, &'a NativeCborValue), E>,
    ) -> Result<(Self, Self), E> {
        let (first, second) = project(self.as_native())?;
        Ok((
            Self {
                document: Arc::clone(&self.document),
                node: first as *const NativeCborValue,
            },
            Self {
                document: Arc::clone(&self.document),
                node: second as *const NativeCborValue,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn document_ptr(&self) -> *const NativeCborValue {
        Arc::as_ptr(&self.document)
    }

    #[cfg(test)]
    pub(crate) fn document_strong_count(&self) -> usize {
        Arc::strong_count(&self.document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_shares_document_and_survives_parent_drop() {
        let root = CborView::new(NativeCborValue::Array(vec![
            NativeCborValue::Int(1),
            NativeCborValue::Array(vec![NativeCborValue::Int(42)]),
        ]));
        let root_node = root.as_native() as *const NativeCborValue;
        let child = root
            .try_child(|value| value.array_at(1))
            .unwrap()
            .try_child(|value| value.array_at(0))
            .unwrap();
        let child_node = child.as_native() as *const NativeCborValue;

        assert_ne!(root_node, child_node);
        assert_eq!(root.document_ptr(), child.document_ptr());
        drop(root);
        assert_eq!(child.as_native(), &NativeCborValue::Int(42));
    }

    #[test]
    fn cloned_view_keeps_the_same_node_alive() {
        let view = CborView::new(NativeCborValue::TextString("value".into()));
        let cloned = view.clone();

        assert_eq!(
            view.as_native() as *const NativeCborValue,
            cloned.as_native() as *const NativeCborValue
        );
        assert_eq!(view.document_ptr(), cloned.document_ptr());
        drop(view);
        assert_eq!(
            cloned.as_native(),
            &NativeCborValue::TextString("value".into())
        );
    }
}
