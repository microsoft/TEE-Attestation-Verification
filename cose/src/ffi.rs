// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_family = "wasm")]
pub mod wasm {
    use wasm_bindgen::prelude::*;

    use crate::CborValue as NativeCborValue;

    /// JavaScript wrapper around an owned CBOR value.
    #[wasm_bindgen]
    #[derive(Clone)]
    pub struct CborValue {
        inner: NativeCborValue,
    }

    impl CborValue {
        pub fn from_native(inner: NativeCborValue) -> Self {
            Self { inner }
        }

        pub fn as_native(&self) -> &NativeCborValue {
            &self.inner
        }

        pub fn into_native(self) -> NativeCborValue {
            self.inner
        }
    }

    #[wasm_bindgen]
    impl CborValue {
        /// Parse a CBOR document from bytes.
        pub fn from_bytes(bytes: &[u8]) -> Result<CborValue, String> {
            NativeCborValue::from_bytes(bytes).map(CborValue::from_native)
        }

        /// Serialize this value as deterministic CBOR bytes.
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            self.inner.to_bytes()
        }

        /// Return the CBOR major type represented by this value.
        pub fn kind(&self) -> String {
            match self.inner {
                NativeCborValue::Int(_) => "int",
                NativeCborValue::Simple(_) => "simple",
                NativeCborValue::ByteString(_) => "bytes",
                NativeCborValue::TextString(_) => "text",
                NativeCborValue::Array(_) => "array",
                NativeCborValue::Map(_) => "map",
                NativeCborValue::Tagged { .. } => "tagged",
            }
            .to_string()
        }

        pub fn int(&self) -> Result<i64, String> {
            match &self.inner {
                NativeCborValue::Int(value) => Ok(*value),
                other => Err(format!("Expected Int, got {:?}", other)),
            }
        }

        pub fn simple(&self) -> Result<u8, String> {
            match &self.inner {
                NativeCborValue::Simple(value) => Ok(*value),
                other => Err(format!("Expected Simple, got {:?}", other)),
            }
        }

        pub fn bytes(&self) -> Result<Vec<u8>, String> {
            match &self.inner {
                NativeCborValue::ByteString(value) => Ok(value.clone()),
                other => Err(format!("Expected ByteString, got {:?}", other)),
            }
        }

        pub fn text(&self) -> Result<String, String> {
            match &self.inner {
                NativeCborValue::TextString(value) => Ok(value.clone()),
                other => Err(format!("Expected TextString, got {:?}", other)),
            }
        }

        pub fn tag(&self) -> Result<u64, String> {
            match &self.inner {
                NativeCborValue::Tagged { tag, .. } => Ok(*tag),
                other => Err(format!("Expected Tagged, got {:?}", other)),
            }
        }

        pub fn tagged_payload(&self) -> Result<CborValue, String> {
            match &self.inner {
                NativeCborValue::Tagged { payload, .. } => {
                    Ok(CborValue::from_native(payload.as_ref().clone()))
                }
                other => Err(format!("Expected Tagged, got {:?}", other)),
            }
        }

        pub fn len(&self) -> Result<u32, String> {
            self.inner
                .len()?
                .try_into()
                .map_err(|_| "CBOR container length does not fit u32".to_string())
        }

        pub fn array_at(&self, index: u32) -> Result<CborValue, String> {
            self.inner
                .array_at(index as usize)
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn map_at_int(&self, key: i64) -> Result<CborValue, String> {
            self.inner
                .map_at_int(key)
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn map_at_text(&self, key: &str) -> Result<CborValue, String> {
            self.inner
                .map_at_str(key)
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn map_key_at(&self, index: u32) -> Result<CborValue, String> {
            map_entry_at(&self.inner, index).map(|(key, _)| CborValue::from_native(key.clone()))
        }

        pub fn map_value_at(&self, index: u32) -> Result<CborValue, String> {
            map_entry_at(&self.inner, index).map(|(_, value)| CborValue::from_native(value.clone()))
        }

        pub fn as_cose_sign1(&self) -> Result<CoseSign1, String> {
            crate::cose_sign1(&self.inner)
                .cloned()
                .map(CoseSign1::from_native)
        }
    }

    /// JavaScript wrapper around a COSE_Sign1 array.
    #[wasm_bindgen]
    #[derive(Clone)]
    pub struct CoseSign1 {
        inner: NativeCborValue,
    }

    impl CoseSign1 {
        pub fn from_native(inner: NativeCborValue) -> Self {
            Self { inner }
        }
    }

    #[wasm_bindgen]
    impl CoseSign1 {
        pub fn protected(&self) -> Result<Vec<u8>, String> {
            required_bytes(self.inner.array_at(0)?, "protected")
        }

        pub fn unprotected(&self) -> Result<CborValue, String> {
            self.inner.array_at(1).cloned().map(CborValue::from_native)
        }

        pub fn payload(&self) -> Result<Vec<u8>, String> {
            required_bytes(self.inner.array_at(2)?, "payload")
        }

        pub fn signature(&self) -> Result<Vec<u8>, String> {
            required_bytes(self.inner.array_at(3)?, "signature")
        }

        pub fn protected_header(&self) -> Result<CborValue, String> {
            NativeCborValue::from_bytes(&self.protected()?).map(CborValue::from_native)
        }
    }

    pub fn required_bytes(value: &NativeCborValue, name: &str) -> Result<Vec<u8>, String> {
        match value {
            NativeCborValue::ByteString(bytes) => Ok(bytes.clone()),
            _ => Err(format!("{name} must be a byte string")),
        }
    }

    fn map_entry_at(
        value: &NativeCborValue,
        index: u32,
    ) -> Result<(&NativeCborValue, &NativeCborValue), String> {
        match value {
            NativeCborValue::Map(entries) => entries
                .get(index as usize)
                .map(|(key, value)| (key, value))
                .ok_or_else(|| format!("Index {index} out of bounds")),
            other => Err(format!("Expected Map, got {:?}", other)),
        }
    }
}
