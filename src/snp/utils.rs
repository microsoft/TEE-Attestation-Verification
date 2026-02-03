#[cfg(feature = "serde")]
pub mod serde_wrappers {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zerocopy::byteorder::little_endian as le;

    pub mod le_u32 {
        use super::*;
        pub fn serialize<S: Serializer>(val: &le::U32, s: S) -> Result<S::Ok, S::Error> {
            val.get().serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<le::U32, D::Error> {
            u32::deserialize(d).map(le::U32::new)
        }
    }

    pub mod le_u64 {
        use super::*;
        pub fn serialize<S: Serializer>(val: &le::U64, s: S) -> Result<S::Ok, S::Error> {
            val.get().serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<le::U64, D::Error> {
            u64::deserialize(d).map(le::U64::new)
        }
    }
}
