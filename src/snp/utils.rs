// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

use asn1_rs::oid;
use asn1_rs::Oid as OidRs;

/// SEV-SNP OID extensions for VCEK certificate verification
/// These OIDs are used to extract TCB values from X.509 certificate extensions
pub(crate) enum Oid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
    Fmc,
}

impl Oid {
    pub(crate) fn oid(&self) -> OidRs<'_> {
        match self {
            Oid::BootLoader => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1),
            Oid::Tee => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2),
            Oid::Snp => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3),
            Oid::Ucode => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8),
            Oid::HwId => oid!(1.3.6 .1 .4 .1 .3704 .1 .4),
            Oid::Fmc => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .9),
        }
    }
}
