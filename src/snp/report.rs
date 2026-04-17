// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use zerocopy::{byteorder::little_endian as le, *};

// ---------------------------------------------------------------------------
// Decoded bitfield types
// ---------------------------------------------------------------------------

/// Decoded guest policy from the 64-bit policy field.
///
/// See AMD SEV-SNP ABI Specification, Table 10: GUEST_POLICY Structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct GuestPolicy(u64);

impl GuestPolicy {
    const ABI_MINOR_MASK: u64 = 0xFF;
    const ABI_MAJOR_MASK: u64 = 0xFF << 8;
    const SMT_BIT: u64 = 1 << 16;
    const MIGRATE_MA_BIT: u64 = 1 << 18;
    const DEBUG_BIT: u64 = 1 << 19;
    const SINGLE_SOCKET_BIT: u64 = 1 << 20;
    const CXL_ALLOW_BIT: u64 = 1 << 21;
    const MEM_AES_256_XTS_BIT: u64 = 1 << 22;
    const RAPL_DIS_BIT: u64 = 1 << 23;
    const CIPHERTEXT_HIDING_DRAM_BIT: u64 = 1 << 24;
    const PAGE_SWAP_DISABLE_BIT: u64 = 1 << 25;

    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(&self) -> u64 {
        self.0
    }

    pub fn abi_minor(&self) -> u8 {
        (self.0 & Self::ABI_MINOR_MASK) as u8
    }

    pub fn abi_major(&self) -> u8 {
        ((self.0 & Self::ABI_MAJOR_MASK) >> 8) as u8
    }

    pub fn smt(&self) -> bool {
        self.0 & Self::SMT_BIT != 0
    }

    pub fn migrate_ma(&self) -> bool {
        self.0 & Self::MIGRATE_MA_BIT != 0
    }

    pub fn debug(&self) -> bool {
        self.0 & Self::DEBUG_BIT != 0
    }

    pub fn single_socket(&self) -> bool {
        self.0 & Self::SINGLE_SOCKET_BIT != 0
    }

    pub fn cxl_allow(&self) -> bool {
        self.0 & Self::CXL_ALLOW_BIT != 0
    }

    pub fn mem_aes_256_xts(&self) -> bool {
        self.0 & Self::MEM_AES_256_XTS_BIT != 0
    }

    pub fn rapl_dis(&self) -> bool {
        self.0 & Self::RAPL_DIS_BIT != 0
    }

    pub fn ciphertext_hiding_dram(&self) -> bool {
        self.0 & Self::CIPHERTEXT_HIDING_DRAM_BIT != 0
    }

    pub fn page_swap_disable(&self) -> bool {
        self.0 & Self::PAGE_SWAP_DISABLE_BIT != 0
    }
}

/// The key type used to sign the attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKey {
    Vcek,
    Vlek,
    None,
    Reserved(u8),
}

impl SigningKey {
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Vcek,
            1 => Self::Vlek,
            7 => Self::None,
            value => Self::Reserved(value),
        }
    }

    pub fn raw(&self) -> u8 {
        match self {
            Self::Vcek => 0,
            Self::Vlek => 1,
            Self::None => 7,
            Self::Reserved(value) => *value,
        }
    }
}

/// Decoded flags field from the attestation report.
///
/// See AMD SEV-SNP ABI Specification, Table 23: ATTESTATION_REPORT Structure,
/// flags field description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ReportFlags(u32);

impl ReportFlags {
    const AUTHOR_KEY_EN_BIT: u32 = 1;
    const MASK_CHIP_KEY_BIT: u32 = 1 << 1;
    const SIGNING_KEY_MASK: u32 = 0b111 << 2;

    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub fn raw(&self) -> u32 {
        self.0
    }

    pub fn author_key_en(&self) -> bool {
        self.0 & Self::AUTHOR_KEY_EN_BIT != 0
    }

    pub fn mask_chip_key(&self) -> bool {
        self.0 & Self::MASK_CHIP_KEY_BIT != 0
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_raw(((self.0 & Self::SIGNING_KEY_MASK) >> 2) as u8)
    }
}

// ---------------------------------------------------------------------------
// TCB version types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[repr(C)]
pub struct TcbVersionMilanGenoa {
    pub boot_loader: u8,
    pub tee: u8,
    reserved: [u8; 4],
    pub snp: u8,
    pub microcode: u8,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[repr(C)]
pub struct TcbVersionTurin {
    pub fmc: u8,
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    reserved: [u8; 3],
    pub microcode: u8,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Default, Immutable, KnownLayout)]
#[repr(C)]
pub struct TcbVersionRaw {
    pub raw: [u8; 8],
}
impl TcbVersionRaw {
    pub fn as_milan_genoa(&self) -> TcbVersionMilanGenoa {
        try_transmute!(*self).unwrap()
    }
    pub fn as_turin(&self) -> TcbVersionTurin {
        try_transmute!(*self).unwrap()
    }
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Signature {
    pub r: [u8; 72],
    pub s: [u8; 72],
    reserved: [u8; 512 - 144],
}

/// SNP Attestation Report (0x4A0 = 1184 bytes).
///
/// See AMD SEV-SNP ABI Specification, Table 23: ATTESTATION_REPORT Structure.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct AttestationReport {
    /// Version number of this attestation report. Set to 0x03 for this specification.
    pub version: le::U32, // 0x000

    /// The guest SVN (Security Version Number).
    pub guest_svn: le::U32, // 0x004

    /// The guest policy. See Table 10 for a description of the guest policy structure.
    pub policy: le::U64, // 0x008

    /// The family ID provided at launch.
    pub family_id: [u8; 16], // 0x010

    /// The image ID provided at launch.
    pub image_id: [u8; 16], // 0x020

    /// The VMPL (Virtual Machine Privilege Level) for this report.
    ///
    /// For a guest-requested attestation report (MSG_REPORT_REQ), this field contains
    /// the value 0-3. A host-requested attestation report (SNP_HV_REPORT_REQ) will
    /// have a value of 0xFFFFFFFF.
    pub vmpl: le::U32, // 0x030

    /// The signature algorithm used to sign this report. See Chapter 10 for encodings.
    pub signature_algo: le::U32, // 0x034

    /// Current TCB (Trusted Computing Base) version.
    pub platform_version: TcbVersionRaw, // 0x038

    /// Information about the platform. See Table 24.
    pub platform_info: le::U64, // 0x040

    /// Flags field containing:
    /// - Bits 31:5: Reserved (must be zero)
    /// - Bits 4:2 (SIGNING_KEY): Encodes the key used to sign this report
    ///   (0=VCEK, 1=VLEK, 2-6=Reserved, 7=None)
    /// - Bit 1 (MASK_CHIP_KEY): The value of MaskChipKey
    /// - Bit 0 (AUTHOR_KEY_EN): Indicates that the digest of the author key is present
    ///   in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
    pub flags: le::U32, // 0x048

    /// Reserved. Must be zero.
    pub reserved0: le::U32, // 0x04C

    /// Guest-provided data if REQUEST_SOURCE is guest, otherwise zero-filled by firmware.
    pub report_data: [u8; 64], // 0x050

    /// The measurement calculated at launch.
    pub measurement: [u8; 48], // 0x090

    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32], // 0x0C0

    /// SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH.
    pub id_key_digest: [u8; 48], // 0x0E0

    /// SHA-384 digest of the Author public key that certified the ID key, if provided
    /// in SNP_LAUNCH_FINISH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48], // 0x110

    /// Report ID of this guest.
    pub report_id: [u8; 32], // 0x140

    /// Report ID of this guest's migration agent.
    pub report_id_ma: [u8; 32], // 0x160

    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersionRaw, // 0x180

    /// CPUID Family ID (combined Extended Family ID and Family ID).
    pub cpuid_fam_id: u8, // 0x188

    /// CPUID Model (combined Extended Model and Model fields).
    pub cpuid_mod_id: u8, // 0x189

    /// CPUID Stepping.
    pub cpuid_step: u8, // 0x18A

    /// Reserved.
    pub reserved1: [u8; 21], // 0x18B

    /// If MaskChipId is set to 0, identifier unique to the chip as output by GET_ID.
    /// Otherwise, set to 0h.
    pub chip_id: [u8; 64], // 0x1A0

    /// Committed TCB version.
    pub committed_tcb: TcbVersionRaw, // 0x1E0

    /// The build number of CurrentVersion.
    pub current_build: u8, // 0x1E8

    /// The minor number of CurrentVersion.
    pub current_minor: u8, // 0x1E9

    /// The major number of CurrentVersion.
    pub current_major: u8, // 0x1EA

    /// Reserved.
    pub reserved2: u8, // 0x1EB

    /// The build number of CommittedVersion.
    pub committed_build: u8, // 0x1EC

    /// The minor version of CommittedVersion.
    pub committed_minor: u8, // 0x1ED

    /// The major version of CommittedVersion.
    pub committed_major: u8, // 0x1EE

    /// Reserved.
    pub reserved3: u8, // 0x1EF

    /// The CurrentTcb at the time the guest was launched or imported.
    pub launch_tcb: TcbVersionRaw, // 0x1F0

    /// Reserved.
    pub reserved4: [u8; 168], // 0x1F8

    /// Signature of bytes 0x00 to 0x29F inclusive of this report.
    /// The format of the signature is described in Chapter 10.
    pub signature: Signature, // 0x2A0
}

impl AttestationReport {
    /// Returns the signed portion of the report (everything before the signature).
    pub fn signed_bytes(&self) -> &[u8] {
        let bytes = self.as_bytes();
        &bytes[..0x2A0]
    }

    /// Decode the guest policy bitfield.
    pub fn policy(&self) -> GuestPolicy {
        GuestPolicy::from_raw(self.policy.get())
    }

    /// Decode the report flags bitfield.
    pub fn flags(&self) -> ReportFlags {
        ReportFlags::from_raw(self.flags.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn attestation_report_size() {
        assert_eq!(size_of::<AttestationReport>(), 0x4A0);
    }

    #[test]
    fn signature_size() {
        assert_eq!(size_of::<Signature>(), 512);
    }

    #[test]
    fn guest_policy_accessors() {
        let raw = 0x12_u64
            | (0x34_u64 << 8)
            | (1_u64 << 16)
            | (1_u64 << 18)
            | (1_u64 << 19)
            | (1_u64 << 20)
            | (1_u64 << 21)
            | (1_u64 << 22)
            | (1_u64 << 23)
            | (1_u64 << 24)
            | (1_u64 << 25);
        let policy = GuestPolicy::from_raw(raw);

        assert_eq!(policy.raw(), raw);
        assert_eq!(policy.abi_minor(), 0x12);
        assert_eq!(policy.abi_major(), 0x34);
        assert!(policy.smt());
        assert!(policy.migrate_ma());
        assert!(policy.debug());
        assert!(policy.single_socket());
        assert!(policy.cxl_allow());
        assert!(policy.mem_aes_256_xts());
        assert!(policy.rapl_dis());
        assert!(policy.ciphertext_hiding_dram());
        assert!(policy.page_swap_disable());
    }

    #[test]
    fn guest_policy_all_clear() {
        let policy = GuestPolicy::from_raw(0);
        assert_eq!(policy.abi_minor(), 0);
        assert_eq!(policy.abi_major(), 0);
        assert!(!policy.smt());
        assert!(!policy.migrate_ma());
        assert!(!policy.debug());
        assert!(!policy.single_socket());
        assert!(!policy.cxl_allow());
        assert!(!policy.mem_aes_256_xts());
        assert!(!policy.rapl_dis());
        assert!(!policy.ciphertext_hiding_dram());
        assert!(!policy.page_swap_disable());
    }

    #[test]
    fn guest_policy_each_bit_individually() {
        let bit_accessors: &[(u64, fn(&GuestPolicy) -> bool)] = &[
            (1 << 16, GuestPolicy::smt),
            (1 << 18, GuestPolicy::migrate_ma),
            (1 << 19, GuestPolicy::debug),
            (1 << 20, GuestPolicy::single_socket),
            (1 << 21, GuestPolicy::cxl_allow),
            (1 << 22, GuestPolicy::mem_aes_256_xts),
            (1 << 23, GuestPolicy::rapl_dis),
            (1 << 24, GuestPolicy::ciphertext_hiding_dram),
            (1 << 25, GuestPolicy::page_swap_disable),
        ];

        for (i, (bit, accessor)) in bit_accessors.iter().enumerate() {
            let policy = GuestPolicy::from_raw(*bit);
            assert!(
                accessor(&policy),
                "accessor at index {i} should be true when its bit is set"
            );
            for (j, (_, other_accessor)) in bit_accessors.iter().enumerate() {
                if i != j {
                    assert!(
                        !other_accessor(&policy),
                        "accessor at index {j} should be false when only bit {i} is set"
                    );
                }
            }
        }
    }

    #[test]
    fn report_flags_accessors() {
        let flags = ReportFlags::from_raw((1_u32 << 0) | (1_u32 << 1) | (1_u32 << 2));

        assert_eq!(flags.raw(), 0b111);
        assert!(flags.author_key_en());
        assert!(flags.mask_chip_key());
        assert_eq!(flags.signing_key(), SigningKey::Vlek);

        let reserved = ReportFlags::from_raw(5_u32 << 2);
        assert_eq!(reserved.signing_key(), SigningKey::Reserved(5));

        let none = ReportFlags::from_raw(7_u32 << 2);
        assert_eq!(none.signing_key(), SigningKey::None);
    }

    #[test]
    fn signing_key_round_trip() {
        for raw in 0..=7u8 {
            let key = SigningKey::from_raw(raw);
            assert_eq!(key.raw(), raw);
        }
    }

    #[test]
    fn attestation_report_policy_and_flags_accessors() {
        let mut bytes = [0_u8; size_of::<AttestationReport>()];
        let policy_raw = 0x5A_u64 | (0xA5_u64 << 8) | (1_u64 << 16) | (1_u64 << 25);
        let flags_raw = (1_u32 << 0) | (7_u32 << 2);

        bytes[0x008..0x010].copy_from_slice(&policy_raw.to_le_bytes());
        bytes[0x048..0x04C].copy_from_slice(&flags_raw.to_le_bytes());

        let report = AttestationReport::ref_from_bytes(&bytes).unwrap();

        assert_eq!(report.policy().raw(), policy_raw);
        assert_eq!(report.policy().abi_minor(), 0x5A);
        assert_eq!(report.policy().abi_major(), 0xA5);
        assert!(report.policy().smt());
        assert!(report.policy().page_swap_disable());

        assert_eq!(report.flags().raw(), flags_raw);
        assert!(report.flags().author_key_en());
        assert!(!report.flags().mask_chip_key());
        assert_eq!(report.flags().signing_key(), SigningKey::None);
    }

    #[test]
    fn field_offsets() {
        use std::mem::offset_of;

        assert_eq!(offset_of!(AttestationReport, version), 0x000);
        assert_eq!(offset_of!(AttestationReport, guest_svn), 0x004);
        assert_eq!(offset_of!(AttestationReport, policy), 0x008);
        assert_eq!(offset_of!(AttestationReport, family_id), 0x010);
        assert_eq!(offset_of!(AttestationReport, image_id), 0x020);
        assert_eq!(offset_of!(AttestationReport, vmpl), 0x030);
        assert_eq!(offset_of!(AttestationReport, signature_algo), 0x034);
        assert_eq!(offset_of!(AttestationReport, platform_version), 0x038);
        assert_eq!(offset_of!(AttestationReport, platform_info), 0x040);
        assert_eq!(offset_of!(AttestationReport, flags), 0x048);
        assert_eq!(offset_of!(AttestationReport, reserved0), 0x04C);
        assert_eq!(offset_of!(AttestationReport, report_data), 0x050);
        assert_eq!(offset_of!(AttestationReport, measurement), 0x090);
        assert_eq!(offset_of!(AttestationReport, host_data), 0x0C0);
        assert_eq!(offset_of!(AttestationReport, id_key_digest), 0x0E0);
        assert_eq!(offset_of!(AttestationReport, author_key_digest), 0x110);
        assert_eq!(offset_of!(AttestationReport, report_id), 0x140);
        assert_eq!(offset_of!(AttestationReport, report_id_ma), 0x160);
        assert_eq!(offset_of!(AttestationReport, reported_tcb), 0x180);
        assert_eq!(offset_of!(AttestationReport, cpuid_fam_id), 0x188);
        assert_eq!(offset_of!(AttestationReport, cpuid_mod_id), 0x189);
        assert_eq!(offset_of!(AttestationReport, cpuid_step), 0x18A);
        assert_eq!(offset_of!(AttestationReport, reserved1), 0x18B);
        assert_eq!(offset_of!(AttestationReport, chip_id), 0x1A0);
        assert_eq!(offset_of!(AttestationReport, committed_tcb), 0x1E0);
        assert_eq!(offset_of!(AttestationReport, current_build), 0x1E8);
        assert_eq!(offset_of!(AttestationReport, current_minor), 0x1E9);
        assert_eq!(offset_of!(AttestationReport, current_major), 0x1EA);
        assert_eq!(offset_of!(AttestationReport, reserved2), 0x1EB);
        assert_eq!(offset_of!(AttestationReport, committed_build), 0x1EC);
        assert_eq!(offset_of!(AttestationReport, committed_minor), 0x1ED);
        assert_eq!(offset_of!(AttestationReport, committed_major), 0x1EE);
        assert_eq!(offset_of!(AttestationReport, reserved3), 0x1EF);
        assert_eq!(offset_of!(AttestationReport, launch_tcb), 0x1F0);
        assert_eq!(offset_of!(AttestationReport, reserved4), 0x1F8);
        assert_eq!(offset_of!(AttestationReport, signature), 0x2A0);
    }
}
