use zerocopy::{byteorder::little_endian as le, *};

#[cfg(feature = "serde")]
use super::utils::serde_wrappers;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(C)]
pub struct TcbVersionMilanGenoa {
    pub boot_loader: u8,
    pub tee: u8,
    reserved: [u8; 4],
    pub snp: u8,
    pub microcode: u8,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(C)]
pub struct TcbVersionTurin {
    pub fmc: u8,
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    reserved: [u8; 3],
    pub microcode: u8,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Default, Immutable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(C)]
pub struct Signature {
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub r: [u8; 72],
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub s: [u8; 72],
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    reserved: [u8; 512 - 144],
}

/// SNP Attestation Report (0x4A0 = 1184 bytes).
///
/// See AMD SEV-SNP ABI Specification, Table 23: ATTESTATION_REPORT Structure.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(C)]
pub struct AttestationReport {
    /// Version number of this attestation report. Set to 0x03 for this specification.
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u32"))]
    pub version: le::U32, // 0x000

    /// The guest SVN (Security Version Number).
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u32"))]
    pub guest_svn: le::U32, // 0x004

    /// The guest policy. See Table 10 for a description of the guest policy structure.
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u64"))]
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
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u32"))]
    pub vmpl: le::U32, // 0x030

    /// The signature algorithm used to sign this report. See Chapter 10 for encodings.
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u32"))]
    pub signature_algo: le::U32, // 0x034

    /// Current TCB (Trusted Computing Base) version.
    pub platform_version: TcbVersionRaw, // 0x038

    /// Information about the platform. See Table 24.
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u64"))]
    pub platform_info: le::U64, // 0x040

    /// Flags field containing:
    /// - Bits 31:5: Reserved (must be zero)
    /// - Bits 4:2 (SIGNING_KEY): Encodes the key used to sign this report
    ///   (0=VCEK, 1=VLEK, 2-6=Reserved, 7=None)
    /// - Bit 1 (MASK_CHIP_KEY): The value of MaskChipKey
    /// - Bit 0 (AUTHOR_KEY_EN): Indicates that the digest of the author key is present
    ///   in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u32"))]
    pub flags: le::U32, // 0x048

    /// Reserved. Must be zero.
    #[cfg_attr(feature = "serde", serde(with = "serde_wrappers::le_u32"))]
    pub reserved0: le::U32, // 0x04C

    /// Guest-provided data if REQUEST_SOURCE is guest, otherwise zero-filled by firmware.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub report_data: [u8; 64], // 0x050

    /// The measurement calculated at launch.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub measurement: [u8; 48], // 0x090

    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32], // 0x0C0

    /// SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub id_key_digest: [u8; 48], // 0x0E0

    /// SHA-384 digest of the Author public key that certified the ID key, if provided
    /// in SNP_LAUNCH_FINISH. Zeroes if AUTHOR_KEY_EN is 1.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
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
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub reserved1: [u8; 21], // 0x18B

    /// If MaskChipId is set to 0, identifier unique to the chip as output by GET_ID.
    /// Otherwise, set to 0h.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
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
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
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
