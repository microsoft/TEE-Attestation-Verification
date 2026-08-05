// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG and Crypt32 cryptographic backend.

use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::time::Duration;

use windows::core::{Error as WindowsError, PCWSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Security::Cryptography::*;

use super::x509_certificate::Certificate;
use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, RsaPkcs1v15SignatureKeyAlgorithm,
    RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

pub struct Key {
    handle: KeyHandle,
    algorithm: SignatureKeyAlgorithm,
}

pub struct Signature {
    bytes: Vec<u8>,
    algorithm: SignatureKeyAlgorithm,
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        checked_u32_len("SPKI DER", spki_der.len())?;

        let mut decoded_size = 0u32;
        unsafe {
            CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                spki_der,
                0,
                None,
                None,
                &mut decoded_size,
            )
        }
        .map_err(|e| operation_error("CryptDecodeObjectEx SPKI size query", e))?;
        if decoded_size < checked_struct_size::<CERT_PUBLIC_KEY_INFO>()? {
            return Err("CryptDecodeObjectEx returned an undersized CERT_PUBLIC_KEY_INFO".into());
        }

        let decoded_size_usize = decoded_size as usize;
        let word_size = size_of::<usize>();
        let word_count = decoded_size_usize
            .checked_add(word_size - 1)
            .ok_or("Decoded SPKI size overflow")?
            / word_size;
        let mut decoded = vec![0usize; word_count];
        let decoded_capacity = word_count
            .checked_mul(word_size)
            .ok_or("Decoded SPKI allocation size overflow")?;
        debug_assert!(align_of::<usize>() >= align_of::<CERT_PUBLIC_KEY_INFO>());

        let mut actual_size = decoded_size;
        unsafe {
            CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                spki_der,
                0,
                None,
                Some(decoded.as_mut_ptr().cast::<c_void>()),
                &mut actual_size,
            )
        }
        .map_err(|e| operation_error("CryptDecodeObjectEx SPKI decode", e))?;
        if actual_size as usize > decoded_capacity
            || actual_size < checked_struct_size::<CERT_PUBLIC_KEY_INFO>()?
        {
            return Err("CryptDecodeObjectEx returned an invalid decoded SPKI size".into());
        }

        let public_key_info = decoded.as_ptr().cast::<CERT_PUBLIC_KEY_INFO>();
        let mut handle = BCRYPT_KEY_HANDLE::default();
        unsafe {
            CryptImportPublicKeyInfoEx2(
                X509_ASN_ENCODING,
                public_key_info,
                CRYPT_IMPORT_PUBLIC_KEY_FLAGS::default(),
                None,
                &mut handle,
            )
        }
        .map_err(|e| operation_error("CryptImportPublicKeyInfoEx2", e))?;
        let handle = KeyHandle::new(handle)?;
        validate_imported_key(&handle, algorithm)?;

        Ok(Self { handle, algorithm })
    }
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        checked_u32_len("signature", signature.len())?;

        let bytes = match algorithm {
            SignatureKeyAlgorithm::Ec(ec_algorithm) => {
                parse_der_ecdsa_signature(signature, ec_algorithm)?
            }
            SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
                signature.to_vec()
            }
        };

        Ok(Self { bytes, algorithm })
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let expected_len = algorithm.scalar_byte_len();
        if r.len() != expected_len || s.len() != expected_len {
            return Err(format!(
                "Invalid ECDSA {} component length: expected {}, got r={} s={}",
                algorithm.name(),
                expected_len,
                r.len(),
                s.len()
            )
            .into());
        }

        let mut bytes = Vec::with_capacity(algorithm.fixed_signature_byte_len());
        bytes.extend_from_slice(r);
        bytes.extend_from_slice(s);
        checked_u32_len("ECDSA signature", bytes.len())?;

        Ok(Self {
            bytes,
            algorithm: SignatureKeyAlgorithm::Ec(algorithm),
        })
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        Certificate::from_pem(pem)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        Certificate::from_pem_chain(pem)
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        Certificate::from_der(der)
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        cert.to_pem()
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.public_key_spki_der()
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.get_extension_value_by_oid(oid)
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        cert.subject_name()
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        cert.issuer_name()
    }

    fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.subject_name_der()
    }

    fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.issuer_name_der()
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: Duration) -> Result<bool> {
        cert.is_valid_at(unix_time)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        Ok(cert.version())
    }

    fn basic_constraints(cert: &Self::Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.basic_constraints()
    }

    fn key_usage(cert: &Self::Certificate) -> Result<Option<super::KeyUsage>> {
        cert.key_usage()
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        cert.extension_criticality(oid)
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        cert.critical_extension_oids()
    }
}

impl CryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    fn digest(algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        checked_u32_len("digest input", bytes.len())?;

        let provider = AlgorithmHandle::open(hash_algorithm_id(algorithm), digest_name(algorithm))?;
        let hash = HashHandle::create(&provider, digest_name(algorithm))?;
        nt_success(
            unsafe { BCryptHashData(hash.0, bytes, 0) },
            &format!("BCryptHashData {}", digest_name(algorithm)),
        )?;

        let mut output = vec![0u8; algorithm.byte_len()];
        checked_u32_len("digest output", output.len())?;
        nt_success(
            unsafe { BCryptFinishHash(hash.0, &mut output, 0) },
            &format!("BCryptFinishHash {}", digest_name(algorithm)),
        )?;
        Ok(output)
    }

    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        if !compatible_key_and_signature(key.algorithm, signature.algorithm) {
            return Err(format!(
                "Signature algorithm {:?} does not match key algorithm {:?}",
                signature.algorithm, key.algorithm
            )
            .into());
        }

        checked_u32_len("signature", signature.bytes.len())?;
        let digest = Self::digest(signature.algorithm.digest(), signed_bytes)?;
        let digest_id = hash_algorithm_id(signature.algorithm.digest());
        let operation = signature_verification_name(signature.algorithm);

        let status = match signature.algorithm {
            SignatureKeyAlgorithm::Ec(_) => unsafe {
                BCryptVerifySignature(
                    key.handle.0,
                    None,
                    &digest,
                    &signature.bytes,
                    BCRYPT_FLAGS::default(),
                )
            },
            SignatureKeyAlgorithm::RsaPss(algorithm) => {
                let padding = BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: digest_id,
                    cbSalt: checked_u32_len("RSA-PSS salt", algorithm.salt_len())?,
                };
                unsafe {
                    BCryptVerifySignature(
                        key.handle.0,
                        Some((&padding as *const BCRYPT_PSS_PADDING_INFO).cast::<c_void>()),
                        &digest,
                        &signature.bytes,
                        BCRYPT_PAD_PSS,
                    )
                }
            }
            SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
                let padding = BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: digest_id,
                };
                unsafe {
                    BCryptVerifySignature(
                        key.handle.0,
                        Some((&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast::<c_void>()),
                        &digest,
                        &signature.bytes,
                        BCRYPT_PAD_PKCS1,
                    )
                }
            }
        };

        nt_success(status, operation)
    }

    fn verify_chain(
        trusted_cert: &Certificate,
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
        unix_time: Option<Duration>,
    ) -> Result<()> {
        let root_store = CertStore::memory("exclusive root")?;
        root_store.add_certificate(trusted_cert, "trusted certificate")?;

        let intermediate_store = CertStore::memory("restricted intermediate")?;
        intermediate_store.add_certificate(trusted_cert, "trusted certificate discovery copy")?;
        for (index, cert) in untrusted_chain.iter().enumerate() {
            intermediate_store
                .add_certificate(cert, &format!("untrusted intermediate certificate {index}"))?;
        }

        let mut engine_config = CERT_CHAIN_ENGINE_CONFIG {
            cbSize: checked_struct_size::<CERT_CHAIN_ENGINE_CONFIG>()?,
            hRestrictedOther: intermediate_store.0,
            hExclusiveRoot: root_store.0,
            dwExclusiveFlags: CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG,
            ..Default::default()
        };
        let engine = ChainEngine::create(&mut engine_config)?;
        let leaf_context = CertContext::from_certificate(leaf, "leaf certificate")?;

        let mut chain_para = CERT_CHAIN_PARA {
            cbSize: checked_struct_size::<CERT_CHAIN_PARA>()?,
            ..Default::default()
        };
        let file_time = unix_time.map(unix_duration_to_filetime).transpose()?;
        let time_ptr = file_time.as_ref().map(|time| time as *const FILETIME);
        let chain = ChainContext::build(
            &engine,
            &leaf_context,
            &mut chain_para,
            time_ptr,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA,
        )?;
        let chain_error_status = chain.error_status();
        if chain_error_status != 0 {
            return Err(format!(
                "CertGetCertificateChain returned trust error status 0x{chain_error_status:08X}"
            )
            .into());
        }

        let policy_para = CERT_CHAIN_POLICY_PARA {
            cbSize: checked_struct_size::<CERT_CHAIN_POLICY_PARA>()?,
            ..Default::default()
        };
        let mut policy_status = CERT_CHAIN_POLICY_STATUS {
            cbSize: checked_struct_size::<CERT_CHAIN_POLICY_STATUS>()?,
            ..Default::default()
        };
        let verified = unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_BASE,
                chain.0,
                &policy_para,
                &mut policy_status,
            )
        };
        if !verified.as_bool() {
            return Err(operation_error(
                "CertVerifyCertificateChainPolicy",
                WindowsError::from_win32(),
            ));
        }
        if policy_status.dwError != 0 {
            return Err(format!(
                "Certificate chain policy verification failed with error 0x{:08X} at chain {} element {}",
                policy_status.dwError, policy_status.lChainIndex, policy_status.lElementIndex
            )
            .into());
        }

        Ok(())
    }
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.algorithm
    }
}

fn validate_imported_key(handle: &KeyHandle, requested: SignatureKeyAlgorithm) -> Result<()> {
    let actual_name = bcrypt_string_property(handle.0.into(), BCRYPT_ALGORITHM_NAME)?;
    let actual_bits = bcrypt_u32_property(handle.0.into(), BCRYPT_KEY_LENGTH)?;

    match requested {
        SignatureKeyAlgorithm::Ec(algorithm) => {
            let expected_name = match algorithm {
                EcSignatureKeyAlgorithm::P256 => "ECDSA_P256",
                EcSignatureKeyAlgorithm::P384 => "ECDSA_P384",
                EcSignatureKeyAlgorithm::P521 => "ECDSA_P521",
            };
            let expected_curve = match algorithm {
                EcSignatureKeyAlgorithm::P256 => "nistP256",
                EcSignatureKeyAlgorithm::P384 => "nistP384",
                EcSignatureKeyAlgorithm::P521 => "nistP521",
            };
            let expected_bits = match algorithm {
                EcSignatureKeyAlgorithm::P256 => 256,
                EcSignatureKeyAlgorithm::P384 => 384,
                EcSignatureKeyAlgorithm::P521 => 521,
            };
            if actual_bits != expected_bits {
                return Err(format!(
                    "ECDSA public key does not match {}: imported algorithm={} strength={}",
                    algorithm.name(),
                    actual_name,
                    actual_bits
                )
                .into());
            }
            if actual_name == "ECDSA" {
                let actual_curve = bcrypt_string_property(handle.0.into(), BCRYPT_ECC_CURVE_NAME)
                    .map_err(|e| {
                    format!(
                        "Failed to query curve name for generic ECDSA {} public key: {e}",
                        algorithm.name()
                    )
                })?;
                if actual_curve != expected_curve {
                    return Err(format!(
                        "ECDSA public key does not match {}: imported algorithm={} curve={} strength={}",
                        algorithm.name(),
                        actual_name,
                        actual_curve,
                        actual_bits
                    )
                    .into());
                }
            } else if actual_name != expected_name {
                return Err(format!(
                    "ECDSA public key does not match {}: imported algorithm={} strength={}",
                    algorithm.name(),
                    actual_name,
                    actual_bits
                )
                .into());
            }
        }
        SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
            if actual_name != "RSA" && actual_name != "RSA_SIGN" {
                return Err(format!(
                    "RSA public key required, but imported algorithm was {actual_name}"
                )
                .into());
            }
        }
    }

    Ok(())
}

fn bcrypt_u32_property(handle: BCRYPT_HANDLE, property: PCWSTR) -> Result<u32> {
    let mut output = [0u8; size_of::<u32>()];
    let mut written = 0u32;
    nt_success(
        unsafe { BCryptGetProperty(handle, property, Some(&mut output), &mut written, 0) },
        "BCryptGetProperty u32",
    )?;
    if written != checked_struct_size::<u32>()? {
        return Err(
            format!("BCryptGetProperty returned {written} bytes for a u32 property").into(),
        );
    }
    Ok(u32::from_ne_bytes(output))
}

fn bcrypt_string_property(handle: BCRYPT_HANDLE, property: PCWSTR) -> Result<String> {
    let mut size = 0u32;
    nt_success(
        unsafe { BCryptGetProperty(handle, property, None, &mut size, 0) },
        "BCryptGetProperty string size query",
    )?;
    if size == 0 || size % 2 != 0 {
        return Err(format!("BCryptGetProperty returned invalid UTF-16 size {size}").into());
    }

    let mut output = vec![0u8; size as usize];
    checked_u32_len("BCrypt string property buffer", output.len())?;
    let mut written = size;
    nt_success(
        unsafe { BCryptGetProperty(handle, property, Some(&mut output), &mut written, 0) },
        "BCryptGetProperty string",
    )?;
    if written > size || written % 2 != 0 {
        return Err(format!("BCryptGetProperty returned invalid UTF-16 length {written}").into());
    }

    let mut units = Vec::with_capacity(written as usize / 2);
    for bytes in output[..written as usize].chunks_exact(2) {
        units.push(u16::from_ne_bytes([bytes[0], bytes[1]]));
    }
    let terminator = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("BCrypt string property was not null-terminated")?;
    if units[terminator..].iter().any(|unit| *unit != 0) {
        return Err("BCrypt string property contained data after its null terminator".into());
    }
    String::from_utf16(&units[..terminator])
        .map_err(|e| format!("BCrypt string property was not valid UTF-16: {e}").into())
}

fn parse_der_ecdsa_signature(
    signature: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
    let mut sequence = DerReader::new(signature);
    if sequence.read_byte()? != 0x30 {
        return Err("ECDSA signature must be a DER SEQUENCE".into());
    }
    let sequence_len = sequence.read_length()?;
    let sequence_bytes = sequence.read_exact(sequence_len)?;
    if !sequence.is_empty() {
        return Err("ECDSA signature has trailing data after DER SEQUENCE".into());
    }

    let mut integers = DerReader::new(sequence_bytes);
    let r = integers.read_positive_integer("r")?;
    let s = integers.read_positive_integer("s")?;
    if !integers.is_empty() {
        return Err("ECDSA signature has trailing data after r and s".into());
    }

    let scalar_len = algorithm.scalar_byte_len();
    let mut fixed = vec![0u8; algorithm.fixed_signature_byte_len()];
    copy_der_scalar(r, &mut fixed[..scalar_len], "r", algorithm)?;
    copy_der_scalar(s, &mut fixed[scalar_len..], "s", algorithm)?;
    Ok(fixed)
}

fn copy_der_scalar(
    integer: &[u8],
    output: &mut [u8],
    name: &str,
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<()> {
    let value = if integer[0] == 0 {
        &integer[1..]
    } else {
        integer
    };
    if value.len() > output.len() {
        return Err(format!(
            "ECDSA {} {name} component exceeds {} bytes",
            algorithm.name(),
            output.len()
        )
        .into());
    }
    let start = output.len() - value.len();
    output[start..].copy_from_slice(value);
    Ok(())
}

struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or("Unexpected end of DER ECDSA signature")?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or("DER ECDSA signature length overflow")?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or("Truncated DER ECDSA signature")?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_length(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first < 0x80 {
            return Ok(first as usize);
        }

        let length_bytes = (first & 0x7f) as usize;
        if length_bytes == 0 {
            return Err("DER ECDSA signature uses an indefinite length".into());
        }
        if length_bytes > size_of::<usize>() {
            return Err("DER ECDSA signature length does not fit usize".into());
        }

        let encoded = self.read_exact(length_bytes)?;
        if encoded[0] == 0 {
            return Err("DER ECDSA signature length has leading zeroes".into());
        }
        let mut length = 0usize;
        for byte in encoded {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(*byte as usize))
                .ok_or("DER ECDSA signature length overflow")?;
        }
        if length < 128 {
            return Err("DER ECDSA signature uses a non-minimal length".into());
        }
        Ok(length)
    }

    fn read_positive_integer(&mut self, name: &str) -> Result<&'a [u8]> {
        if self.read_byte()? != 0x02 {
            return Err(format!("ECDSA signature {name} is not a DER INTEGER").into());
        }
        let len = self.read_length()?;
        if len == 0 {
            return Err(format!("ECDSA signature {name} INTEGER is empty").into());
        }
        let integer = self.read_exact(len)?;
        if integer[0] & 0x80 != 0 {
            return Err(format!("ECDSA signature {name} INTEGER is negative").into());
        }
        if integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0 {
            return Err(format!("ECDSA signature {name} INTEGER is not minimally encoded").into());
        }
        if integer.iter().all(|byte| *byte == 0) {
            return Err(format!("ECDSA signature {name} INTEGER is zero").into());
        }
        Ok(integer)
    }
}

fn hash_algorithm_id(algorithm: DigestAlgorithm) -> PCWSTR {
    match algorithm {
        DigestAlgorithm::Sha256 => BCRYPT_SHA256_ALGORITHM,
        DigestAlgorithm::Sha384 => BCRYPT_SHA384_ALGORITHM,
        DigestAlgorithm::Sha512 => BCRYPT_SHA512_ALGORITHM,
    }
}

fn digest_name(algorithm: DigestAlgorithm) -> &'static str {
    match algorithm {
        DigestAlgorithm::Sha256 => "SHA-256",
        DigestAlgorithm::Sha384 => "SHA-384",
        DigestAlgorithm::Sha512 => "SHA-512",
    }
}

fn signature_verification_name(algorithm: SignatureKeyAlgorithm) -> &'static str {
    match algorithm {
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256) => {
            "ECDSA P-256 signature verification"
        }
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => {
            "ECDSA P-384 signature verification"
        }
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521) => {
            "ECDSA P-521 signature verification"
        }
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256) => {
            "RSA-PSS SHA-256 signature verification"
        }
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
            "RSA-PSS SHA-384 signature verification"
        }
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps512) => {
            "RSA-PSS SHA-512 signature verification"
        }
        SignatureKeyAlgorithm::RsaPkcs1v15(RsaPkcs1v15SignatureKeyAlgorithm::Rs256) => {
            "RSA PKCS#1 v1.5 SHA-256 signature verification"
        }
        SignatureKeyAlgorithm::RsaPkcs1v15(RsaPkcs1v15SignatureKeyAlgorithm::Rs384) => {
            "RSA PKCS#1 v1.5 SHA-384 signature verification"
        }
        SignatureKeyAlgorithm::RsaPkcs1v15(RsaPkcs1v15SignatureKeyAlgorithm::Rs512) => {
            "RSA PKCS#1 v1.5 SHA-512 signature verification"
        }
    }
}

fn unix_duration_to_filetime(unix_time: Duration) -> Result<FILETIME> {
    const WINDOWS_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: u64 = 10_000_000;

    let ticks = unix_time
        .as_secs()
        .checked_mul(TICKS_PER_SECOND)
        .and_then(|ticks| ticks.checked_add((unix_time.subsec_nanos() / 100) as u64))
        .and_then(|ticks| ticks.checked_add(WINDOWS_EPOCH_TICKS))
        .ok_or("Unix time does not fit Windows FILETIME")?;

    Ok(FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    })
}

fn checked_u32_len(operation: &str, len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| format!("{operation} length does not fit u32").into())
}

fn checked_struct_size<T>() -> Result<u32> {
    checked_u32_len("Windows structure", size_of::<T>())
}

fn nt_success(status: windows::Win32::Foundation::NTSTATUS, operation: &str) -> Result<()> {
    status.ok().map_err(|e| operation_error(operation, e))
}

fn operation_error(operation: &str, error: WindowsError) -> Box<dyn std::error::Error> {
    format!("{operation} failed: {error}").into()
}

struct AlgorithmHandle(BCRYPT_ALG_HANDLE);

impl AlgorithmHandle {
    fn open(algorithm: PCWSTR, name: &str) -> Result<Self> {
        let mut handle = BCRYPT_ALG_HANDLE::default();
        nt_success(
            unsafe {
                BCryptOpenAlgorithmProvider(
                    &mut handle,
                    algorithm,
                    PCWSTR::null(),
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
                )
            },
            &format!("BCryptOpenAlgorithmProvider {name}"),
        )?;
        if handle.is_invalid() {
            return Err(
                format!("BCryptOpenAlgorithmProvider {name} returned a null handle").into(),
            );
        }
        Ok(Self(handle))
    }
}

impl Drop for AlgorithmHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
        }
    }
}

struct HashHandle(BCRYPT_HASH_HANDLE);

impl HashHandle {
    fn create(provider: &AlgorithmHandle, name: &str) -> Result<Self> {
        let mut handle = BCRYPT_HASH_HANDLE::default();
        nt_success(
            unsafe { BCryptCreateHash(provider.0, &mut handle, None, None, 0) },
            &format!("BCryptCreateHash {name}"),
        )?;
        if handle.is_invalid() {
            return Err(format!("BCryptCreateHash {name} returned a null handle").into());
        }
        Ok(Self(handle))
    }
}

impl Drop for HashHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { BCryptDestroyHash(self.0) };
        }
    }
}

struct KeyHandle(BCRYPT_KEY_HANDLE);

impl KeyHandle {
    fn new(handle: BCRYPT_KEY_HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            return Err("CryptImportPublicKeyInfoEx2 returned a null key handle".into());
        }
        Ok(Self(handle))
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { BCryptDestroyKey(self.0) };
        }
    }
}

struct CertStore(HCERTSTORE);

impl CertStore {
    fn memory(name: &str) -> Result<Self> {
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                X509_ASN_ENCODING,
                None,
                CERT_STORE_CREATE_NEW_FLAG,
                None,
            )
        }
        .map_err(|e| operation_error(&format!("CertOpenStore {name}"), e))?;
        Ok(Self(handle))
    }

    fn add_certificate(&self, cert: &Certificate, name: &str) -> Result<()> {
        let der = cert.to_der()?;
        checked_u32_len(name, der.len())?;
        unsafe {
            CertAddEncodedCertificateToStore(
                Some(self.0),
                X509_ASN_ENCODING,
                &der,
                CERT_STORE_ADD_ALWAYS,
                None,
            )
        }
        .map_err(|e| operation_error(&format!("CertAddEncodedCertificateToStore {name}"), e))
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CertCloseStore(Some(self.0), 0) };
        }
    }
}

struct CertContext(*const CERT_CONTEXT);

impl CertContext {
    fn from_certificate(cert: &Certificate, name: &str) -> Result<Self> {
        let der = cert.to_der()?;
        checked_u32_len(name, der.len())?;
        let context = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, &der) };
        if context.is_null() {
            return Err(operation_error(
                &format!("CertCreateCertificateContext {name}"),
                WindowsError::from_win32(),
            ));
        }
        Ok(Self(context))
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
        }
    }
}

struct ChainEngine(HCERTCHAINENGINE);

impl ChainEngine {
    fn create(config: &mut CERT_CHAIN_ENGINE_CONFIG) -> Result<Self> {
        let mut handle = HCERTCHAINENGINE::default();
        unsafe { CertCreateCertificateChainEngine(config, &mut handle) }
            .map_err(|e| operation_error("CertCreateCertificateChainEngine", e))?;
        if handle.is_invalid() {
            return Err("CertCreateCertificateChainEngine returned a null handle".into());
        }
        Ok(Self(handle))
    }
}

impl Drop for ChainEngine {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { CertFreeCertificateChainEngine(Some(self.0)) };
        }
    }
}

struct ChainContext(*const CERT_CHAIN_CONTEXT);

impl ChainContext {
    fn build(
        engine: &ChainEngine,
        leaf: &CertContext,
        parameters: &mut CERT_CHAIN_PARA,
        time: Option<*const FILETIME>,
        flags: u32,
    ) -> Result<Self> {
        let mut context = std::ptr::null_mut();
        unsafe {
            CertGetCertificateChain(
                Some(engine.0),
                leaf.0,
                time,
                None,
                parameters,
                flags,
                None,
                &mut context,
            )
        }
        .map_err(|e| operation_error("CertGetCertificateChain", e))?;
        if context.is_null() {
            return Err("CertGetCertificateChain returned a null chain context".into());
        }
        Ok(Self(context))
    }

    fn error_status(&self) -> u32 {
        unsafe { (*self.0).TrustStatus.dwErrorStatus }
    }
}

impl Drop for ChainContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CertFreeCertificateChain(self.0) };
        }
    }
}
