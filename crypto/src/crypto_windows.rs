// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{c_void, CString};
use std::mem::{align_of, size_of};
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows::core::{Free, Owned, PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::{
    FILETIME, HLOCAL, STATUS_INVALID_PARAMETER, STATUS_INVALID_SIGNATURE,
};
use windows::Win32::Security::Cryptography::{
    self as Crypto32, BCryptCreateHash, BCryptFinishHash, BCryptGetProperty, BCryptHashData,
    BCryptOpenAlgorithmProvider, BCryptVerifySignature, BCRYPT_KEY_HANDLE,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS,
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM, BCRYPT_SIGNATURE_LENGTH,
};

use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, SignatureBackend, SignatureKeyAlgorithm,
};

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";
const X509_PEM_BEGIN: &str = "-----BEGIN X509 CERTIFICATE-----";
const X509_PEM_END: &str = "-----END X509 CERTIFICATE-----";

// RFC 9090 §2: https://www.rfc-editor.org/rfc/rfc9090.html#section-2
const MAX_OID_FIRST_ARC: u32 = 2;
const MAX_OID_SECOND_ARC_FOR_FIRST_TWO_ROOTS: u64 = 39;

// https://learn.microsoft.com/windows/win32/api/minwinbase/ns-minwinbase-filetime
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
const FILETIME_UNIX_EPOCH_OFFSET_TICKS: u64 = 116_444_736_000_000_000;

// RFC 5280 §4.2.1.9: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9
const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";
// RFC 5280 §4.2.1.3: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3
const KEY_USAGE_OID: &str = "2.5.29.15";

pub struct Crypto;

/// Owns Crypt32-validated DER and recreates operation-scoped contexts so handles are not shared.
#[derive(Clone, Debug)]
pub struct Certificate(Arc<[u8]>);

struct NativeCertificate(NonNull<Crypto32::CERT_CONTEXT>);

/// Owns CNG-validated SPKI DER and recreates operation-scoped keys so handles are not shared.
pub struct Key {
    spki: Vec<u8>,
    algorithm: SignatureKeyAlgorithm,
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.algorithm
    }
}

pub struct Signature {
    bytes: Vec<u8>,
    algorithm: SignatureKeyAlgorithm,
}

impl Certificate {
    fn from_der(der: &[u8]) -> Result<Self> {
        let context = NativeCertificate::from_der(der)?;
        Ok(Self(Arc::from(context.der()?)))
    }

    fn der(&self) -> &[u8] {
        &self.0
    }

    fn with_context<T>(
        &self,
        operation: impl for<'a> FnOnce(&'a NativeCertificate) -> Result<T>,
    ) -> Result<T> {
        let context = NativeCertificate::from_der(self.der())?;
        operation(&context)
    }
}

impl NativeCertificate {
    fn from_der(der: &[u8]) -> Result<Self> {
        native_len(der)?;
        let context =
            unsafe { Crypto32::CertCreateCertificateContext(Crypto32::X509_ASN_ENCODING, der) };
        NonNull::new(context)
            .map(Self)
            .ok_or_else(|| windows::core::Error::from_win32().into())
    }

    fn as_ptr(&self) -> *const Crypto32::CERT_CONTEXT {
        self.0.as_ptr()
    }

    fn context(&self) -> &Crypto32::CERT_CONTEXT {
        unsafe { self.0.as_ref() }
    }

    fn info(&self) -> Result<&Crypto32::CERT_INFO> {
        unsafe { self.context().pCertInfo.as_ref() }.ok_or_else(|| "Null CERT_INFO".into())
    }

    fn der(&self) -> Result<&[u8]> {
        let context = self.context();
        unsafe { native_slice(context.pbCertEncoded, context.cbCertEncoded, self) }
    }

    fn extensions(&self) -> Result<&[Crypto32::CERT_EXTENSION]> {
        let info = self.info()?;
        unsafe { native_slice(info.rgExtension, info.cExtension, self) }
    }

    fn extension(&self, oid: &str) -> Result<Option<&Crypto32::CERT_EXTENSION>> {
        let arcs = oid.split('.').collect::<Vec<_>>();
        if arcs.len() < 2
            || arcs
                .iter()
                .any(|arc| arc.is_empty() || !arc.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err("Invalid dotted-decimal OID".into());
        }
        let first: u32 = arcs[0].parse()?;
        let second: u64 = arcs[1].parse()?;
        if first > MAX_OID_FIRST_ARC
            || (first < MAX_OID_FIRST_ARC && second > MAX_OID_SECOND_ARC_FOR_FIRST_TWO_ROOTS)
        {
            return Err("Invalid dotted-decimal OID".into());
        }
        let oid = CString::new(oid)?;
        let extensions = self.extensions()?;
        if extensions.is_empty() {
            return Ok(None);
        }
        Ok(unsafe { Crypto32::CertFindExtension(PCSTR(oid.as_ptr().cast()), extensions).as_ref() })
    }
}

impl Drop for NativeCertificate {
    fn drop(&mut self) {
        // Microsoft documents this as always returning nonzero, so discard it.
        // https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatecontext#return-value
        let _ = unsafe { Crypto32::CertFreeCertificateContext(Some(self.as_ptr())) };
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let key = import_key(spki)?;
        let actual = query_buffer(|output, len| {
            unsafe {
                BCryptGetProperty(
                    (*key).into(),
                    Crypto32::BCRYPT_ALGORITHM_NAME,
                    output,
                    len,
                    0,
                )
            }
            .ok()?;
            Ok(())
        })?;
        let chunks = actual.chunks_exact(size_of::<u16>());
        if !chunks.remainder().is_empty() {
            return Err("BCRYPT_ALGORITHM_NAME returned invalid utf-16".into());
        }
        let actual = String::from_utf16(
          chunks
            .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))
            .collect::<Vec<_>>()
            .strip_suffix(&[0])
            .ok_or("BCRYPT_ALGORITHM_NAME is not null-terminated")?)?;
        let compatible = match algorithm {
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256) => actual == "ECDSA_P256",
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => actual == "ECDSA_P384",
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521) => actual == "ECDSA_P521",
            SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
                matches!(actual.as_str(), "RSA" | "RSA_SIGN")
            }
        };
        if !compatible {
            return Err(format!(
                "Public key algorithm {actual} does not match requested algorithm {algorithm:?}"
            )
            .into());
        }

        Ok(Self {
            spki: spki.to_vec(),
            algorithm,
        })
    }
}

impl SignatureBackend for Signature {
    fn from_bytes(bytes: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let bytes = match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => {
                let decoded = decode::<Crypto32::CERT_ECC_SIGNATURE>(bytes)?;
                let width = algorithm.scalar_byte_len();
                let mut output = vec![0; width * 2];
                let mut r =
                    unsafe { native_slice(decoded.r.pbData, decoded.r.cbData, &decoded)?.to_vec() };
                let mut s =
                    unsafe { native_slice(decoded.s.pbData, decoded.s.cbData, &decoded)?.to_vec() };
                r.reverse();
                s.reverse();
                pad_component(&r, &mut output[..width])?;
                pad_component(&s, &mut output[width..])?;
                output
            }
            SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
                bytes.to_vec()
            }
        };
        Ok(Self { bytes, algorithm })
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let mut bytes = vec![0; algorithm.fixed_signature_byte_len()];
        let width = algorithm.scalar_byte_len();
        pad_component(r, &mut bytes[..width])?;
        pad_component(s, &mut bytes[width..])?;
        Ok(Self {
            bytes,
            algorithm: SignatureKeyAlgorithm::Ec(algorithm),
        })
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Certificate> {
        Certificate::from_der(&decode_pem(pem)?)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Certificate>> {
        let pem = std::str::from_utf8(pem)?;
        let mut boundaries = pem
            .match_indices(PEM_END)
            .chain(pem.match_indices(X509_PEM_END))
            .map(|(start, boundary)| start + boundary.len())
            .collect::<Vec<_>>();
        boundaries.sort_unstable();

        let remaining = &pem[boundaries.last().copied().unwrap_or_default()..];
        if remaining.contains(PEM_BEGIN) || remaining.contains(X509_PEM_BEGIN) {
            return Err("Unterminated certificate PEM".into());
        }

        std::iter::once(0)
            .chain(boundaries.iter().copied())
            .zip(boundaries.iter().copied())
            .map(|(start, end)| &pem[start..end])
            .filter(|record| record.contains(PEM_BEGIN) || record.contains(X509_PEM_BEGIN))
            .map(|record| {
                if record.contains(PEM_BEGIN) && !record.ends_with(PEM_END) {
                    Err("Mismatched certificate PEM boundaries".into())
                } else if record.contains(X509_PEM_BEGIN) && !record.ends_with(X509_PEM_END) {
                    Err("Mismatched certificate PEM boundaries".into())
                } else {
                    Certificate::from_der(&decode_pem(record.as_bytes())?)
                }
            })
            .collect()
    }

    fn from_der(der: &[u8]) -> Result<Certificate> {
        Certificate::from_der(der)
    }

    fn to_der(cert: &Certificate) -> Result<Vec<u8>> {
        Ok(cert.der().to_vec())
    }

    fn to_pem(cert: &Certificate) -> Result<String> {
        native_len(cert.der())?;
        let flags = Crypto32::CRYPT_STRING(
            Crypto32::CRYPT_STRING_BASE64HEADER.0 | Crypto32::CRYPT_STRING_NOCR,
        );
        let mut output = query_buffer(|output, len| {
            let output = output.map(|output| PSTR(output.as_mut_ptr()));
            if !unsafe { Crypto32::CryptBinaryToStringA(cert.der(), flags, output, len) }.as_bool()
            {
                return Err(windows::core::Error::from_win32().into());
            }
            Ok(())
        })?;
        if output.last() == Some(&0) {
            output.pop();
        }
        Ok(String::from_utf8(output)?)
    }

    fn get_public_key(cert: &Certificate) -> Result<Vec<u8>> {
        cert.with_context(|context| {
            encode(
                Crypto32::X509_PUBLIC_KEY_INFO,
                &context.info()?.SubjectPublicKeyInfo,
            )
        })
    }

    fn get_extension_value_by_oid(cert: &Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.with_context(|context| {
            context
                .extension(oid)?
                .map(|ext| unsafe {
                    native_slice(ext.Value.pbData, ext.Value.cbData, context).map(<[u8]>::to_vec)
                })
                .transpose()
        })
    }

    fn subject_name(cert: &Certificate) -> String {
        cert.with_context(|context| name(&context.info()?.Subject))
            .unwrap_or_else(|_| "<unavailable certificate name>".into())
    }

    fn issuer_name(cert: &Certificate) -> String {
        cert.with_context(|context| name(&context.info()?.Issuer))
            .unwrap_or_else(|_| "<unavailable certificate name>".into())
    }

    fn subject_name_der(cert: &Certificate) -> Result<Vec<u8>> {
        cert.with_context(|context| {
            let value = &context.info()?.Subject;
            Ok(unsafe { native_slice(value.pbData, value.cbData, context)?.to_vec() })
        })
    }

    fn issuer_name_der(cert: &Certificate) -> Result<Vec<u8>> {
        cert.with_context(|context| {
            let value = &context.info()?.Issuer;
            Ok(unsafe { native_slice(value.pbData, value.cbData, context)?.to_vec() })
        })
    }

    fn is_valid_at(cert: &Certificate, unix_time: Duration) -> Result<bool> {
        let ticks = unix_time
            .as_secs()
            .checked_mul(FILETIME_TICKS_PER_SECOND)
            .and_then(|ticks| ticks.checked_add(FILETIME_UNIX_EPOCH_OFFSET_TICKS))
            .ok_or("Unix time does not fit FILETIME")?;
        let time = FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        cert.with_context(|context| {
            Ok(unsafe { Crypto32::CertVerifyTimeValidity(Some(&time), context.info()?) } == 0)
        })
    }

    fn version(cert: &Certificate) -> Result<u8> {
        cert.with_context(|context| Ok(context.info()?.dwVersion.try_into()?))
    }

    fn basic_constraints(cert: &Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.with_context(|context| {
            let Some(ext) = context.extension(BASIC_CONSTRAINTS_OID)? else {
                return Ok(None);
            };
            let encoded = unsafe { native_slice(ext.Value.pbData, ext.Value.cbData, context)? };
            let decoded = decode::<Crypto32::CERT_BASIC_CONSTRAINTS2_INFO>(encoded)?;
            Ok(Some(super::BasicConstraints {
                critical: ext.fCritical.as_bool(),
                ca: decoded.fCA.as_bool(),
                path_len_constraint: decoded
                    .fPathLenConstraint
                    .as_bool()
                    .then_some(decoded.dwPathLenConstraint as usize),
            }))
        })
    }

    fn key_usage(cert: &Certificate) -> Result<Option<super::KeyUsage>> {
        cert.with_context(|context| {
            if context.extension(KEY_USAGE_OID)?.is_none() {
                return Ok(None);
            }
            let mut usage = [0];
            unsafe {
                Crypto32::CertGetIntendedKeyUsage(
                    Crypto32::X509_ASN_ENCODING,
                    context.info()?,
                    &mut usage,
                )
            }?;
            Ok(Some(super::KeyUsage {
                key_cert_sign: usage[0] & Crypto32::CERT_KEY_CERT_SIGN_KEY_USAGE as u8 != 0,
            }))
        })
    }

    fn extension_criticality(cert: &Certificate, oid: &str) -> Result<Option<bool>> {
        cert.with_context(|context| Ok(context.extension(oid)?.map(|ext| ext.fCritical.as_bool())))
    }

    fn critical_extension_oids(cert: &Certificate) -> Vec<String> {
        cert.with_context(|context| {
            Ok(context
                .extensions()?
                .iter()
                .filter(|ext| ext.fCritical.as_bool())
                .filter_map(|ext| unsafe { ext.pszObjId.to_string().ok() })
                .collect())
        })
        .unwrap_or_default()
    }
}

impl CryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    fn digest(algorithm: DigestAlgorithm, input: &[u8]) -> Result<Vec<u8>> {
        let provider = into_owned(|handle| {
            unsafe {
                BCryptOpenAlgorithmProvider(
                    handle,
                    hash_id(algorithm),
                    PCWSTR::null(),
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
                )
            }
            .ok()
        })?;
        let hash = into_owned(|handle| {
            unsafe { BCryptCreateHash(*provider, handle, None, None, 0) }.ok()
        })?;
        for chunk in input.chunks(u32::MAX as usize) {
            unsafe { BCryptHashData(*hash, chunk, 0) }.ok()?;
        }
        let mut output = vec![0; algorithm.byte_len()];
        unsafe { BCryptFinishHash(*hash, &mut output, 0) }.ok()?;
        Ok(output)
    }

    fn verify_signature(key: &Key, signature: &Signature, input: &[u8]) -> Result<()> {
        if !compatible_key_and_signature(key.algorithm, signature.algorithm) {
            return Err("Signature algorithm does not match key algorithm".into());
        }
        let handle = import_key(&key.spki)?;
        let mut signature_len = [0; size_of::<u32>()];
        let mut len = 0;
        unsafe {
            BCryptGetProperty(
                (*handle).into(),
                BCRYPT_SIGNATURE_LENGTH,
                Some(&mut signature_len),
                &mut len,
                0,
            )
        }
        .ok()?;
        if len as usize != signature_len.len()
            || signature.bytes.len() != u32::from_ne_bytes(signature_len) as usize
        {
            return Err("signature verification failed".into());
        }
        let digest = Self::digest(signature.algorithm.digest(), input)?;
        let hash = hash_id(signature.algorithm.digest());
        let status = match signature.algorithm {
            // With dwFlags == 0, BCryptVerifySignature requires pPaddingInfo == NULL.
            // https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature
            SignatureKeyAlgorithm::Ec(_) => unsafe {
                BCryptVerifySignature(*handle, None, &digest, &signature.bytes, Default::default())
            },
            SignatureKeyAlgorithm::RsaPss(algorithm) => {
                let padding = BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: hash,
                    cbSalt: algorithm.salt_len() as u32,
                };
                unsafe {
                    BCryptVerifySignature(
                        *handle,
                        Some((&padding as *const BCRYPT_PSS_PADDING_INFO).cast()),
                        &digest,
                        &signature.bytes,
                        BCRYPT_PAD_PSS,
                    )
                }
            }
            SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
                let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: hash };
                unsafe {
                    BCryptVerifySignature(
                        *handle,
                        Some((&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast()),
                        &digest,
                        &signature.bytes,
                        BCRYPT_PAD_PKCS1,
                    )
                }
            }
        };
        if status == STATUS_INVALID_SIGNATURE || status == STATUS_INVALID_PARAMETER {
            Err("signature verification failed".into())
        } else {
            status.ok().map_err(Into::into)
        }
    }

    fn verify_chain(
        trusted_cert: &Self::Certificate,
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
        unix_time: Option<Duration>,
    ) -> Result<()> {
        super::x509_policy::verify_certificate_path(
            verify_x509_certificate_signature,
            trusted_cert,
            untrusted_chain,
            leaf,
        )?;

        let singleton_path = untrusted_chain.is_empty() && trusted_cert.der() == leaf.der();
        let policy_path = std::iter::once(trusted_cert)
            .chain(untrusted_chain.iter().copied())
            .chain((!singleton_path).then_some(leaf));
        super::x509_policy::rfc5280_policy::<Crypto, _>(
            policy_path,
            unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH)?),
        )
    }
}

fn verify_x509_certificate_signature(issuer: &Certificate, subject: &Certificate) -> Result<()> {
    issuer.with_context(|issuer| {
        subject.with_context(|subject| unsafe {
            Crypto32::CryptVerifyCertificateSignatureEx(
                None,
                Crypto32::X509_ASN_ENCODING,
                Crypto32::CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
                subject.as_ptr().cast(),
                Crypto32::CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
                Some(issuer.as_ptr().cast()),
                Default::default(),
                None,
            )
            .map_err(Into::into)
        })
    })
}

trait DecodeType {
    const KIND: PCSTR;
}

impl DecodeType for Crypto32::CERT_ECC_SIGNATURE {
    const KIND: PCSTR = Crypto32::X509_ECC_SIGNATURE;
}

impl DecodeType for Crypto32::CERT_BASIC_CONSTRAINTS2_INFO {
    const KIND: PCSTR = Crypto32::X509_BASIC_CONSTRAINTS2;
}

impl DecodeType for Crypto32::CERT_PUBLIC_KEY_INFO {
    const KIND: PCSTR = Crypto32::X509_PUBLIC_KEY_INFO;
}

struct Decoded<T> {
    value: NonNull<T>,
    _allocation: Owned<HLOCAL>,
}

impl<T> Deref for Decoded<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.value.as_ref() }
    }
}

fn decode<T: DecodeType>(input: &[u8]) -> Result<Decoded<T>> {
    native_len(input)?;
    let mut pointer = std::ptr::null_mut::<c_void>();
    let mut len = 0;
    unsafe {
        Crypto32::CryptDecodeObjectEx(
            Crypto32::X509_ASN_ENCODING,
            T::KIND,
            input,
            Crypto32::CRYPT_DECODE_ALLOC_FLAG,
            None,
            Some((&mut pointer as *mut *mut c_void).cast()),
            &mut len,
        )
    }?;
    NonNull::<c_void>::new(pointer).ok_or("CryptDecodeObjectEx returned null")?;
    let allocation = unsafe { Owned::new(HLOCAL(pointer)) };
    if (len as usize) < size_of::<T>() {
        return Err("CryptDecodeObjectEx returned a truncated value".into());
    }
    let value =
        NonNull::new(allocation.0.cast::<T>()).ok_or("CryptDecodeObjectEx returned null")?;
    if value.as_ptr() as usize % align_of::<T>() != 0 {
        return Err("Misaligned decoded Windows pointer".into());
    }
    Ok(Decoded {
        value,
        _allocation: allocation,
    })
}

fn encode<T>(kind: PCSTR, value: &T) -> Result<Vec<u8>> {
    let mut pointer = std::ptr::null_mut::<c_void>();
    let mut len = 0;
    unsafe {
        Crypto32::CryptEncodeObjectEx(
            Crypto32::X509_ASN_ENCODING,
            kind,
            (value as *const T).cast(),
            Crypto32::CRYPT_ENCODE_ALLOC_FLAG,
            None,
            Some((&mut pointer as *mut *mut c_void).cast()),
            &mut len,
        )
    }?;
    NonNull::new(pointer).ok_or("CryptEncodeObjectEx returned null")?;
    let allocation = unsafe { Owned::new(HLOCAL(pointer)) };
    Ok(unsafe { native_slice(pointer.cast(), len, &allocation)?.to_vec() })
}

fn decode_pem(pem: &[u8]) -> Result<Vec<u8>> {
    native_len(pem)?;
    let flags = Crypto32::CRYPT_STRING(
        Crypto32::CRYPT_STRING_BASE64HEADER.0 | Crypto32::CRYPT_STRING_STRICT.0,
    );
    query_buffer(|output, len| {
        let output = output.map(|output| output.as_mut_ptr());
        unsafe { Crypto32::CryptStringToBinaryA(pem, flags, output, len, None, None) }?;
        Ok(())
    })
}

fn import_key(spki: &[u8]) -> Result<Owned<BCRYPT_KEY_HANDLE>> {
    let info = decode::<Crypto32::CERT_PUBLIC_KEY_INFO>(spki)?;
    into_owned(|handle| unsafe {
        Crypto32::CryptImportPublicKeyInfoEx2(
            Crypto32::X509_ASN_ENCODING,
            &*info,
            Crypto32::CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG,
            None,
            handle,
        )
    })
}

fn into_owned<T>(initialize: impl FnOnce(&mut T) -> windows::core::Result<()>) -> Result<Owned<T>>
where
    T: Default + Free,
{
    let mut handle = T::default();
    initialize(&mut handle)?;
    Ok(unsafe { Owned::new(handle) })
}

fn pad_component(input: &[u8], output: &mut [u8]) -> Result<()> {
    if input.is_empty() || input.len() > output.len() {
        return Err("Invalid ECDSA component length".into());
    }
    let offset = output.len() - input.len();
    output[offset..].copy_from_slice(input);
    Ok(())
}

fn name(value: &Crypto32::CRYPT_INTEGER_BLOB) -> Result<String> {
    let output = query_buffer(|output, len| {
        *len = unsafe {
            Crypto32::CertNameToStrW(
                Crypto32::X509_ASN_ENCODING,
                value,
                Crypto32::CERT_X500_NAME_STR,
                output,
            )
        };
        if *len == 0 {
            Err(windows::core::Error::from_win32().into())
        } else {
            Ok(())
        }
    })?;
    let output = output
        .strip_suffix(&[0])
        .ok_or("Certificate name is not null-terminated")?;
    Ok(String::from_utf16(output)?)
}

fn query_buffer<T: Default + Clone>(
    mut query: impl FnMut(Option<&mut [T]>, &mut u32) -> Result<()>,
) -> Result<Vec<T>> {
    let mut len = 0;
    query(None, &mut len)?;
    let mut output = vec![T::default(); len as usize];
    query(Some(&mut output), &mut len)?;
    if len as usize > output.len() {
        return Err("Windows output likely overflowed the output buffer".into());
    }
    output.truncate(len as usize);
    Ok(output)
}

fn hash_id(algorithm: DigestAlgorithm) -> PCWSTR {
    match algorithm {
        DigestAlgorithm::Sha256 => BCRYPT_SHA256_ALGORITHM,
        DigestAlgorithm::Sha384 => BCRYPT_SHA384_ALGORITHM,
        DigestAlgorithm::Sha512 => BCRYPT_SHA512_ALGORITHM,
    }
}

fn native_len(input: &[u8]) -> Result<u32> {
    input
        .len()
        .try_into()
        .map_err(|_| "Input exceeds the Windows API length limit".into())
}

unsafe fn native_slice<'a, T, O>(pointer: *const T, len: u32, _owner: &'a O) -> Result<&'a [T]> {
    if len == 0 {
        return Ok(&[]);
    }
    let pointer = NonNull::new(pointer.cast_mut()).ok_or("Null Windows pointer")?;
    if pointer.as_ptr() as usize % align_of::<T>() != 0 {
        return Err("Misaligned Windows pointer".into());
    }
    let len = len as usize;
    let _bytes = len
        .checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or("Windows slice is too large")?;
    Ok(unsafe { std::slice::from_raw_parts(pointer.as_ptr(), len) })
}
