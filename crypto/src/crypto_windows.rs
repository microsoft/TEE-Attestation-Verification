// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{c_void, CString};
use std::mem::{align_of, size_of};
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

use windows::core::{Owned, PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::{FILETIME, HLOCAL, STATUS_INVALID_SIGNATURE};
use windows::Win32::Security::Cryptography::{X509_ASN_ENCODING as X509, *};

use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, SignatureBackend, SignatureKeyAlgorithm,
};

const PEM_LABELS: [(&[u8], &[u8]); 2] = [
    (b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"),
    (
        b"-----BEGIN X509 CERTIFICATE-----",
        b"-----END X509 CERTIFICATE-----",
    ),
];

pub struct Crypto;

#[derive(Clone, Debug)]
pub struct Certificate(Arc<[u8]>);

struct NativeCertificate(NonNull<CERT_CONTEXT>);

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

fn display_name(certificate: &Certificate, subject: bool) -> String {
    certificate
        .with_context(|context| {
            let info = context.info()?;
            name(if subject { &info.Subject } else { &info.Issuer })
        })
        .unwrap_or_else(|_| "<unavailable certificate name>".into())
}

impl Certificate {
    fn from_der(der: &[u8]) -> Result<Self> {
        NativeCertificate::from_der(der)?;
        Ok(Self(Arc::from(der)))
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

    fn with_extension<T>(
        &self,
        oid: &str,
        operation: impl for<'a> FnOnce(&'a NativeCertificate, Option<&'a CERT_EXTENSION>) -> Result<T>,
    ) -> Result<T> {
        validate_oid(oid)?;
        let oid = CString::new(oid)?;
        self.with_context(|context| {
            let extensions = context.extensions()?;
            let extension = if extensions.is_empty() {
                None
            } else {
                unsafe { CertFindExtension(PCSTR(oid.as_ptr().cast()), extensions).as_ref() }
            };
            operation(context, extension)
        })
    }
}

impl NativeCertificate {
    fn from_der(der: &[u8]) -> Result<Self> {
        native_len(der)?;
        let context = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der) };
        NonNull::new(context)
            .map(Self)
            .ok_or_else(|| windows::core::Error::from_win32().into())
    }

    fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.0.as_ptr()
    }

    fn context(&self) -> &CERT_CONTEXT {
        unsafe { self.0.as_ref() }
    }

    fn info(&self) -> Result<&CERT_INFO> {
        unsafe { self.context().pCertInfo.as_ref() }.ok_or_else(|| "Null CERT_INFO".into())
    }

    fn extensions(&self) -> Result<&[CERT_EXTENSION]> {
        let info = self.info()?;
        unsafe { native_slice(info.rgExtension, info.cExtension, self) }
    }
}

impl Drop for NativeCertificate {
    fn drop(&mut self) {
        let _ = unsafe { CertFreeCertificateContext(Some(self.as_ptr())) };
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let key = import_key(spki)?;
        validate_key(&key, algorithm)?;
        Ok(Self {
            spki: spki.to_vec(),
            algorithm,
        })
    }
}

impl SignatureBackend for Signature {
    fn from_bytes(bytes: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let bytes = match algorithm {
            SignatureKeyAlgorithm::Ec(ec) => ecdsa_signature(bytes, ec)?,
            _ => bytes.to_vec(),
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
        let (record, _) = next_pem_record(pem)?.ok_or("No certificate PEM blocks found")?;
        Certificate::from_der(&decode_pem(record)?)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Certificate>> {
        let mut result = Vec::new();
        let mut rest = pem;
        while let Some((record, remaining)) = next_pem_record(rest)? {
            result.push(Certificate::from_der(&decode_pem(record)?)?);
            rest = remaining;
        }
        Ok(result)
    }

    fn from_der(der: &[u8]) -> Result<Certificate> {
        Certificate::from_der(der)
    }

    fn to_der(cert: &Certificate) -> Result<Vec<u8>> {
        Ok(cert.der().to_vec())
    }

    fn to_pem(cert: &Certificate) -> Result<String> {
        native_len(cert.der())?;
        let mut len = 0;
        let flags = CRYPT_STRING(CRYPT_STRING_BASE64HEADER.0 | CRYPT_STRING_NOCR);
        if !unsafe { CryptBinaryToStringA(cert.der(), flags, None, &mut len) }.as_bool() {
            return Err(windows::core::Error::from_win32().into());
        }
        let mut output = vec![0; len as usize];
        if !unsafe {
            CryptBinaryToStringA(cert.der(), flags, Some(PSTR(output.as_mut_ptr())), &mut len)
        }
        .as_bool()
        {
            return Err(windows::core::Error::from_win32().into());
        }
        output.truncate(len as usize);
        if output.last() == Some(&0) {
            output.pop();
        }
        Ok(String::from_utf8(output)?)
    }

    fn get_public_key(cert: &Certificate) -> Result<Vec<u8>> {
        cert.with_context(|context| {
            encode(X509_PUBLIC_KEY_INFO, &context.info()?.SubjectPublicKeyInfo)
        })
    }

    fn get_extension_value_by_oid(cert: &Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.with_extension(oid, |context, extension| {
            extension
                .map(|ext| unsafe {
                    native_slice(ext.Value.pbData, ext.Value.cbData, context).map(<[u8]>::to_vec)
                })
                .transpose()
        })
    }

    fn subject_name(cert: &Certificate) -> String {
        display_name(cert, true)
    }

    fn issuer_name(cert: &Certificate) -> String {
        display_name(cert, false)
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
        let time = filetime(unix_time)?;
        cert.with_context(|context| {
            Ok(unsafe { CertVerifyTimeValidity(Some(&time), context.info()?) } == 0)
        })
    }

    fn version(cert: &Certificate) -> Result<u8> {
        cert.with_context(|context| Ok(context.info()?.dwVersion.try_into()?))
    }

    fn basic_constraints(cert: &Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.with_extension("2.5.29.19", |context, extension| {
            let Some(ext) = extension else {
                return Ok(None);
            };
            let encoded = unsafe { native_slice(ext.Value.pbData, ext.Value.cbData, context)? };
            let decoded = decode(X509_BASIC_CONSTRAINTS2, encoded)?;
            let value = decoded_ref::<CERT_BASIC_CONSTRAINTS2_INFO>(&decoded)?;
            Ok(Some(super::BasicConstraints {
                critical: ext.fCritical.as_bool(),
                ca: value.fCA.as_bool(),
                path_len_constraint: value
                    .fPathLenConstraint
                    .as_bool()
                    .then_some(value.dwPathLenConstraint as usize),
            }))
        })
    }

    fn key_usage(cert: &Certificate) -> Result<Option<super::KeyUsage>> {
        cert.with_extension("2.5.29.15", |_, extension| {
            if extension.is_none() {
                return Ok(None);
            }
            cert.with_context(|context| {
                let mut usage = [0];
                unsafe { CertGetIntendedKeyUsage(X509_ASN_ENCODING, context.info()?, &mut usage) }?;
                Ok(Some(super::KeyUsage {
                    key_cert_sign: usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE as u8 != 0,
                }))
            })
        })
    }

    fn extension_criticality(cert: &Certificate, oid: &str) -> Result<Option<bool>> {
        cert.with_extension(oid, |_, extension| {
            Ok(extension.map(|ext| ext.fCritical.as_bool()))
        })
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
        let mut raw = BCRYPT_ALG_HANDLE::default();
        unsafe {
            BCryptOpenAlgorithmProvider(
                &mut raw,
                hash_id(algorithm),
                PCWSTR::null(),
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
            )
        }
        .ok()?;
        let provider = unsafe { Owned::new(raw) };
        let mut raw_hash = BCRYPT_HASH_HANDLE::default();
        unsafe { BCryptCreateHash(*provider, &mut raw_hash, None, None, 0) }.ok()?;
        let hash = unsafe { Owned::new(raw_hash) };
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
        if signature.bytes.len() != key_u32_property(&handle, BCRYPT_SIGNATURE_LENGTH)? as usize {
            return Err("signature verification failed".into());
        }
        let digest = Self::digest(signature.algorithm.digest(), input)?;
        let hash = hash_id(signature.algorithm.digest());
        let status = match signature.algorithm {
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
        if status == STATUS_INVALID_SIGNATURE {
            Err("signature verification failed".into())
        } else {
            status.ok().map_err(Into::into)
        }
    }

    fn verify_chain(
        trusted: &Certificate,
        untrusted: &[&Certificate],
        leaf: &Certificate,
        unix_time: Option<Duration>,
    ) -> Result<()> {
        let roots = CertStore::new()?;
        roots.add(trusted)?;
        let intermediates = CertStore::new()?;
        for cert in untrusted {
            intermediates.add(cert)?;
        }
        let mut config = CERT_CHAIN_ENGINE_CONFIG {
            cbSize: size_of::<CERT_CHAIN_ENGINE_CONFIG>() as u32,
            hExclusiveRoot: roots.0,
            hExclusiveTrustedPeople: roots.0,
            dwExclusiveFlags: CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG,
            ..Default::default()
        };
        let mut raw_engine = HCERTCHAINENGINE::default();
        unsafe { CertCreateCertificateChainEngine(&mut config, &mut raw_engine) }?;
        let engine = unsafe { Owned::new(raw_engine) };
        let parameters = CERT_CHAIN_PARA {
            cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
            ..Default::default()
        };
        let leaf_context = NativeCertificate::from_der(leaf.der())?;
        let time = unix_time.map(filetime).transpose()?;
        let mut raw_chain = std::ptr::null_mut();
        unsafe {
            CertGetCertificateChain(
                Some(*engine),
                leaf_context.as_ptr(),
                time.as_ref().map(|value| value as *const FILETIME),
                Some(intermediates.0),
                &parameters,
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
                    | CERT_CHAIN_DISABLE_AIA
                    | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
                    | CERT_CHAIN_ENABLE_PEER_TRUST,
                None,
                &mut raw_chain,
            )
        }?;
        let chain = ChainContext::new(raw_chain)?;
        let context = chain.as_ref();
        if context.cChain != 1 {
            return Err(format!(
                "Expected one simple certificate chain, found {}",
                context.cChain
            )
            .into());
        }
        let simple_chains = unsafe { native_slice(context.rgpChain, context.cChain, &chain)? };
        let simple = unsafe { simple_chains[0].as_ref() }.ok_or("Null simple certificate chain")?;
        if !simple.pTrustListInfo.is_null() {
            return Err("CTL-connected certificate chains are not supported".into());
        }
        if simple.cElement == 0 {
            return Err("Certificate chain contains no elements".into());
        }
        let elements = unsafe { native_slice(simple.rgpElement, simple.cElement, &chain)? };
        let contexts = elements
            .iter()
            .map(|element| -> Result<&CERT_CONTEXT> {
                let Some(element) = (unsafe { element.as_ref() }) else {
                    return Err("Null certificate chain element".into());
                };
                let Some(context) = (unsafe { element.pCertContext.as_ref() }) else {
                    return Err("Null chain certificate context".into());
                };
                Ok(context)
            })
            .collect::<Result<Vec<_>>>()?;
        let ders = contexts
            .iter()
            .map(|context| unsafe {
                native_slice(context.pbCertEncoded, context.cbCertEncoded, &chain)
            })
            .collect::<Result<Vec<_>>>()?;
        let anchored = ders.last().is_some_and(|der| *der == trusted.der());
        let supplied = ders
            .iter()
            .skip(1)
            .take(ders.len().saturating_sub(2))
            .all(|der| untrusted.iter().any(|cert| *der == cert.der()));
        let status = context.TrustStatus.dwErrorStatus;
        if status == 0 && anchored && supplied {
            Ok(())
        } else {
            Err(format!("Certificate chain trust error 0x{status:08X}").into())
        }
    }
}

fn decode(kind: PCSTR, input: &[u8]) -> Result<Owned<HLOCAL>> {
    native_len(input)?;
    let mut pointer = std::ptr::null_mut::<c_void>();
    let mut len = 0;
    unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            kind,
            input,
            CRYPT_DECODE_ALLOC_FLAG,
            None,
            Some((&mut pointer as *mut *mut c_void).cast()),
            &mut len,
        )
    }?;
    NonNull::<c_void>::new(pointer).ok_or("CryptDecodeObjectEx returned null")?;
    Ok(unsafe { Owned::new(HLOCAL(pointer)) })
}

fn encode<T>(kind: PCSTR, value: &T) -> Result<Vec<u8>> {
    let mut pointer = std::ptr::null_mut::<c_void>();
    let mut len = 0;
    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            kind,
            (value as *const T).cast(),
            CRYPT_ENCODE_ALLOC_FLAG,
            None,
            Some((&mut pointer as *mut *mut c_void).cast()),
            &mut len,
        )
    }?;
    NonNull::new(pointer).ok_or("CryptEncodeObjectEx returned null")?;
    let allocation = unsafe { Owned::new(HLOCAL(pointer)) };
    Ok(unsafe { native_slice(pointer.cast(), len, &allocation)?.to_vec() })
}

fn next_pem_record(input: &[u8]) -> Result<Option<(&[u8], &[u8])>> {
    let find = |marker: &[u8]| input.windows(marker.len()).position(|part| part == marker);
    let Some((begin, (_, end_marker))) = PEM_LABELS
        .iter()
        .filter_map(|label| find(label.0).map(|position| (position, label)))
        .min_by_key(|(position, _)| *position)
    else {
        return Ok(None);
    };
    let record = &input[begin..];
    let end = record
        .windows(end_marker.len())
        .position(|part| part == *end_marker)
        .ok_or("Unterminated certificate PEM")?
        + end_marker.len();
    Ok(Some((&record[..end], &record[end..])))
}

fn decode_pem(pem: &[u8]) -> Result<Vec<u8>> {
    native_len(pem)?;
    let flags = CRYPT_STRING(CRYPT_STRING_BASE64HEADER.0 | CRYPT_STRING_STRICT.0);
    let mut len = 0;
    unsafe { CryptStringToBinaryA(pem, flags, None, &mut len, None, None) }?;
    let mut output = vec![0; len as usize];
    unsafe { CryptStringToBinaryA(pem, flags, Some(output.as_mut_ptr()), &mut len, None, None) }?;
    output.truncate(len as usize);
    Ok(output)
}

fn import_key(spki: &[u8]) -> Result<Owned<BCRYPT_KEY_HANDLE>> {
    let info = decode(X509_PUBLIC_KEY_INFO, spki)?;
    let info = decoded_ref::<CERT_PUBLIC_KEY_INFO>(&info)?;
    let mut raw = BCRYPT_KEY_HANDLE::default();
    unsafe {
        CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            info,
            CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG,
            None,
            &mut raw,
        )
    }?;
    Ok(unsafe { Owned::new(raw) })
}

fn validate_key(key: &Owned<BCRYPT_KEY_HANDLE>, expected: SignatureKeyAlgorithm) -> Result<()> {
    let actual = key_property((**key).into(), BCRYPT_ALGORITHM_NAME)?;
    let valid = match expected {
        SignatureKeyAlgorithm::Ec(algorithm) => {
            actual
                == match algorithm {
                    EcSignatureKeyAlgorithm::P256 => "ECDSA_P256",
                    EcSignatureKeyAlgorithm::P384 => "ECDSA_P384",
                    EcSignatureKeyAlgorithm::P521 => "ECDSA_P521",
                }
        }
        _ => actual == "RSA" || actual == "RSA_SIGN",
    };
    if valid {
        Ok(())
    } else {
        Err(format!("Public key algorithm {actual} does not match {expected:?}").into())
    }
}

fn key_property(key: BCRYPT_HANDLE, property: PCWSTR) -> Result<String> {
    let mut len = 0;
    unsafe { BCryptGetProperty(key, property, None, &mut len, 0) }.ok()?;
    let mut output = vec![0; len as usize];
    unsafe { BCryptGetProperty(key, property, Some(&mut output), &mut len, 0) }.ok()?;
    if len as usize > output.len() {
        return Err("CNG property length changed between calls".into());
    }
    let units = output[..len as usize]
        .chunks_exact(2)
        .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    Ok(String::from_utf16(&units)?)
}

fn key_u32_property(key: &Owned<BCRYPT_KEY_HANDLE>, property: PCWSTR) -> Result<u32> {
    let mut value = [0; size_of::<u32>()];
    let mut len = 0;
    unsafe { BCryptGetProperty((**key).into(), property, Some(&mut value), &mut len, 0) }.ok()?;
    if len as usize != value.len() {
        return Err("CNG returned an invalid u32 property length".into());
    }
    Ok(u32::from_ne_bytes(value))
}

fn ecdsa_signature(der: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Vec<u8>> {
    let decoded = decode(X509_ECC_SIGNATURE, der)?;
    let signature = decoded_ref::<CERT_ECC_SIGNATURE>(&decoded)?;
    let width = algorithm.scalar_byte_len();
    let mut output = vec![0; width * 2];
    let mut r = unsafe { native_slice(signature.r.pbData, signature.r.cbData, &decoded)?.to_vec() };
    let mut s = unsafe { native_slice(signature.s.pbData, signature.s.cbData, &decoded)?.to_vec() };
    r.reverse();
    s.reverse();
    pad_component(&r, &mut output[..width])?;
    pad_component(&s, &mut output[width..])?;
    Ok(output)
}

fn pad_component(input: &[u8], output: &mut [u8]) -> Result<()> {
    if input.is_empty() || input.len() > output.len() {
        return Err("Invalid ECDSA component length".into());
    }
    let offset = output.len() - input.len();
    output[offset..].copy_from_slice(input);
    Ok(())
}

fn name(value: &CRYPT_INTEGER_BLOB) -> Result<String> {
    let len = unsafe { CertNameToStrW(X509_ASN_ENCODING, value, CERT_X500_NAME_STR, None) };
    if len == 0 {
        return Err(windows::core::Error::from_win32().into());
    }
    let mut output = vec![0; len as usize];
    let len = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING,
            value,
            CERT_X500_NAME_STR,
            Some(&mut output),
        )
    } as usize;
    if len == 0 || len > output.len() {
        return Err(windows::core::Error::from_win32().into());
    }
    Ok(String::from_utf16(&output[..len - 1])?)
}

fn filetime(time: Duration) -> Result<FILETIME> {
    let ticks = time
        .as_secs()
        .checked_mul(10_000_000)
        .and_then(|ticks| ticks.checked_add(116_444_736_000_000_000))
        .ok_or("Unix time does not fit FILETIME")?;
    Ok(FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    })
}

fn hash_id(algorithm: DigestAlgorithm) -> PCWSTR {
    match algorithm {
        DigestAlgorithm::Sha256 => BCRYPT_SHA256_ALGORITHM,
        DigestAlgorithm::Sha384 => BCRYPT_SHA384_ALGORITHM,
        DigestAlgorithm::Sha512 => BCRYPT_SHA512_ALGORITHM,
    }
}

fn validate_oid(oid: &str) -> Result<()> {
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
    if first > 2 || (first < 2 && second > 39) {
        return Err("Invalid dotted-decimal OID".into());
    }
    Ok(())
}

fn native_len(input: &[u8]) -> Result<u32> {
    input
        .len()
        .try_into()
        .map_err(|_| "Input exceeds the Windows API length limit".into())
}

fn decoded_ref<T>(allocation: &Owned<HLOCAL>) -> Result<&T> {
    let pointer = allocation.0.cast::<T>();
    let pointer = NonNull::new(pointer).ok_or("Null decoded Windows pointer")?;
    if pointer.as_ptr() as usize % align_of::<T>() != 0 {
        return Err("Misaligned decoded Windows pointer".into());
    }
    Ok(unsafe { pointer.as_ref() })
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

struct ChainContext(NonNull<CERT_CHAIN_CONTEXT>);

impl ChainContext {
    fn new(context: *mut CERT_CHAIN_CONTEXT) -> Result<Self> {
        NonNull::new(context)
            .map(Self)
            .ok_or_else(|| "Null certificate chain".into())
    }

    fn as_ref(&self) -> &CERT_CHAIN_CONTEXT {
        unsafe { self.0.as_ref() }
    }
}

impl Drop for ChainContext {
    fn drop(&mut self) {
        unsafe { CertFreeCertificateChain(self.0.as_ptr()) };
    }
}

struct CertStore(HCERTSTORE);

impl CertStore {
    fn new() -> Result<Self> {
        Ok(Self(unsafe {
            CertOpenStore(CERT_STORE_PROV_MEMORY, X509, None, Default::default(), None)
        }?))
    }

    fn add(&self, certificate: &Certificate) -> Result<()> {
        unsafe {
            CertAddEncodedCertificateToStore(
                Some(self.0),
                X509_ASN_ENCODING,
                certificate.der(),
                CERT_STORE_ADD_ALWAYS,
                None,
            )
        }?;
        Ok(())
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
}
