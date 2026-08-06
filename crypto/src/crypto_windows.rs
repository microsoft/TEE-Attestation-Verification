// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{c_void, CString};
use std::mem::size_of;
use std::ptr::NonNull;
use std::time::Duration;

use windows::core::{Owned, PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::{FILETIME, HLOCAL};
use windows::Win32::Security::Cryptography::{X509_ASN_ENCODING as X509, *};

use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, SignatureBackend, SignatureKeyAlgorithm,
};

const PEM: (&[u8], &[u8]) = (b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----");

pub struct Crypto;

#[derive(Debug)]
pub struct Certificate(NonNull<CERT_CONTEXT>);

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
        .info()
        .and_then(|info| name(if subject { &info.Subject } else { &info.Issuer }))
        .unwrap_or_else(|_| "<unavailable certificate name>".into())
}

impl Clone for Certificate {
    fn clone(&self) -> Self {
        let context = unsafe { CertDuplicateCertificateContext(Some(self.as_ptr())) };
        Self(NonNull::new(context).expect("CertDuplicateCertificateContext returned null"))
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        let _ = unsafe { CertFreeCertificateContext(Some(self.as_ptr())) };
    }
}

impl Certificate {
    fn from_der(der: &[u8]) -> Result<Self> {
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

    fn der(&self) -> Result<&[u8]> {
        slice(self.context().pbCertEncoded, self.context().cbCertEncoded)
    }

    fn extensions(&self) -> Result<&[CERT_EXTENSION]> {
        let info = self.info()?;
        slice(info.rgExtension, info.cExtension)
    }

    fn extension(&self, oid: &str) -> Result<Option<&CERT_EXTENSION>> {
        validate_oid(oid)?;
        let oid = CString::new(oid)?;
        let extensions = self.extensions()?;
        if extensions.is_empty() {
            return Ok(None);
        }
        Ok(unsafe { CertFindExtension(PCSTR(oid.as_ptr().cast()), extensions).as_ref() })
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
        let mut chain = Self::from_pem_chain(pem)?;
        if chain.len() != 1 {
            return Err(format!("Expected one certificate, found {}", chain.len()).into());
        }
        Ok(chain.remove(0))
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Certificate>> {
        let find = |input: &[u8], marker: &[u8]| {
            input.windows(marker.len()).position(|part| part == marker)
        };
        let mut result = Vec::new();
        let mut rest = pem;
        while let Some(begin) = find(rest, PEM.0) {
            rest = &rest[begin..];
            let end = find(rest, PEM.1).ok_or("Unterminated certificate PEM")? + PEM.1.len();
            result.push(Certificate::from_der(&decode_pem(&rest[..end])?)?);
            rest = &rest[end..];
        }
        if result.is_empty() {
            return Err("No certificate PEM blocks found".into());
        }
        Ok(result)
    }

    fn from_der(der: &[u8]) -> Result<Certificate> {
        Certificate::from_der(der)
    }

    fn to_der(cert: &Certificate) -> Result<Vec<u8>> {
        Ok(cert.der()?.to_vec())
    }

    fn to_pem(cert: &Certificate) -> Result<String> {
        let mut len = 0;
        let flags = CRYPT_STRING(CRYPT_STRING_BASE64HEADER.0 | CRYPT_STRING_NOCR);
        if !unsafe { CryptBinaryToStringA(cert.der()?, flags, None, &mut len) }.as_bool() {
            return Err(windows::core::Error::from_win32().into());
        }
        let mut output = vec![0; len as usize];
        if !unsafe {
            CryptBinaryToStringA(
                cert.der()?,
                flags,
                Some(PSTR(output.as_mut_ptr())),
                &mut len,
            )
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
        encode(X509_PUBLIC_KEY_INFO, &cert.info()?.SubjectPublicKeyInfo)
    }

    fn get_extension_value_by_oid(cert: &Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.extension(oid)?
            .map(|ext| Ok(blob(&ext.Value)?.to_vec()))
            .transpose()
    }

    fn subject_name(cert: &Certificate) -> String {
        display_name(cert, true)
    }

    fn issuer_name(cert: &Certificate) -> String {
        display_name(cert, false)
    }

    fn subject_name_der(cert: &Certificate) -> Result<Vec<u8>> {
        Ok(blob(&cert.info()?.Subject)?.to_vec())
    }

    fn issuer_name_der(cert: &Certificate) -> Result<Vec<u8>> {
        Ok(blob(&cert.info()?.Issuer)?.to_vec())
    }

    fn is_valid_at(cert: &Certificate, unix_time: Duration) -> Result<bool> {
        let time = filetime(unix_time)?;
        Ok(unsafe { CertVerifyTimeValidity(Some(&time), cert.info()?) } == 0)
    }

    fn version(cert: &Certificate) -> Result<u8> {
        Ok(cert.info()?.dwVersion.try_into()?)
    }

    fn basic_constraints(cert: &Certificate) -> Result<Option<super::BasicConstraints>> {
        let Some(ext) = cert.extension("2.5.29.19")? else {
            return Ok(None);
        };
        let decoded = decode(X509_BASIC_CONSTRAINTS2, blob(&ext.Value)?)?;
        let value = unsafe { &*decoded.0.cast::<CERT_BASIC_CONSTRAINTS2_INFO>() };
        Ok(Some(super::BasicConstraints {
            critical: ext.fCritical.as_bool(),
            ca: value.fCA.as_bool(),
            path_len_constraint: value
                .fPathLenConstraint
                .as_bool()
                .then_some(value.dwPathLenConstraint as usize),
        }))
    }

    fn key_usage(cert: &Certificate) -> Result<Option<super::KeyUsage>> {
        if cert.extension("2.5.29.15")?.is_none() {
            return Ok(None);
        }
        let mut usage = [0];
        unsafe { CertGetIntendedKeyUsage(X509_ASN_ENCODING, cert.info()?, &mut usage) }?;
        Ok(Some(super::KeyUsage {
            key_cert_sign: usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE as u8 != 0,
        }))
    }

    fn extension_criticality(cert: &Certificate, oid: &str) -> Result<Option<bool>> {
        Ok(cert.extension(oid)?.map(|ext| ext.fCritical.as_bool()))
    }

    fn critical_extension_oids(cert: &Certificate) -> Vec<String> {
        cert.extensions()
            .into_iter()
            .flatten()
            .filter(|ext| ext.fCritical.as_bool())
            .filter_map(|ext| unsafe { ext.pszObjId.to_string().ok() })
            .collect()
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
        let mut output = vec![0; algorithm.byte_len()];
        unsafe { BCryptHash(*provider, None, input, &mut output) }.ok()?;
        Ok(output)
    }

    fn verify_signature(key: &Key, signature: &Signature, input: &[u8]) -> Result<()> {
        if !compatible_key_and_signature(key.algorithm, signature.algorithm) {
            return Err("Signature algorithm does not match key algorithm".into());
        }
        let handle = import_key(&key.spki)?;
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
        status.ok().map_err(|_| "signature verification failed")?;
        Ok(())
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
        let time = unix_time.map(filetime).transpose()?;
        let mut raw_chain = std::ptr::null_mut();
        unsafe {
            CertGetCertificateChain(
                Some(*engine),
                leaf.as_ptr(),
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
        let chain = NonNull::new(raw_chain).ok_or("Null certificate chain")?;
        let status = unsafe { chain.as_ref().TrustStatus.dwErrorStatus };
        unsafe { CertFreeCertificateChain(chain.as_ptr()) };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("Certificate chain trust error 0x{status:08X}").into())
        }
    }
}

fn decode(kind: PCSTR, input: &[u8]) -> Result<Owned<HLOCAL>> {
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
    let _allocation = unsafe { Owned::new(HLOCAL(pointer)) };
    Ok(slice(pointer.cast(), len)?.to_vec())
}

fn decode_pem(pem: &[u8]) -> Result<Vec<u8>> {
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
    let info = unsafe { &*info.0.cast::<CERT_PUBLIC_KEY_INFO>() };
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
    if raw.is_invalid() {
        return Err("CryptImportPublicKeyInfoEx2 returned null".into());
    }
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
    let units = output[..len as usize]
        .chunks_exact(2)
        .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    Ok(String::from_utf16(&units)?)
}

fn ecdsa_signature(der: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Vec<u8>> {
    let signature = decode(X509_ECC_SIGNATURE, der)?;
    let signature = unsafe { &*signature.0.cast::<CERT_ECC_SIGNATURE>() };
    let width = algorithm.scalar_byte_len();
    let mut output = vec![0; width * 2];
    let mut r = blob(&signature.r)?.to_vec();
    let mut s = blob(&signature.s)?.to_vec();
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
    Ok(String::from_utf16(&output[..len.saturating_sub(1)])?)
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

fn slice<'a, T>(pointer: *const T, len: u32) -> Result<&'a [T]> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() || len as usize > isize::MAX as usize / size_of::<T>() {
        return Err("Invalid Windows pointer or length".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(pointer, len as usize) })
}

fn blob(value: &CRYPT_INTEGER_BLOB) -> Result<&[u8]> {
    slice(value.pbData, value.cbData)
}

fn validate_oid(oid: &str) -> Result<()> {
    let valid_arc = |arc: &str| !arc.is_empty() && arc.bytes().all(|b| b.is_ascii_digit());
    if oid.split('.').count() >= 2 && oid.split('.').all(valid_arc) {
        Ok(())
    } else {
        Err("Invalid dotted-decimal OID".into())
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
                certificate.der()?,
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
