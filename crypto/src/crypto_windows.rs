// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{c_void, CString};
use std::mem::{align_of, size_of};
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

use windows::core::{Free, Owned, PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::{
    FILETIME, HLOCAL, STATUS_INVALID_PARAMETER, STATUS_INVALID_SIGNATURE,
};
use windows::Win32::Security::Cryptography::{
    self as Crypto32, BCryptCreateHash, BCryptFinishHash, BCryptGetProperty, BCryptHashData,
    BCryptOpenAlgorithmProvider, BCryptVerifySignature, BCRYPT_ALGORITHM_NAME, BCRYPT_HANDLE,
    BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS,
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
        validate_oid(oid)?;
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
        let _ = unsafe { Crypto32::CertFreeCertificateContext(Some(self.as_ptr())) };
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let key = import_key(spki)?;
        let actual = key_property((*key).into(), BCRYPT_ALGORITHM_NAME)?;
        let valid = match algorithm {
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
        if !valid {
            return Err(
                format!("Public key algorithm {actual} does not match {algorithm:?}").into(),
            );
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
        let pem = std::str::from_utf8(pem)?
            .replace(X509_PEM_BEGIN, PEM_BEGIN)
            .replace(X509_PEM_END, PEM_END);
        pem.split_inclusive(PEM_END)
            .filter(|record| record.contains(PEM_BEGIN))
            .map(|record| {
                if !record.ends_with(PEM_END) {
                    return Err("Unterminated certificate PEM".into());
                }
                Certificate::from_der(&decode_pem(record.as_bytes())?)
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
        let mut len = 0;
        let flags = Crypto32::CRYPT_STRING(
            Crypto32::CRYPT_STRING_BASE64HEADER.0 | Crypto32::CRYPT_STRING_NOCR,
        );
        // discovers length to allocate the buffer
        if !unsafe { Crypto32::CryptBinaryToStringA(cert.der(), flags, None, &mut len) }.as_bool() {
            return Err(windows::core::Error::from_win32().into());
        }
        let mut output = vec![0; len as usize];
        if !unsafe {
            Crypto32::CryptBinaryToStringA(
                cert.der(),
                flags,
                Some(PSTR(output.as_mut_ptr())),
                &mut len,
            )
        }
        .as_bool()
        {
            return Err(windows::core::Error::from_win32().into());
        }
        if len as usize > output.len() {
            return Err("CryptBinaryToStringA output length increased between calls".into());
        }
        // The second call reports the written length.
        output.truncate(len as usize);
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
        let time = filetime(unix_time)?;
        cert.with_context(|context| {
            Ok(unsafe { Crypto32::CertVerifyTimeValidity(Some(&time), context.info()?) } == 0)
        })
    }

    fn version(cert: &Certificate) -> Result<u8> {
        cert.with_context(|context| Ok(context.info()?.dwVersion.try_into()?))
    }

    fn basic_constraints(cert: &Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.with_context(|context| {
            // Basic Constraints, RFC 5280 §4.2.1.9.
            let Some(ext) = context.extension("2.5.29.19")? else {
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
            if context.extension("2.5.29.15")?.is_none() {
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
        if signature.bytes.len() != key_u32_property(&handle, BCRYPT_SIGNATURE_LENGTH)? as usize {
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
        let mut config = Crypto32::CERT_CHAIN_ENGINE_CONFIG {
            cbSize: size_of::<Crypto32::CERT_CHAIN_ENGINE_CONFIG>() as u32,
            hRestrictedRoot: roots.0,
            hRestrictedOther: intermediates.0,
            ..Default::default()
        };
        let engine = into_owned(|handle| unsafe {
            Crypto32::CertCreateCertificateChainEngine(&mut config, handle)
        })?;
        let parameters = Crypto32::CERT_CHAIN_PARA {
            cbSize: size_of::<Crypto32::CERT_CHAIN_PARA>() as u32,
            ..Default::default()
        };
        let leaf_context = NativeCertificate::from_der(leaf.der())?;
        let time = unix_time.map(filetime).transpose()?;
        let mut raw_chain = std::ptr::null_mut();
        unsafe {
            Crypto32::CertGetCertificateChain(
                Some(*engine),
                leaf_context.as_ptr(),
                time.as_ref().map(|value| value as *const FILETIME),
                Some(intermediates.0),
                &parameters,
                Crypto32::CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
                    | Crypto32::CERT_CHAIN_DISABLE_AIA
                    | Crypto32::CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
                    | Crypto32::CERT_CHAIN_DISABLE_PASS1_QUALITY_FILTERING
                    | Crypto32::CERT_CHAIN_ENABLE_PEER_TRUST
                    | Crypto32::CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS,
                None,
                &mut raw_chain,
            )
        }?;
        let chain = ChainContext::new(raw_chain)?;
        let primary_status = chain.as_ref().TrustStatus.dwErrorStatus;
        for context in chain.contexts()? {
            if chain.is_supplied_path(context, trusted, untrusted)? {
                return Ok(());
            }
        }
        Err(format!(
            "No acceptable caller-supplied certificate chain (primary trust error 0x{primary_status:08X})"
        )
        .into())
    }
}

impl ChainContext {
    fn contexts(&self) -> Result<Vec<&Crypto32::CERT_CHAIN_CONTEXT>> {
        let primary = self.as_ref();
        let lower = unsafe {
            native_slice(
                primary.rgpLowerQualityChainContext,
                primary.cLowerQualityChainContext,
                self,
            )?
        };
        let mut contexts = Vec::with_capacity(lower.len() + 1);
        contexts.push(primary);
        for (index, context) in lower.iter().enumerate() {
            let Some(context) = (unsafe { context.as_ref() }) else {
                return Err(format!("Null lower-quality certificate chain {index}").into());
            };
            contexts.push(context);
        }
        Ok(contexts)
    }

    fn is_supplied_path(
        &self,
        context: &Crypto32::CERT_CHAIN_CONTEXT,
        trusted: &Certificate,
        untrusted: &[&Certificate],
    ) -> Result<bool> {
        if context.TrustStatus.dwErrorStatus != 0 {
            return Ok(false);
        }
        if context.cChain != 1 {
            return Ok(false);
        }
        let simple_chains = unsafe { native_slice(context.rgpChain, context.cChain, self)? };
        let simple = unsafe { simple_chains[0].as_ref() }.ok_or("Null simple certificate chain")?;
        if !simple.pTrustListInfo.is_null() {
            return Ok(false);
        }
        if simple.cElement == 0 {
            return Err("Certificate chain contains no elements".into());
        }
        let elements = unsafe { native_slice(simple.rgpElement, simple.cElement, self)? };
        let contexts = elements
            .iter()
            .map(|element| -> Result<&Crypto32::CERT_CONTEXT> {
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
                native_slice(context.pbCertEncoded, context.cbCertEncoded, self)
            })
            .collect::<Result<Vec<_>>>()?;
        let anchored = ders.last().is_some_and(|der| *der == trusted.der());
        let supplied = ders
            .iter()
            .skip(1)
            .take(ders.len().saturating_sub(2))
            .all(|der| untrusted.iter().any(|cert| *der == cert.der()));
        Ok(anchored && supplied)
    }
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

#[cfg(test)]
mod pem_chain_tests {
    use super::*;

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");

    fn with_x509_label(pem: &[u8]) -> Vec<u8> {
        std::str::from_utf8(pem)
            .expect("certificate PEM should be UTF-8")
            .replace(
                "-----BEGIN CERTIFICATE-----",
                "-----BEGIN X509 CERTIFICATE-----",
            )
            .replace(
                "-----END CERTIFICATE-----",
                "-----END X509 CERTIFICATE-----",
            )
            .into_bytes()
    }

    #[test]
    fn supported_pem_labels_preserve_chain_order() {
        let ask = with_x509_label(MILAN_ASK);
        let pem = [ask.as_slice(), b"\n", MILAN_ARK].concat();

        let chain = Crypto::from_pem_chain(&pem).expect("PEM chain should parse");
        let expected = [MILAN_ASK, MILAN_ARK];

        assert_eq!(chain.len(), expected.len());
        for (certificate, expected_pem) in chain.iter().zip(expected) {
            let expected =
                Crypto::from_pem(expected_pem).expect("expected certificate should parse");
            assert_eq!(
                Crypto::to_der(certificate).expect("certificate should encode"),
                Crypto::to_der(&expected).expect("expected certificate should encode")
            );
        }
    }

    #[test]
    fn unterminated_pem_record_is_rejected() {
        let pem = b"-----BEGIN CERTIFICATE-----\n";

        let error = Crypto::from_pem_chain(pem).expect_err("unterminated PEM should fail");

        assert_eq!(error.to_string(), "Unterminated certificate PEM");
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn output_types_select_matching_decode_kinds() {
        let signature = decode::<Crypto32::CERT_ECC_SIGNATURE>(&[
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
        ])
        .expect("ECDSA signature should decode");
        assert_eq!(signature.r.cbData, 1);
        assert_eq!(signature.s.cbData, 1);

        let constraints =
            decode::<Crypto32::CERT_BASIC_CONSTRAINTS2_INFO>(&[0x30, 0x03, 0x01, 0x01, 0xff])
                .expect("Basic Constraints should decode");
        assert!(constraints.fCA.as_bool());

        let public_key = decode::<Crypto32::CERT_PUBLIC_KEY_INFO>(&[
            0x30, 0x1c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, 0x05, 0x00, 0x03, 0x0b, 0x00, 0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x01,
            0x00, 0x01,
        ])
        .expect("SubjectPublicKeyInfo should decode");
        assert_eq!(public_key.PublicKey.cbData, 10);
    }
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
    let mut len = 0;
    unsafe { Crypto32::CryptStringToBinaryA(pem, flags, None, &mut len, None, None) }?;
    let mut output = vec![0; len as usize];
    unsafe {
        Crypto32::CryptStringToBinaryA(pem, flags, Some(output.as_mut_ptr()), &mut len, None, None)
    }?;
    output.truncate(len as usize);
    Ok(output)
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

fn pad_component(input: &[u8], output: &mut [u8]) -> Result<()> {
    if input.is_empty() || input.len() > output.len() {
        return Err("Invalid ECDSA component length".into());
    }
    let offset = output.len() - input.len();
    output[offset..].copy_from_slice(input);
    Ok(())
}

fn name(value: &Crypto32::CRYPT_INTEGER_BLOB) -> Result<String> {
    let len = unsafe {
        Crypto32::CertNameToStrW(
            Crypto32::X509_ASN_ENCODING,
            value,
            Crypto32::CERT_X500_NAME_STR,
            None,
        )
    };
    if len == 0 {
        return Err(windows::core::Error::from_win32().into());
    }
    let mut output = vec![0; len as usize];
    let len = unsafe {
        Crypto32::CertNameToStrW(
            Crypto32::X509_ASN_ENCODING,
            value,
            Crypto32::CERT_X500_NAME_STR,
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

struct ChainContext(NonNull<Crypto32::CERT_CHAIN_CONTEXT>);

impl ChainContext {
    fn new(context: *mut Crypto32::CERT_CHAIN_CONTEXT) -> Result<Self> {
        NonNull::new(context)
            .map(Self)
            .ok_or_else(|| "Null certificate chain".into())
    }

    fn as_ref(&self) -> &Crypto32::CERT_CHAIN_CONTEXT {
        unsafe { self.0.as_ref() }
    }
}

impl Drop for ChainContext {
    fn drop(&mut self) {
        unsafe { Crypto32::CertFreeCertificateChain(self.0.as_ptr()) };
    }
}

struct CertStore(Crypto32::HCERTSTORE);

impl CertStore {
    fn new() -> Result<Self> {
        Ok(Self(unsafe {
            Crypto32::CertOpenStore(
                Crypto32::CERT_STORE_PROV_MEMORY,
                Crypto32::X509_ASN_ENCODING,
                None,
                Default::default(),
                None,
            )
        }?))
    }

    fn add(&self, certificate: &Certificate) -> Result<()> {
        unsafe {
            Crypto32::CertAddEncodedCertificateToStore(
                Some(self.0),
                Crypto32::X509_ASN_ENCODING,
                certificate.der(),
                Crypto32::CERT_STORE_ADD_ALWAYS,
                None,
            )
        }?;
        Ok(())
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        let _ = unsafe { Crypto32::CertCloseStore(Some(self.0), 0) };
    }
}
