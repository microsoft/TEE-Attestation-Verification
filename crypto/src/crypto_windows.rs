// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG and Crypt32 cryptographic backend.

use std::ffi::{c_void, CString};
use std::marker::PhantomData;
use std::mem::{align_of, size_of};
use std::ptr::NonNull;
use std::time::Duration;

use windows::core::{Error as WindowsError, PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Security::Cryptography::*;

use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, RsaPkcs1v15SignatureKeyAlgorithm,
    RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

const PEM_BEGIN_CERTIFICATE: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END_CERTIFICATE: &[u8] = b"-----END CERTIFICATE-----";
const UNAVAILABLE_CERTIFICATE_NAME: &str = "<unavailable certificate name>";

pub struct Crypto;

#[derive(Debug)]
pub struct Certificate {
    context: NonNull<CERT_CONTEXT>,
}

pub struct Key {
    spki_der: Vec<u8>,
    algorithm: SignatureKeyAlgorithm,
}

pub struct Signature {
    bytes: Vec<u8>,
    algorithm: SignatureKeyAlgorithm,
}

impl Clone for Certificate {
    fn clone(&self) -> Self {
        let context =
            unsafe { CertDuplicateCertificateContext(Some(self.context.as_ptr().cast_const())) };
        Self {
            context: NonNull::new(context)
                .expect("CertDuplicateCertificateContext returned a null context"),
        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        let _ = unsafe { CertFreeCertificateContext(Some(self.context.as_ptr().cast_const())) };
    }
}

impl Certificate {
    fn from_pem(pem: &[u8]) -> Result<Self> {
        let mut certificates = parse_pem_certificates(pem)?;
        if certificates.len() != 1 {
            return Err(format!(
                "Expected exactly one CERTIFICATE PEM block, found {}",
                certificates.len()
            )
            .into());
        }
        Self::from_der(&certificates.remove(0))
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self>> {
        parse_pem_certificates(pem)?
            .into_iter()
            .map(|der| Self::from_der(&der))
            .collect()
    }

    fn from_der(der: &[u8]) -> Result<Self> {
        require_nonempty_u32_input("certificate DER", der)?;

        let signed =
            decode_object::<CERT_SIGNED_CONTENT_INFO>(X509_CERT, der, "X.509 certificate")?;
        validate_signed_content(signed.get())?;
        require_canonical_encoding(X509_CERT, signed.get(), der, "X.509 certificate")?;
        let to_be_signed = copy_blob(
            &signed.get().ToBeSigned,
            "certificate to-be-signed bytes",
            true,
        )?;

        let context = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der) };
        let certificate = Self {
            context: NonNull::new(context).ok_or_else(|| {
                operation_error("CertCreateCertificateContext", WindowsError::from_win32())
            })?,
        };

        if !certificate
            .context()
            .dwCertEncodingType
            .contains(X509_ASN_ENCODING)
        {
            return Err("Certificate context does not use X.509 ASN.1 encoding".into());
        }
        if certificate.encoded_bytes()? != der {
            return Err("CertCreateCertificateContext changed the encoded certificate".into());
        }

        let cert_info = certificate.cert_info()?;
        validate_cert_info(cert_info)?;
        let encoded_tbs = encode_object(
            X509_CERT_TO_BE_SIGNED,
            cert_info,
            "certificate to-be-signed",
        )?;
        if encoded_tbs != to_be_signed {
            return Err(
                "Certificate context to-be-signed bytes differ from the signed content".into(),
            );
        }

        Ok(certificate)
    }

    fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.encoded_bytes()?.to_vec())
    }

    fn to_pem(&self) -> Result<String> {
        let flags = CRYPT_STRING(CRYPT_STRING_BASE64HEADER.0 | CRYPT_STRING_NOCR);
        let pem = binary_to_string(self.encoded_bytes()?, flags, "certificate PEM encoding")?;
        String::from_utf8(pem)
            .map_err(|e| format!("CryptBinaryToStringA returned non-ASCII PEM: {e}").into())
    }

    fn public_key_spki_der(&self) -> Result<Vec<u8>> {
        let public_key_info = &self.cert_info()?.SubjectPublicKeyInfo;
        validate_public_key_info(public_key_info)?;
        encode_object(
            X509_PUBLIC_KEY_INFO,
            public_key_info,
            "certificate SubjectPublicKeyInfo",
        )
    }

    fn get_extension_value_by_oid(&self, oid: &str) -> Result<Option<Vec<u8>>> {
        self.find_extension(oid)?
            .map(|extension| copy_blob(&extension.Value, "certificate extension value", false))
            .transpose()
    }

    fn subject_name(&self) -> String {
        self.cert_info()
            .and_then(|info| name_to_string(&info.Subject, "certificate subject"))
            .unwrap_or_else(|_| UNAVAILABLE_CERTIFICATE_NAME.to_string())
    }

    fn issuer_name(&self) -> String {
        self.cert_info()
            .and_then(|info| name_to_string(&info.Issuer, "certificate issuer"))
            .unwrap_or_else(|_| UNAVAILABLE_CERTIFICATE_NAME.to_string())
    }

    fn subject_name_der(&self) -> Result<Vec<u8>> {
        copy_blob(&self.cert_info()?.Subject, "certificate subject name", true)
    }

    fn issuer_name_der(&self) -> Result<Vec<u8>> {
        copy_blob(&self.cert_info()?.Issuer, "certificate issuer name", true)
    }

    fn is_valid_at(&self, unix_time: Duration) -> Result<bool> {
        let file_time = unix_duration_to_filetime(unix_time)?;
        Ok(unsafe {
            CertVerifyTimeValidity(Some(&file_time), self.cert_info()? as *const CERT_INFO)
        } == 0)
    }

    fn version(&self) -> Result<u8> {
        match self.cert_info()?.dwVersion {
            CERT_V1 => Ok(0),
            CERT_V2 => Ok(1),
            CERT_V3 => Ok(2),
            version => Err(format!("Unsupported X.509 certificate version {version}").into()),
        }
    }

    fn basic_constraints(&self) -> Result<Option<super::BasicConstraints>> {
        let Some(extension) = self.find_extension("2.5.29.19")? else {
            return Ok(None);
        };
        let value = blob_bytes(&extension.Value, "basicConstraints extension value", true)?;
        let decoded = decode_object::<CERT_BASIC_CONSTRAINTS2_INFO>(
            X509_BASIC_CONSTRAINTS2,
            value,
            "basicConstraints",
        )?;
        require_canonical_encoding(
            X509_BASIC_CONSTRAINTS2,
            decoded.get(),
            value,
            "basicConstraints",
        )?;
        let constraints = decoded.get();

        Ok(Some(super::BasicConstraints {
            critical: extension.fCritical.as_bool(),
            ca: constraints.fCA.as_bool(),
            path_len_constraint: constraints
                .fPathLenConstraint
                .as_bool()
                .then_some(constraints.dwPathLenConstraint as usize),
        }))
    }

    fn key_usage(&self) -> Result<Option<super::KeyUsage>> {
        let Some(extension) = self.find_extension("2.5.29.15")? else {
            return Ok(None);
        };
        let value = blob_bytes(&extension.Value, "keyUsage extension value", true)?;
        let decoded = decode_object::<CRYPT_BIT_BLOB>(X509_KEY_USAGE, value, "keyUsage extension")?;
        let usage_bytes = bit_blob_bytes(decoded.get(), "decoded keyUsage", false)?;
        require_canonical_encoding(X509_KEY_USAGE, decoded.get(), value, "keyUsage extension")?;

        Ok(Some(super::KeyUsage {
            key_cert_sign: usage_bytes
                .first()
                .map(|byte| *byte & CERT_KEY_CERT_SIGN_KEY_USAGE as u8 != 0)
                .unwrap_or(false),
        }))
    }

    fn extension_criticality(&self, oid: &str) -> Result<Option<bool>> {
        Ok(self
            .find_extension(oid)?
            .map(|extension| extension.fCritical.as_bool()))
    }

    fn critical_extension_oids(&self) -> Vec<String> {
        let extensions = match self.extensions() {
            Ok(extensions) => extensions,
            Err(_) => return Vec::new(),
        };

        extensions
            .iter()
            .filter(|extension| extension.fCritical.as_bool())
            .filter_map(extension_oid)
            .collect()
    }

    fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.context.as_ptr().cast_const()
    }

    fn context(&self) -> &CERT_CONTEXT {
        unsafe { self.context.as_ref() }
    }

    fn cert_info(&self) -> Result<&CERT_INFO> {
        unsafe { self.context().pCertInfo.as_ref() }
            .ok_or_else(|| "Certificate context contains a null CERT_INFO".into())
    }

    fn encoded_bytes(&self) -> Result<&[u8]> {
        pointer_slice(
            self.context(),
            self.context().pbCertEncoded.cast_const(),
            self.context().cbCertEncoded,
            "certificate encoded bytes",
            true,
        )
    }

    fn extensions(&self) -> Result<&[CERT_EXTENSION]> {
        extension_slice(self.cert_info()?)
    }

    fn find_extension(&self, oid: &str) -> Result<Option<&CERT_EXTENSION>> {
        let oid = validated_oid_cstring(oid)?;
        let extensions = self.extensions()?;
        if extensions.is_empty() {
            return Ok(None);
        }

        let found =
            unsafe { CertFindExtension(PCSTR::from_raw(oid.as_ptr().cast::<u8>()), extensions) };
        if found.is_null() {
            return Ok(None);
        }

        let start = extensions.as_ptr() as usize;
        let byte_len = extensions
            .len()
            .checked_mul(size_of::<CERT_EXTENSION>())
            .ok_or("Certificate extension array size overflow")?;
        let end = start
            .checked_add(byte_len)
            .ok_or("Certificate extension array address overflow")?;
        let address = found as usize;
        if address < start || address >= end || (address - start) % size_of::<CERT_EXTENSION>() != 0
        {
            return Err("CertFindExtension returned a pointer outside the extension array".into());
        }

        Ok(Some(unsafe { &*found }))
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let handle = import_spki(spki_der)?;
        validate_imported_key(&handle, algorithm)?;
        drop(handle);

        Ok(Self {
            spki_der: spki_der.to_vec(),
            algorithm,
        })
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
        cert.version()
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
        let handle = import_spki(&key.spki_der)?;
        validate_imported_key(&handle, key.algorithm)?;
        let digest = Self::digest(signature.algorithm.digest(), signed_bytes)?;
        let digest_id = hash_algorithm_id(signature.algorithm.digest());
        let operation = signature_verification_name(signature.algorithm);

        let status = match signature.algorithm {
            SignatureKeyAlgorithm::Ec(_) => unsafe {
                BCryptVerifySignature(
                    handle.0,
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
                        handle.0,
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
                        handle.0,
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
        let trusted_people_store = CertStore::memory("exclusive trusted people")?;
        trusted_people_store.add_certificate(trusted_cert, "peer-trusted certificate")?;

        let intermediate_store = CertStore::memory("restricted intermediate")?;
        for (index, cert) in untrusted_chain.iter().enumerate() {
            intermediate_store
                .add_certificate(cert, &format!("untrusted intermediate certificate {index}"))?;
        }

        let mut engine_config = CERT_CHAIN_ENGINE_CONFIG {
            cbSize: checked_struct_size::<CERT_CHAIN_ENGINE_CONFIG>()?,
            hExclusiveRoot: root_store.0,
            hExclusiveTrustedPeople: trusted_people_store.0,
            dwExclusiveFlags: CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG,
            ..Default::default()
        };
        let engine = ChainEngine::create(&mut engine_config)?;

        let mut chain_para = CERT_CHAIN_PARA {
            cbSize: checked_struct_size::<CERT_CHAIN_PARA>()?,
            ..Default::default()
        };
        let file_time = unix_time.map(unix_duration_to_filetime).transpose()?;
        let time_ptr = file_time.as_ref().map(|time| time as *const FILETIME);
        let chain = ChainContext::build(
            &engine,
            leaf,
            &mut chain_para,
            time_ptr,
            &intermediate_store,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
                | CERT_CHAIN_DISABLE_AIA
                | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
                | CERT_CHAIN_ENABLE_PEER_TRUST,
        )?;
        let leaf_der = leaf.to_der()?;
        let trusted_der = trusted_cert.to_der()?;
        let untrusted_der = untrusted_chain
            .iter()
            .map(|cert| cert.to_der())
            .collect::<Result<Vec<_>>>()?;
        chain.validate_path(&leaf_der, &trusted_der, &untrusted_der)?;
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

struct DecodedObject<T> {
    storage: Vec<usize>,
    marker: PhantomData<T>,
}

impl<T> DecodedObject<T> {
    fn get(&self) -> &T {
        unsafe { &*self.storage.as_ptr().cast::<T>() }
    }
}

fn decode_object<T>(object_type: PCSTR, encoded: &[u8], name: &str) -> Result<DecodedObject<T>> {
    require_nonempty_u32_input(name, encoded)?;
    if align_of::<usize>() < align_of::<T>() {
        return Err(format!(
            "{name} requires alignment {}, exceeding native decode storage alignment {}",
            align_of::<T>(),
            align_of::<usize>()
        )
        .into());
    }

    let mut required_size = 0u32;
    unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            object_type,
            encoded,
            0,
            None,
            None,
            &mut required_size,
        )
    }
    .map_err(|e| operation_error(&format!("CryptDecodeObjectEx {name} size query"), e))?;
    if required_size < checked_struct_size::<T>()? {
        return Err(format!(
            "CryptDecodeObjectEx {name} returned undersized output {required_size}"
        )
        .into());
    }

    let required_size =
        usize::try_from(required_size).map_err(|_| format!("{name} size does not fit usize"))?;
    let word_size = size_of::<usize>();
    let word_count = required_size
        .checked_add(word_size - 1)
        .ok_or_else(|| format!("{name} decoded size overflow"))?
        / word_size;
    let mut storage = vec![0usize; word_count];
    let capacity = word_count
        .checked_mul(word_size)
        .ok_or_else(|| format!("{name} decoded allocation size overflow"))?;
    let mut actual_size = checked_u32_len(name, capacity)?;
    unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            object_type,
            encoded,
            0,
            None,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            &mut actual_size,
        )
    }
    .map_err(|e| operation_error(&format!("CryptDecodeObjectEx {name}"), e))?;
    if actual_size < checked_struct_size::<T>()? || actual_size as usize > capacity {
        return Err(format!(
            "CryptDecodeObjectEx {name} returned invalid output size {actual_size}"
        )
        .into());
    }

    Ok(DecodedObject {
        storage,
        marker: PhantomData,
    })
}

fn encode_object<T>(object_type: PCSTR, value: &T, name: &str) -> Result<Vec<u8>> {
    let mut required_size = 0u32;
    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            object_type,
            (value as *const T).cast::<c_void>(),
            CRYPT_ENCODE_OBJECT_FLAGS::default(),
            None,
            None,
            &mut required_size,
        )
    }
    .map_err(|e| operation_error(&format!("CryptEncodeObjectEx {name} size query"), e))?;
    if required_size == 0 {
        return Err(format!("CryptEncodeObjectEx {name} returned an empty encoding").into());
    }

    let mut encoded = vec![0u8; required_size as usize];
    let mut actual_size = required_size;
    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            object_type,
            (value as *const T).cast::<c_void>(),
            CRYPT_ENCODE_OBJECT_FLAGS::default(),
            None,
            Some(encoded.as_mut_ptr().cast::<c_void>()),
            &mut actual_size,
        )
    }
    .map_err(|e| operation_error(&format!("CryptEncodeObjectEx {name}"), e))?;
    if actual_size == 0 || actual_size as usize > encoded.len() {
        return Err(format!(
            "CryptEncodeObjectEx {name} returned invalid output size {actual_size}"
        )
        .into());
    }
    encoded.truncate(actual_size as usize);
    Ok(encoded)
}

fn require_canonical_encoding<T>(
    object_type: PCSTR,
    value: &T,
    encoded: &[u8],
    name: &str,
) -> Result<()> {
    if encode_object(object_type, value, name)? != encoded {
        return Err(format!("{name} is not a canonical whole-input DER encoding").into());
    }
    Ok(())
}

fn parse_pem_certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    require_nonempty_u32_input("PEM input", pem)?;

    let mut certificates = Vec::new();
    let mut cursor = 0usize;
    while cursor < pem.len() {
        while cursor < pem.len() && pem[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor == pem.len() {
            break;
        }
        if cursor != 0 && pem[cursor - 1] != b'\n' {
            return Err(format!(
                "CERTIFICATE PEM begin label at byte {cursor} is not at the start of a line"
            )
            .into());
        }
        if !pem[cursor..].starts_with(PEM_BEGIN_CERTIFICATE) {
            return Err(format!(
                "Unexpected non-whitespace data outside a CERTIFICATE PEM block at byte {cursor}"
            )
            .into());
        }

        let body_start = cursor
            .checked_add(PEM_BEGIN_CERTIFICATE.len())
            .ok_or("PEM block offset overflow")?;
        let body_start = consume_pem_line_ending(pem, body_start, "begin label")?;
        let end_offset = find_subslice(&pem[body_start..], PEM_END_CERTIFICATE)
            .ok_or("CERTIFICATE PEM block has no matching end label")?;
        let body_end = body_start
            .checked_add(end_offset)
            .ok_or("PEM block length overflow")?;
        if body_end == 0 || pem[body_end - 1] != b'\n' {
            return Err("CERTIFICATE PEM end label is not at the start of a line".into());
        }
        certificates.push(decode_base64_certificate(&pem[body_start..body_end])?);
        cursor = body_end
            .checked_add(PEM_END_CERTIFICATE.len())
            .ok_or("PEM block end offset overflow")?;
        if cursor < pem.len() {
            cursor = consume_pem_line_ending(pem, cursor, "end label")?;
        }
    }

    if certificates.is_empty() {
        return Err("PEM input contains no CERTIFICATE blocks".into());
    }
    Ok(certificates)
}

fn consume_pem_line_ending(pem: &[u8], offset: usize, label: &str) -> Result<usize> {
    let remaining = pem
        .get(offset..)
        .ok_or("PEM line-ending offset is out of bounds")?;
    if remaining.starts_with(b"\r\n") {
        return offset
            .checked_add(2)
            .ok_or_else(|| "PEM line-ending offset overflow".into());
    }
    if remaining.starts_with(b"\n") {
        return offset
            .checked_add(1)
            .ok_or_else(|| "PEM line-ending offset overflow".into());
    }
    Err(format!("CERTIFICATE PEM {label} must occupy a complete LF or CRLF line").into())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_base64_certificate(base64: &[u8]) -> Result<Vec<u8>> {
    require_nonempty_u32_input("certificate Base64", base64)?;
    let flags = CRYPT_STRING(CRYPT_STRING_BASE64.0 | CRYPT_STRING_STRICT.0);
    let mut required_size = 0u32;
    unsafe { CryptStringToBinaryA(base64, flags, None, &mut required_size, None, None) }
        .map_err(|e| operation_error("CryptStringToBinaryA certificate size query", e))?;
    if required_size == 0 {
        return Err("CERTIFICATE PEM block has an empty Base64 payload".into());
    }

    let mut decoded = vec![0u8; required_size as usize];
    let mut actual_size = required_size;
    unsafe {
        CryptStringToBinaryA(
            base64,
            flags,
            Some(decoded.as_mut_ptr()),
            &mut actual_size,
            None,
            None,
        )
    }
    .map_err(|e| operation_error("CryptStringToBinaryA certificate", e))?;
    if actual_size == 0 || actual_size as usize > decoded.len() {
        return Err(format!(
            "CryptStringToBinaryA certificate returned invalid output size {actual_size}"
        )
        .into());
    }
    decoded.truncate(actual_size as usize);

    let canonical_flags = CRYPT_STRING(CRYPT_STRING_BASE64.0 | CRYPT_STRING_NOCRLF);
    let canonical = binary_to_string(
        &decoded,
        canonical_flags,
        "certificate Base64 canonicalization",
    )?;
    let normalized = base64
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if normalized != canonical {
        return Err("CERTIFICATE PEM block does not use canonical Base64".into());
    }

    Ok(decoded)
}

fn binary_to_string(binary: &[u8], flags: CRYPT_STRING, name: &str) -> Result<Vec<u8>> {
    require_nonempty_u32_input(name, binary)?;

    let mut required_size = 0u32;
    if !unsafe { CryptBinaryToStringA(binary, flags, None, &mut required_size) }.as_bool() {
        return Err(operation_error(
            &format!("CryptBinaryToStringA {name} size query"),
            WindowsError::from_win32(),
        ));
    }
    if required_size == 0 {
        return Err(format!("CryptBinaryToStringA {name} returned an empty size").into());
    }

    let mut encoded = vec![0u8; required_size as usize];
    let mut actual_size = required_size;
    if !unsafe {
        CryptBinaryToStringA(
            binary,
            flags,
            Some(PSTR::from_raw(encoded.as_mut_ptr())),
            &mut actual_size,
        )
    }
    .as_bool()
    {
        return Err(operation_error(
            &format!("CryptBinaryToStringA {name}"),
            WindowsError::from_win32(),
        ));
    }

    let actual_size =
        usize::try_from(actual_size).map_err(|_| format!("{name} length does not fit usize"))?;
    if actual_size >= encoded.len() || encoded[actual_size] != 0 {
        return Err(format!(
            "CryptBinaryToStringA {name} returned an invalid terminated length {actual_size}"
        )
        .into());
    }
    encoded.truncate(actual_size);
    if encoded.contains(&0) {
        return Err(format!("CryptBinaryToStringA {name} returned an embedded null").into());
    }
    Ok(encoded)
}

fn name_to_string(name: &CRYPT_INTEGER_BLOB, description: &str) -> Result<String> {
    blob_bytes(name, description, true)?;

    let required_size =
        unsafe { CertNameToStrW(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, None) };
    if required_size == 0 {
        return Err(operation_error(
            &format!("CertNameToStrW {description} size query"),
            WindowsError::from_win32(),
        ));
    }

    let mut output = vec![0u16; required_size as usize];
    let actual_size = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING,
            name,
            CERT_X500_NAME_STR,
            Some(&mut output),
        )
    };
    if actual_size == 0 || actual_size > required_size {
        return Err(format!(
            "CertNameToStrW {description} returned invalid output size {actual_size}"
        )
        .into());
    }
    let actual_size = actual_size as usize;
    if output[actual_size - 1] != 0 || output[..actual_size - 1].contains(&0) {
        return Err(format!("CertNameToStrW {description} returned invalid termination").into());
    }

    String::from_utf16(&output[..actual_size - 1])
        .map_err(|e| format!("CertNameToStrW {description} returned invalid UTF-16: {e}").into())
}

fn pointer_slice<'a, O: ?Sized, T>(
    _owner: &'a O,
    pointer: *const T,
    count: u32,
    name: &str,
    require_nonempty: bool,
) -> Result<&'a [T]> {
    let count = usize::try_from(count).map_err(|_| format!("{name} length does not fit usize"))?;
    if count == 0 {
        if require_nonempty {
            return Err(format!("{name} is empty").into());
        }
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(format!("{name} has a null pointer with nonzero length").into());
    }
    let byte_len = count
        .checked_mul(size_of::<T>())
        .ok_or_else(|| format!("{name} byte length overflow"))?;
    if byte_len > isize::MAX as usize {
        return Err(format!("{name} exceeds the maximum Rust slice length").into());
    }

    Ok(unsafe { std::slice::from_raw_parts(pointer, count) })
}

fn blob_bytes<'a>(
    blob: &'a CRYPT_INTEGER_BLOB,
    name: &str,
    require_nonempty: bool,
) -> Result<&'a [u8]> {
    pointer_slice(
        blob,
        blob.pbData.cast_const(),
        blob.cbData,
        name,
        require_nonempty,
    )
}

fn copy_blob(blob: &CRYPT_INTEGER_BLOB, name: &str, require_nonempty: bool) -> Result<Vec<u8>> {
    Ok(blob_bytes(blob, name, require_nonempty)?.to_vec())
}

fn bit_blob_bytes<'a>(
    blob: &'a CRYPT_BIT_BLOB,
    name: &str,
    require_nonempty: bool,
) -> Result<&'a [u8]> {
    if blob.cUnusedBits > 7 {
        return Err(format!("{name} has invalid unused-bit count {}", blob.cUnusedBits).into());
    }
    let bytes = pointer_slice(
        blob,
        blob.pbData.cast_const(),
        blob.cbData,
        name,
        require_nonempty,
    )?;
    if bytes.is_empty() && blob.cUnusedBits != 0 {
        return Err(format!("{name} has unused bits but no data").into());
    }
    Ok(bytes)
}

fn extension_slice(info: &CERT_INFO) -> Result<&[CERT_EXTENSION]> {
    pointer_slice(
        info,
        info.rgExtension.cast_const(),
        info.cExtension,
        "certificate extension array",
        false,
    )
}

fn validate_signed_content(signed: &CERT_SIGNED_CONTENT_INFO) -> Result<()> {
    blob_bytes(&signed.ToBeSigned, "certificate to-be-signed bytes", true)?;
    validate_algorithm_identifier(
        &signed.SignatureAlgorithm,
        "certificate signature algorithm",
    )?;
    bit_blob_bytes(&signed.Signature, "certificate signature", true)?;
    Ok(())
}

fn validate_cert_info(info: &CERT_INFO) -> Result<()> {
    blob_bytes(&info.SerialNumber, "certificate serial number", true)?;
    validate_algorithm_identifier(&info.SignatureAlgorithm, "certificate signature algorithm")?;
    validate_name(&info.Issuer, "certificate issuer name")?;
    validate_name(&info.Subject, "certificate subject name")?;
    validate_public_key_info(&info.SubjectPublicKeyInfo)?;
    bit_blob_bytes(&info.IssuerUniqueId, "certificate issuer unique ID", false)?;
    bit_blob_bytes(
        &info.SubjectUniqueId,
        "certificate subject unique ID",
        false,
    )?;
    for (index, extension) in extension_slice(info)?.iter().enumerate() {
        if extension.pszObjId.is_null() {
            return Err(format!("Certificate extension {index} has a null OID").into());
        }
        blob_bytes(
            &extension.Value,
            &format!("certificate extension {index} value"),
            false,
        )?;
    }
    Ok(())
}

fn validate_name(name: &CRYPT_INTEGER_BLOB, description: &str) -> Result<()> {
    let encoded = blob_bytes(name, description, true)?;
    let decoded = decode_object::<CERT_NAME_INFO>(X509_NAME, encoded, description)?;
    let name_info = decoded.get();
    let rdns = pointer_slice(
        name_info,
        name_info.rgRDN.cast_const(),
        name_info.cRDN,
        &format!("{description} RDN array"),
        false,
    )?;
    for (rdn_index, rdn) in rdns.iter().enumerate() {
        let attributes = pointer_slice(
            rdn,
            rdn.rgRDNAttr.cast_const(),
            rdn.cRDNAttr,
            &format!("{description} RDN {rdn_index} attribute array"),
            true,
        )?;
        for (attribute_index, attribute) in attributes.iter().enumerate() {
            if attribute.pszObjId.is_null() {
                return Err(format!(
                    "{description} RDN {rdn_index} attribute {attribute_index} has a null OID"
                )
                .into());
            }
            blob_bytes(
                &attribute.Value,
                &format!("{description} RDN {rdn_index} attribute {attribute_index} value"),
                false,
            )?;
        }
    }
    require_canonical_encoding(X509_NAME, name_info, encoded, description)
}

fn validate_algorithm_identifier(algorithm: &CRYPT_ALGORITHM_IDENTIFIER, name: &str) -> Result<()> {
    if algorithm.pszObjId.is_null() {
        return Err(format!("{name} has a null OID").into());
    }
    blob_bytes(&algorithm.Parameters, &format!("{name} parameters"), false)?;
    Ok(())
}

fn validate_public_key_info(public_key_info: &CERT_PUBLIC_KEY_INFO) -> Result<()> {
    validate_algorithm_identifier(&public_key_info.Algorithm, "public key algorithm")?;
    bit_blob_bytes(&public_key_info.PublicKey, "public key bit string", true)?;
    Ok(())
}

fn extension_oid(extension: &CERT_EXTENSION) -> Option<String> {
    if extension.pszObjId.is_null() {
        return None;
    }
    let oid = unsafe { extension.pszObjId.to_string().ok()? };
    validate_oid(&oid).ok()?;
    Some(oid)
}

fn validated_oid_cstring(oid: &str) -> Result<CString> {
    validate_oid(oid)?;
    CString::new(oid).map_err(|_| "OID unexpectedly contains an interior null".into())
}

fn validate_oid(oid: &str) -> Result<()> {
    checked_u32_len("OID", oid.len())?;
    let mut arcs = oid.split('.');
    let first = arcs
        .next()
        .ok_or("OID must contain at least two dotted-decimal arcs")?;
    let second = arcs
        .next()
        .ok_or("OID must contain at least two dotted-decimal arcs")?;
    validate_oid_arc(first)?;
    validate_oid_arc(second)?;
    for arc in arcs {
        validate_oid_arc(arc)?;
    }

    if first != "0" && first != "1" && first != "2" {
        return Err("OID first arc must be 0, 1, or 2".into());
    }
    if first != "2" {
        if second.len() > 2
            || second
                .parse::<u8>()
                .map_err(|_| "OID second arc is invalid")?
                > 39
        {
            return Err("OID second arc must be at most 39 when the first arc is 0 or 1".into());
        }
    }
    Ok(())
}

fn validate_oid_arc(arc: &str) -> Result<()> {
    if arc.is_empty() {
        return Err("OID contains an empty arc".into());
    }
    if !arc.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("OID contains a non-decimal arc".into());
    }
    if arc.len() > 1 && arc.as_bytes()[0] == b'0' {
        return Err("OID arcs must not contain leading zeroes".into());
    }
    Ok(())
}

fn require_nonempty_u32_input(name: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(format!("{name} is empty").into());
    }
    checked_u32_len(name, bytes.len())?;
    Ok(())
}

fn import_spki(spki_der: &[u8]) -> Result<KeyHandle> {
    let decoded = decode_object::<CERT_PUBLIC_KEY_INFO>(
        X509_PUBLIC_KEY_INFO,
        spki_der,
        "SubjectPublicKeyInfo",
    )?;
    validate_public_key_info(decoded.get())?;
    require_canonical_encoding(
        X509_PUBLIC_KEY_INFO,
        decoded.get(),
        spki_der,
        "SubjectPublicKeyInfo",
    )?;

    let mut handle = BCRYPT_KEY_HANDLE::default();
    unsafe {
        CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            decoded.get(),
            CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG,
            None,
            &mut handle,
        )
    }
    .map_err(|e| operation_error("CryptImportPublicKeyInfoEx2 signing key import", e))?;
    KeyHandle::new(handle)
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
        let der = cert.encoded_bytes()?;
        checked_u32_len(name, der.len())?;
        unsafe {
            CertAddEncodedCertificateToStore(
                Some(self.0),
                X509_ASN_ENCODING,
                der,
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
        leaf: &Certificate,
        parameters: &mut CERT_CHAIN_PARA,
        time: Option<*const FILETIME>,
        additional_store: &CertStore,
        flags: u32,
    ) -> Result<Self> {
        let mut context = std::ptr::null_mut();
        unsafe {
            CertGetCertificateChain(
                Some(engine.0),
                leaf.as_ptr(),
                time,
                Some(additional_store.0),
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

    fn validate_path(
        &self,
        expected_leaf: &[u8],
        expected_trusted: &[u8],
        allowed_intermediates: &[Vec<u8>],
    ) -> Result<()> {
        let context = unsafe { self.0.as_ref() }
            .ok_or("Certificate chain context unexpectedly became null")?;
        if context.cbSize < checked_struct_size::<CERT_CHAIN_CONTEXT>()? {
            return Err(format!(
                "Certificate chain context has invalid size {}",
                context.cbSize
            )
            .into());
        }
        if context.cChain != 1 {
            return Err(format!(
                "Certificate chain context contains {} simple chains; expected exactly one",
                context.cChain
            )
            .into());
        }
        let simple_chains = pointer_slice(
            context,
            context.rgpChain.cast_const(),
            context.cChain,
            "certificate simple-chain array",
            true,
        )?;
        let simple_chain_ptr = *simple_chains
            .first()
            .ok_or("Certificate chain context contains no simple chains")?;
        let simple_chain = unsafe { simple_chain_ptr.as_ref() }
            .ok_or("Certificate chain context contains a null simple chain")?;
        if simple_chain.cbSize < checked_struct_size::<CERT_SIMPLE_CHAIN>()? {
            return Err(format!(
                "Certificate simple chain has invalid size {}",
                simple_chain.cbSize
            )
            .into());
        }

        let element_count = usize::try_from(simple_chain.cElement)
            .map_err(|_| "Certificate chain element count does not fit usize")?;
        if element_count == 0 {
            return Err("Certificate simple chain contains no elements".into());
        }
        let max_elements = allowed_intermediates
            .len()
            .checked_add(2)
            .ok_or("Allowed certificate path length overflow")?;
        if element_count > max_elements {
            return Err(format!(
                "Certificate simple chain contains {element_count} elements, exceeding the caller-supplied path limit {max_elements}"
            )
            .into());
        }
        let elements = pointer_slice(
            simple_chain,
            simple_chain.rgpElement.cast_const(),
            simple_chain.cElement,
            "certificate chain element array",
            true,
        )?;

        for (index, element_ptr) in elements.iter().copied().enumerate() {
            let element = unsafe { element_ptr.as_ref() }
                .ok_or_else(|| format!("Certificate chain element {index} is null"))?;
            if element.cbSize < checked_struct_size::<CERT_CHAIN_ELEMENT>()? {
                return Err(format!(
                    "Certificate chain element {index} has invalid size {}",
                    element.cbSize
                )
                .into());
            }

            let cert_context = unsafe { element.pCertContext.as_ref() }
                .ok_or_else(|| format!("Certificate chain element {index} has a null context"))?;
            let encoded = pointer_slice(
                cert_context,
                cert_context.pbCertEncoded.cast_const(),
                cert_context.cbCertEncoded,
                &format!("certificate chain element {index} encoded bytes"),
                true,
            )?;

            if index == 0 && encoded != expected_leaf {
                return Err(
                    "Certificate chain begins with a certificate other than the supplied leaf"
                        .into(),
                );
            }
            if index + 1 == element_count && encoded != expected_trusted {
                return Err(
                    "Certificate chain terminates at a certificate other than the supplied trust anchor"
                        .into(),
                );
            }
            if index > 0
                && index + 1 < element_count
                && !allowed_intermediates
                    .iter()
                    .any(|allowed| allowed.as_slice() == encoded)
            {
                return Err(format!(
                    "Certificate chain element {index} was not supplied by the caller"
                )
                .into());
            }
        }

        Ok(())
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
