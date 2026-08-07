// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WASM WebCrypto-backed cryptographic backend.
//!
//! This backend uses the host runtime's `globalThis.crypto.subtle` API for
//! asynchronous certificate-chain and SEV-SNP attestation report signature
//! verification. Certificate parsing, encoding, and extension inspection use
//! the shared pure-Rust X.509 parser. The runtime must provide WebCrypto with
//! RSA-PSS/SHA-384 and ECDSA P-256/P-384/P-521 verification support.

use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use std::time::Duration;
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::x509_certificate::{self, Certificate as X509Certificate};
use super::x509_policy;
use super::{
    compatible_key_and_signature, AsyncCryptoBackend, AsyncKeyBackend, CertificateBackend,
    DigestAlgorithm, EcSignatureKeyAlgorithm, Result, RsaPkcs1v15SignatureKeyAlgorithm,
    RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    inner: X509Certificate,
}

pub struct Key {
    key: CryptoKey,
    spki_der: Vec<u8>,
    algorithm: SignatureKeyAlgorithm,
}

pub enum Signature {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
        fixed: Vec<u8>,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => Ok(Signature::Ecdsa {
                algorithm,
                fixed: super::ecdsa_signature::ecdsa_der_to_fixed(signature, algorithm)?,
            }),
            SignatureKeyAlgorithm::RsaPss(algorithm) => Ok(Signature::RsaPss {
                algorithm,
                raw: signature.to_vec(),
            }),
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => Ok(Signature::RsaPkcs1v15 {
                algorithm,
                raw: signature.to_vec(),
            }),
        }
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        Ok(Signature::Ecdsa {
            algorithm,
            fixed: super::ecdsa_signature::fixed_from_components(r, s, algorithm)?,
        })
    }
}

impl AsyncKeyBackend for Key {
    async fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let subtle = subtle_crypto()?;
        let params = import_params(algorithm)?;
        let key = import_spki_key(&subtle, spki_der, &params).await?;

        Ok(Key {
            key,
            spki_der: spki_der.to_vec(),
            algorithm,
        })
    }
}

impl Certificate {
    fn from_inner(inner: X509Certificate) -> Self {
        Self { inner }
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        Ok(Certificate::from_inner(X509Certificate::from_pem(pem)?))
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        X509Certificate::from_pem_chain(pem)?
            .into_iter()
            .map(Certificate::from_inner)
            .map(Ok)
            .collect()
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        Ok(Certificate::from_inner(X509Certificate::from_der(der)?))
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.to_der()
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        cert.inner.to_pem()
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.public_key_spki_der()
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.inner.get_extension_value_by_oid(oid)
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        cert.inner.subject_name()
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        cert.inner.issuer_name()
    }

    fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.subject_name_der()
    }

    fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.inner.issuer_name_der()
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        cert.inner.is_valid_at(unix_time)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        Ok(cert.inner.version())
    }

    fn basic_constraints(cert: &Self::Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.inner.basic_constraints()
    }

    fn key_usage(cert: &Self::Certificate) -> Result<Option<super::KeyUsage>> {
        cert.inner.key_usage()
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        cert.inner.extension_criticality(oid)
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        cert.inner.critical_extension_oids()
    }
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.algorithm
    }
}

impl AsyncCryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    async fn digest(algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        let subtle = subtle_crypto()?;
        let promise = subtle
            .digest_with_str_and_u8_array(digest_algorithm_name(algorithm), bytes)
            .map_err(js_error)?;
        let digest = JsFuture::from(promise).await.map_err(js_error)?;
        Ok(Uint8Array::new(&digest).to_vec())
    }

    async fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        let signature_algorithm = signature.algorithm();
        if !compatible_key_and_signature(key.algorithm, signature_algorithm) {
            return Err(format!(
                "WebCrypto signature algorithm {signature_algorithm:?} does not match key algorithm {:?}",
                key.algorithm
            )
            .into());
        }

        let subtle = subtle_crypto()?;
        let temporary_key = if key.algorithm == signature_algorithm {
            None
        } else {
            let import_params = import_params(signature_algorithm)?;
            Some(import_spki_key(&subtle, &key.spki_der, &import_params).await?)
        };
        let verification_key = temporary_key.as_ref().unwrap_or(&key.key);
        let params = verify_params(signature_algorithm)?;
        let signature = webcrypto_signature_bytes(signature_algorithm, signature)?;

        verify_with_subtle(&subtle, verification_key, &params, &signature, signed_bytes).await
    }

    async fn verify_chain(
        trusted_cert: &Self::Certificate,
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
        unix_time: Option<Duration>,
    ) -> Result<()> {
        let untrusted_x509 = untrusted_chain
            .iter()
            .map(|cert| &cert.inner)
            .collect::<Vec<_>>();

        x509_certificate::verify_certificate_path_async(
            |issuer, subject| Box::pin(verify_x509_certificate_signature(issuer, subject)),
            &trusted_cert.inner,
            &untrusted_x509,
            &leaf.inner,
        )
        .await?;

        let policy_path = std::iter::once(trusted_cert)
            .chain(untrusted_chain.iter().copied())
            .chain(std::iter::once(leaf));
        x509_policy::rfc5280_policy::<Crypto, _>(policy_path, unix_time.unwrap_or(unix_time_now()?))
    }
}

fn unix_time_now() -> Result<Duration> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || millis < 0.0 || millis > u64::MAX as f64 {
        return Err("Failed to read current Unix time from JavaScript Date".into());
    }

    Ok(Duration::from_millis(millis as u64))
}

async fn verify_x509_certificate_signature(
    issuer: &X509Certificate,
    subject: &X509Certificate,
) -> Result<()> {
    let spki_der = issuer.public_key_spki_der()?;
    let algorithm = subject.signature_algorithm()?;
    let key = <Key as AsyncKeyBackend>::from_spki_der(&spki_der, algorithm).await?;
    let data = subject.tbs_certificate_der()?;
    let signature =
        <Signature as SignatureBackend>::from_bytes(subject.signature_bytes(), algorithm)?;

    <Crypto as AsyncCryptoBackend>::verify_signature(&key, &signature, &data).await
}

async fn import_spki_key(
    subtle: &SubtleCrypto,
    spki_der: &[u8],
    algorithm: &Object,
) -> Result<CryptoKey> {
    let key_data = Uint8Array::from(spki_der);
    let usages = Array::new();
    usages.push(&JsValue::from_str("verify"));
    let key_usages = JsValue::from(usages);

    let promise = subtle
        .import_key_with_object("spki", key_data.as_ref(), algorithm, false, &key_usages)
        .map_err(js_error)?;
    let key = JsFuture::from(promise).await.map_err(js_error)?;

    key.dyn_into::<CryptoKey>()
        .map_err(|_| "WebCrypto importKey did not return a CryptoKey".into())
}

async fn verify_with_subtle(
    subtle: &SubtleCrypto,
    key: &CryptoKey,
    params: &Object,
    signature: &[u8],
    data: &[u8],
) -> Result<()> {
    let promise = subtle
        .verify_with_object_and_u8_array_and_u8_array(params, key, signature, data)
        .map_err(js_error)?;
    let verified = JsFuture::from(promise).await.map_err(js_error)?;

    if verified.as_bool() == Some(true) {
        Ok(())
    } else {
        Err("WebCrypto signature verification failed".into())
    }
}

fn subtle_crypto() -> Result<SubtleCrypto> {
    let global = js_sys::global();
    let crypto = Reflect::get(&global, &JsValue::from_str("crypto")).map_err(js_error)?;
    if crypto.is_undefined() || crypto.is_null() {
        return Err("globalThis.crypto is not available".into());
    }

    let subtle = Reflect::get(&crypto, &JsValue::from_str("subtle")).map_err(js_error)?;
    if subtle.is_undefined() || subtle.is_null() {
        return Err("globalThis.crypto.subtle is not available".into());
    }

    subtle
        .dyn_into::<SubtleCrypto>()
        .map_err(|_| "globalThis.crypto.subtle is not a SubtleCrypto object".into())
}

fn import_params(algorithm: SignatureKeyAlgorithm) -> Result<Object> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(algorithm) => ecdsa_import_params(algorithm),
        SignatureKeyAlgorithm::RsaPss(algorithm) => rsa_pss_import_params(algorithm.digest()),
        SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => rsa_pkcs1v15_params(algorithm.digest()),
    }
}

fn verify_params(algorithm: SignatureKeyAlgorithm) -> Result<Object> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(algorithm) => ecdsa_verify_params(algorithm.digest()),
        SignatureKeyAlgorithm::RsaPss(algorithm) => rsa_pss_verify_params(algorithm.salt_len()),
        SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => rsa_pkcs1v15_params(algorithm.digest()),
    }
}

fn webcrypto_signature_bytes(
    algorithm: SignatureKeyAlgorithm,
    signature: &Signature,
) -> Result<Vec<u8>> {
    match (algorithm, signature) {
        (SignatureKeyAlgorithm::Ec(key_algorithm), Signature::Ecdsa { algorithm, fixed })
            if key_algorithm == *algorithm =>
        {
            Ok(fixed.clone())
        }
        (SignatureKeyAlgorithm::RsaPss(key_algorithm), Signature::RsaPss { algorithm, raw })
            if key_algorithm == *algorithm =>
        {
            Ok(raw.clone())
        }
        (
            SignatureKeyAlgorithm::RsaPkcs1v15(key_algorithm),
            Signature::RsaPkcs1v15 { algorithm, raw },
        ) if key_algorithm == *algorithm => Ok(raw.clone()),
        _ => Err(format!(
            "WebCrypto signature algorithm {:?} does not match key algorithm {algorithm:?}",
            signature.algorithm()
        )
        .into()),
    }
}

impl Signature {
    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm, .. } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Self::RsaPkcs1v15 { algorithm, .. } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }
}

fn rsa_pss_import_params(digest: DigestAlgorithm) -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "RSA-PSS")?;
    set_string(&params, "hash", digest_algorithm_name(digest))?;
    Ok(params)
}

fn rsa_pss_verify_params(salt_len: usize) -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "RSA-PSS")?;
    Reflect::set(
        &params,
        &JsValue::from_str("saltLength"),
        &JsValue::from_f64(salt_len as f64),
    )
    .map_err(js_error)?;
    Ok(params)
}

fn rsa_pkcs1v15_params(digest: DigestAlgorithm) -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "RSASSA-PKCS1-v1_5")?;
    set_string(&params, "hash", digest_algorithm_name(digest))?;
    Ok(params)
}

fn ecdsa_import_params(algorithm: EcSignatureKeyAlgorithm) -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "ECDSA")?;
    set_string(&params, "namedCurve", algorithm.name())?;
    Ok(params)
}

fn ecdsa_verify_params(digest: DigestAlgorithm) -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "ECDSA")?;
    set_string(&params, "hash", digest_algorithm_name(digest))?;
    Ok(params)
}

fn digest_algorithm_name(digest: DigestAlgorithm) -> &'static str {
    match digest {
        DigestAlgorithm::Sha256 => "SHA-256",
        DigestAlgorithm::Sha384 => "SHA-384",
        DigestAlgorithm::Sha512 => "SHA-512",
    }
}

fn set_string(target: &Object, key: &str, value: &str) -> Result<()> {
    Reflect::set(target, &JsValue::from_str(key), &JsValue::from_str(value)).map_err(js_error)?;
    Ok(())
}

fn js_error(error: JsValue) -> Box<dyn std::error::Error> {
    format!("WebCrypto error: {:?}", error).into()
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "CryptoKey")]
    type CryptoKey;

    #[wasm_bindgen(typescript_type = "SubtleCrypto")]
    type SubtleCrypto;

    #[wasm_bindgen(method, structural, catch, js_name = importKey)]
    fn import_key_with_object(
        this: &SubtleCrypto,
        format: &str,
        key_data: &Object,
        algorithm: &Object,
        extractable: bool,
        key_usages: &JsValue,
    ) -> std::result::Result<Promise, JsValue>;

    #[wasm_bindgen(method, structural, catch, js_name = verify)]
    fn verify_with_object_and_u8_array_and_u8_array(
        this: &SubtleCrypto,
        algorithm: &Object,
        key: &CryptoKey,
        signature: &[u8],
        data: &[u8],
    ) -> std::result::Result<Promise, JsValue>;

    #[wasm_bindgen(method, structural, catch, js_name = digest)]
    fn digest_with_str_and_u8_array(
        this: &SubtleCrypto,
        algorithm: &str,
        data: &[u8],
    ) -> std::result::Result<Promise, JsValue>;
}
