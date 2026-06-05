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
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::x509_certificate::{self, Certificate as X509Certificate};
use super::{
    AsyncCryptoBackend, AsyncKeyBackend, AsyncKeySignatureBackend, CertificateBackend,
    DigestAlgorithm, EcSignatureKeyAlgorithm, Result, RsaPssSignatureKeyAlgorithm,
    SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    inner: X509Certificate,
}

pub struct Key {
    key: CryptoKey,
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
}

impl SignatureBackend for Crypto {
    type Signature = Signature;

    fn signature_from_der(
        signature: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Self::Signature> {
        signature_from_der(signature, algorithm)
    }

    fn signature_from_raw(
        signature: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Self::Signature> {
        signature_from_raw(signature, algorithm)
    }

    fn signature_from_ec_components(
        r: &[u8],
        s: &[u8],
        algorithm: EcSignatureKeyAlgorithm,
    ) -> Result<Self::Signature> {
        signature_from_ec_components(r, s, algorithm)
    }
}

impl AsyncKeyBackend for Crypto {
    type Key = Key;

    async fn key_from_spki_der(
        spki_der: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Self::Key> {
        Key::from_spki_der(spki_der, algorithm).await
    }
}

impl AsyncKeySignatureBackend for Crypto {
    async fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        key.verify(signed_bytes, signature).await
    }
}

impl Crypto {
    pub async fn key_from_spki_der(
        spki_der: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Key> {
        Key::from_spki_der(spki_der, algorithm).await
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
}

impl Key {
    pub async fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let subtle = subtle_crypto()?;
        let params = import_params(algorithm)?;
        let key = import_spki_key(&subtle, spki_der, &params).await?;

        Ok(Key { key, algorithm })
    }

    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.algorithm
    }

    pub async fn verify(&self, signed_bytes: &[u8], signature: &Signature) -> Result<()> {
        let subtle = subtle_crypto()?;
        let params = verify_params(self.algorithm)?;
        let signature = webcrypto_signature_bytes(self.algorithm, signature)?;

        verify_with_subtle(&subtle, &self.key, &params, &signature, signed_bytes).await
    }
}

impl AsyncCryptoBackend for Crypto {
    async fn verify_chain(
        trusted_cert: &Self::Certificate,
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
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
        .await
    }
}

async fn verify_x509_certificate_signature(
    issuer: &X509Certificate,
    subject: &X509Certificate,
) -> Result<()> {
    let spki_der = issuer.public_key_spki_der()?;
    let key =
        <Crypto as AsyncKeyBackend>::key_from_spki_der(&spki_der, subject.signature_algorithm()?)
            .await?;
    let data = subject.tbs_certificate_der()?;
    let signature = <Crypto as SignatureBackend>::signature_from_raw(
        subject.signature_bytes(),
        subject.signature_algorithm()?,
    )?;

    <Crypto as AsyncKeySignatureBackend>::verify_signature(&key, &signature, &data).await
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
        SignatureKeyAlgorithm::RsaPss(algorithm @ RsaPssSignatureKeyAlgorithm::Ps384) => {
            rsa_pss_import_params(algorithm.digest())
        }
        _ => Err(format!("Unsupported WebCrypto signature key algorithm: {algorithm:?}").into()),
    }
}

fn verify_params(algorithm: SignatureKeyAlgorithm) -> Result<Object> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(algorithm) => ecdsa_verify_params(algorithm.digest()),
        SignatureKeyAlgorithm::RsaPss(algorithm @ RsaPssSignatureKeyAlgorithm::Ps384) => {
            rsa_pss_verify_params(algorithm.salt_len())
        }
        _ => Err(format!("Unsupported WebCrypto signature key algorithm: {algorithm:?}").into()),
    }
}

fn signature_from_der(_signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Signature> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(algorithm) => Err(format!(
            "WebCrypto ECDSA {} signatures must be provided as components",
            algorithm.name()
        )
        .into()),
        SignatureKeyAlgorithm::RsaPss(_) => Err("RSA-PSS signatures must be raw bytes".into()),
    }
}

fn signature_from_raw(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Signature> {
    match algorithm {
        SignatureKeyAlgorithm::RsaPss(algorithm @ RsaPssSignatureKeyAlgorithm::Ps384) => {
            Ok(Signature::RsaPss {
                algorithm,
                raw: signature.to_vec(),
            })
        }
        SignatureKeyAlgorithm::RsaPss(algorithm) => {
            Err(format!("Unsupported WebCrypto RSA-PSS signature algorithm: {algorithm:?}").into())
        }
        SignatureKeyAlgorithm::Ec(_) => {
            Err("ECDSA signatures must be provided as components".into())
        }
    }
}

fn signature_from_ec_components(
    r: &[u8],
    s: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Signature> {
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

    let mut fixed = Vec::with_capacity(algorithm.fixed_signature_byte_len());
    fixed.extend_from_slice(r);
    fixed.extend_from_slice(s);
    Ok(Signature::Ecdsa { algorithm, fixed })
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
        (
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384),
            Signature::RsaPss {
                algorithm: RsaPssSignatureKeyAlgorithm::Ps384,
                raw,
            },
        ) => Ok(raw.clone()),
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
}
