// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WASM WebCrypto-backed cryptographic backend.
//!
//! This backend uses the host runtime's `globalThis.crypto.subtle` API for
//! asynchronous certificate-chain and SEV-SNP attestation report signature
//! verification. Certificate parsing, encoding, and extension inspection use
//! the shared pure-Rust X.509 parser. The runtime must provide WebCrypto with
//! RSA-PSS/SHA-384 and ECDSA P-384/SHA-384 verification support.

use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::signature as signature_types;
use super::x509_certificate::{self, Certificate as X509Certificate};
use super::{
    AsyncCryptoBackend, AsyncSignatureBackend, CertificateBackend, EcSignatureKeyAlgorithm, Result,
    RsaPssSignatureKeyAlgorithm, Signature, SignatureEncoding, SignatureKeyAlgorithm,
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

impl AsyncSignatureBackend for Crypto {
    type Key = Key;
    type Signature<'a> = signature_types::Signature<'a>;

    async fn key_from_spki_der(
        spki_der: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> Result<Self::Key> {
        Key::from_spki_der(spki_der, algorithm).await
    }

    async fn verify_signature(
        key: &Self::Key,
        signed_bytes: &[u8],
        signature: &Self::Signature<'_>,
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

    pub async fn verify(&self, signed_bytes: &[u8], signature: &Signature<'_>) -> Result<()> {
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
    let key = <Crypto as AsyncSignatureBackend>::key_from_spki_der(
        &spki_der,
        subject.signature_algorithm()?,
    )
    .await?;
    let data = subject.tbs_certificate_der()?;
    let signature = Signature::raw(subject.signature_bytes());

    <Crypto as AsyncSignatureBackend>::verify_signature(&key, &data, &signature).await
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
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => ecdsa_import_params(),
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
            rsa_pss_import_params("SHA-384")
        }
        _ => Err(format!("Unsupported WebCrypto signature key algorithm: {algorithm:?}").into()),
    }
}

fn verify_params(algorithm: SignatureKeyAlgorithm) -> Result<Object> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => ecdsa_verify_params("SHA-384"),
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
            rsa_pss_verify_params(RsaPssSignatureKeyAlgorithm::Ps384.salt_len())
        }
        _ => Err(format!("Unsupported WebCrypto signature key algorithm: {algorithm:?}").into()),
    }
}

fn webcrypto_signature_bytes(
    algorithm: SignatureKeyAlgorithm,
    signature: &Signature<'_>,
) -> Result<Vec<u8>> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => {
            if signature.encoding() != SignatureEncoding::EcdsaFixed {
                return Err(
                    "WebCrypto ECDSA verification requires fixed-width signature encoding".into(),
                );
            }

            Ok(signature.ecdsa_p384_fixed_bytes()?.to_vec())
        }
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => {
            if signature.encoding() != SignatureEncoding::Raw {
                return Err("RSA-PSS verification requires raw signature encoding".into());
            }

            Ok(signature.bytes().to_vec())
        }
        _ => Err(format!("Unsupported WebCrypto signature key algorithm: {algorithm:?}").into()),
    }
}

fn rsa_pss_import_params(hash: &str) -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "RSA-PSS")?;
    set_string(&params, "hash", hash)?;
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

fn ecdsa_import_params() -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "ECDSA")?;
    set_string(&params, "namedCurve", "P-384")?;
    Ok(params)
}

fn ecdsa_verify_params(hash: &str) -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "ECDSA")?;
    set_string(&params, "hash", hash)?;
    Ok(params)
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
