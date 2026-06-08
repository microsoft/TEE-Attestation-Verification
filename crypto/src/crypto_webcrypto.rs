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

use super::verifier::Async as AsyncVerifier;
use super::x509_certificate::{Certificate as X509Certificate, SignatureAlgorithm};
use super::{AsyncCryptoBackend, AsyncReportSignatureVerifier, CertificateBackend, Result};

pub struct Crypto;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    inner: X509Certificate,
}

impl Certificate {
    fn from_inner(inner: X509Certificate) -> Self {
        Self { inner }
    }
}

impl AsyncVerifier<Certificate> for Certificate {
    async fn verify(&self, subject: &Certificate) -> Result<()> {
        let subtle = subtle_crypto()?;
        let key = import_certificate_signing_key(
            &subtle,
            &self.inner,
            subject.inner.signature_algorithm()?,
        )
        .await?;
        let signature = subject.inner.signature_bytes().to_vec();
        let data = subject.inner.tbs_certificate_der()?;

        verify_signature(
            &subtle,
            &key,
            WebCryptoVerifyAlgorithm::RsaPssSha384,
            &signature,
            &data,
        )
        .await
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

    fn public_key_algorithm(cert: &Self::Certificate) -> Result<String> {
        Ok(cert.inner.public_key_algorithm())
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

    fn issuer_name_matches_subject(
        cert: &Self::Certificate,
        issuer: &Self::Certificate,
    ) -> Result<bool> {
        cert.inner.issuer_name_matches_subject(&issuer.inner)
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        cert.inner.is_valid_at(unix_time)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        Ok(cert.inner.version())
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        cert.inner.extension_criticality(oid)
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        cert.inner.critical_extension_oids()
    }
}

impl AsyncReportSignatureVerifier for Crypto {
    async fn verify_ecdsa_p384_sha384_signature(
        cert: &Self::Certificate,
        signed_bytes: &[u8],
        r: [u8; 72],
        s: [u8; 72],
    ) -> Result<()> {
        let subtle = subtle_crypto()?;
        let key = import_attestation_key(&subtle, &cert.inner).await?;
        let signature = attestation_signature_p1363(r, s)?;

        verify_signature(
            &subtle,
            &key,
            WebCryptoVerifyAlgorithm::EcdsaP384Sha384,
            &signature,
            signed_bytes,
        )
        .await
    }
}

impl AsyncCryptoBackend for Crypto {
    type Certificate = Certificate;

    async fn verify_chain(
        trusted_certs: &[&Self::Certificate],
        untrusted_chain: &[&Self::Certificate],
        leaf: &Self::Certificate,
    ) -> Result<()> {
        let untrusted_chain = untrusted_chain.iter().chain(std::iter::once(&leaf));
        let mut prev: Option<&Certificate> = None;

        for &cert in untrusted_chain {
            if let Some(issuer) = prev {
                issuer.verify(cert).await?;
            } else {
                let mut verified = false;
                for &trusted in trusted_certs {
                    if trusted.verify(cert).await.is_ok() {
                        verified = true;
                        break;
                    }
                }

                if !verified {
                    return Err("Failed to verify certificate: no matching trusted issuer".into());
                }
            }

            prev = Some(cert);
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
enum WebCryptoVerifyAlgorithm {
    RsaPssSha384,
    EcdsaP384Sha384,
}

async fn import_certificate_signing_key(
    subtle: &SubtleCrypto,
    cert: &X509Certificate,
    signature_algorithm: SignatureAlgorithm,
) -> Result<CryptoKey> {
    let spki_der = cert.public_key_spki_der()?;
    let params = match signature_algorithm {
        SignatureAlgorithm::RsaPss => rsa_pss_import_params()?,
    };

    import_spki_key(subtle, &spki_der, &params).await
}

async fn import_attestation_key(
    subtle: &SubtleCrypto,
    cert: &X509Certificate,
) -> Result<CryptoKey> {
    let spki_der = cert.public_key_spki_der()?;
    let params = ecdsa_import_params()?;
    import_spki_key(subtle, &spki_der, &params).await
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

async fn verify_signature(
    subtle: &SubtleCrypto,
    key: &CryptoKey,
    algorithm: WebCryptoVerifyAlgorithm,
    signature: &[u8],
    data: &[u8],
) -> Result<()> {
    let params = match algorithm {
        WebCryptoVerifyAlgorithm::RsaPssSha384 => rsa_pss_verify_params()?,
        WebCryptoVerifyAlgorithm::EcdsaP384Sha384 => ecdsa_verify_params()?,
    };

    let promise = subtle
        .verify_with_object_and_u8_array_and_u8_array(&params, key, signature, data)
        .map_err(js_error)?;
    let verified = JsFuture::from(promise).await.map_err(js_error)?;

    if verified.as_bool() == Some(true) {
        Ok(())
    } else {
        Err("WebCrypto signature verification failed".into())
    }
}

fn attestation_signature_p1363(r: [u8; 72], s: [u8; 72]) -> Result<Vec<u8>> {
    let mut p1363 = Vec::with_capacity(96);

    if r[48..].iter().any(|byte| *byte != 0) {
        return Err(
            "Invalid r scalar padding: upper 24 bytes must be zero for P-384 signatures".into(),
        );
    }
    let mut r_bytes: [u8; 48] = r[..48].try_into().map_err(|_| "Invalid r scalar length")?;
    r_bytes.reverse();

    if s[48..].iter().any(|byte| *byte != 0) {
        return Err(
            "Invalid s scalar padding: upper 24 bytes must be zero for P-384 signatures".into(),
        );
    }
    let mut s_bytes: [u8; 48] = s[..48].try_into().map_err(|_| "Invalid s scalar length")?;
    s_bytes.reverse();

    p1363.extend_from_slice(&r_bytes);
    p1363.extend_from_slice(&s_bytes);
    Ok(p1363)
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

fn rsa_pss_import_params() -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "RSA-PSS")?;
    set_string(&params, "hash", "SHA-384")?;
    Ok(params)
}

fn rsa_pss_verify_params() -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "RSA-PSS")?;
    Reflect::set(
        &params,
        &JsValue::from_str("saltLength"),
        &JsValue::from_f64(48.0),
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

fn ecdsa_verify_params() -> Result<Object> {
    let params = Object::new();
    set_string(&params, "name", "ECDSA")?;
    set_string(&params, "hash", "SHA-384")?;
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
