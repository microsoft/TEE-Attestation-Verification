// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use pkcs1::RsaPublicKey;
use x509_cert::{
    der::{oid::ObjectIdentifier, Decode},
    spki::SubjectPublicKeyInfoRef,
};

use super::{EcSignatureKeyAlgorithm, Result, SignatureKeyAlgorithm};

pub(crate) enum PublicKey<'a> {
    Ec {
        algorithm: EcSignatureKeyAlgorithm,
        point: &'a [u8],
    },
    Rsa {
        modulus: &'a [u8],
        exponent: &'a [u8],
    },
}

pub(crate) fn parse_spki(
    spki_der: &[u8],
    algorithm: SignatureKeyAlgorithm,
) -> Result<PublicKey<'_>> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| format!("Failed to parse public key SPKI: {e:?}"))?;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or("Public key SPKI bit string is not byte-aligned")?;

    match algorithm {
        SignatureKeyAlgorithm::Ec(algorithm) => {
            if spki.algorithm.oid != oid::EC_PUBLIC_KEY {
                return Err(
                    format!("Expected EC public key OID, got {}", spki.algorithm.oid).into(),
                );
            }

            let curve_oid = spki
                .algorithm
                .parameters
                .ok_or("EC public key curve parameters are required")?
                .decode_as::<ObjectIdentifier>()
                .map_err(|e| format!("Failed to parse EC curve OID: {e:?}"))?;
            if curve_oid != ec_curve_oid(algorithm) {
                return Err(format!(
                    "EC public key curve does not match requested {} algorithm",
                    algorithm.name()
                )
                .into());
            }

            let expected_len = 1 + 2 * algorithm.scalar_byte_len();
            if key_bytes.len() != expected_len || key_bytes.first() != Some(&0x04) {
                return Err(format!(
                    "An uncompressed SEC1 {} public key is required",
                    algorithm.name()
                )
                .into());
            }

            Ok(PublicKey::Ec {
                algorithm,
                point: &key_bytes[1..],
            })
        }
        SignatureKeyAlgorithm::RsaPss(_) | SignatureKeyAlgorithm::RsaPkcs1v15(_) => {
            if spki.algorithm.oid != oid::RSA_ENCRYPTION {
                return Err(
                    format!("Expected RSA public key OID, got {}", spki.algorithm.oid).into(),
                );
            }
            if spki
                .algorithm
                .parameters
                .map(|parameters| !parameters.is_null())
                .unwrap_or(false)
            {
                return Err("Unsupported RSA public key parameters".into());
            }

            let rsa = RsaPublicKey::from_der(key_bytes)
                .map_err(|e| format!("Failed to parse PKCS#1 RSA public key: {e:?}"))?;
            Ok(PublicKey::Rsa {
                modulus: rsa.modulus.as_bytes(),
                exponent: rsa.public_exponent.as_bytes(),
            })
        }
    }
}

fn ec_curve_oid(algorithm: EcSignatureKeyAlgorithm) -> ObjectIdentifier {
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => oid::P256,
        EcSignatureKeyAlgorithm::P384 => oid::P384,
        EcSignatureKeyAlgorithm::P521 => oid::P521,
    }
}

mod oid {
    use x509_cert::der::oid::ObjectIdentifier;

    pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    pub const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    pub const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    pub const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
    pub const RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
}
