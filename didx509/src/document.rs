// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn write_json_string(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push('"');
    for c in value.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\0'..='\u{1f}' => {
                output.push_str("\\u00");
                output.push(HEX[(c as usize) >> 4] as char);
                output.push(HEX[(c as usize) & 15] as char);
            }
            c => output.push(c),
        }
    }
    output.push('"');
}

fn write_json_member(output: &mut String, name: &str, value: &str) {
    write_json_string(output, name);
    output.push(':');
    write_json_string(output, value);
}

/// Minimal RFC 7518 public JWK. Integer and coordinate strings use base64url.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Jwk {
    Rsa { n: String, e: String },
    Ec { crv: String, x: String, y: String },
}

impl Jwk {
    fn write_json(&self, output: &mut String) {
        output.push('{');
        match self {
            Self::Rsa { n, e } => {
                write_json_member(output, "kty", "RSA");
                output.push(',');
                write_json_member(output, "n", n);
                output.push(',');
                write_json_member(output, "e", e);
            }
            Self::Ec { crv, x, y } => {
                write_json_member(output, "kty", "EC");
                output.push(',');
                write_json_member(output, "crv", crv);
                output.push(',');
                write_json_member(output, "x", x);
                output.push(',');
                write_json_member(output, "y", y);
            }
        }
        output.push('}');
    }

    /// Serialize the public key without optional JWK metadata.
    pub fn to_json(&self) -> String {
        let mut output = String::new();
        self.write_json(&mut output);
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    pub public_key_jwk: Jwk,
}

/// A did:x509 document with one JsonWebKey verification method.
///
/// JSON member order is not a canonicalization contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidDocument {
    pub id: String,
    pub verification_method: VerificationMethod,
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
}

impl DidDocument {
    /// Serialize using the Controlled Identifiers v1 context.
    pub fn to_json(&self) -> String {
        let mut output = String::new();
        output.push('{');
        write_json_member(&mut output, "@context", "https://www.w3.org/ns/cid/v1");
        output.push(',');
        write_json_member(&mut output, "id", &self.id);
        output.push_str(",\"verificationMethod\":[{");
        let method = &self.verification_method;
        write_json_member(&mut output, "id", &method.id);
        output.push(',');
        write_json_member(&mut output, "type", "JsonWebKey");
        output.push(',');
        write_json_member(&mut output, "controller", &method.controller);
        output.push_str(",\"publicKeyJwk\":");
        method.public_key_jwk.write_json(&mut output);
        output.push_str("}]");
        for (name, values) in [
            ("authentication", &self.authentication),
            ("assertionMethod", &self.assertion_method),
            ("keyAgreement", &self.key_agreement),
        ] {
            if values.is_empty() {
                continue;
            }
            output.push(',');
            write_json_string(&mut output, name);
            output.push_str(":[");
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_json_string(&mut output, value);
            }
            output.push(']');
        }
        output.push('}');
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn expected_jwk(key: &Jwk) -> Value {
        match key {
            Jwk::Rsa { n, e } => json!({"kty": "RSA", "n": n, "e": e}),
            Jwk::Ec { crv, x, y } => json!({"kty": "EC", "crv": crv, "x": x, "y": y}),
        }
    }

    #[test]
    fn serialization_preserves_every_unicode_scalar() {
        let value: String = (0..=0x10ffff).filter_map(char::from_u32).collect();
        let key = Jwk::Rsa {
            n: value,
            e: String::new(),
        };
        let actual: Value = serde_json::from_str(&key.to_json()).unwrap();
        assert_eq!(actual, expected_jwk(&key));
    }

    #[test]
    fn serialization_matches_schema_for_all_relationship_combinations() {
        for value in [
            "",
            "\"\\\0\n\r\t\u{08}\u{0c}\u{1f}caf\u{e9}\u{1f600}\u{2028}",
        ] {
            for key in [
                Jwk::Rsa {
                    n: value.into(),
                    e: value.into(),
                },
                Jwk::Ec {
                    crv: value.into(),
                    x: value.into(),
                    y: value.into(),
                },
            ] {
                let actual: Value = serde_json::from_str(&key.to_json()).unwrap();
                assert_eq!(actual, expected_jwk(&key));
                for flags in 0..8 {
                    let relationship = |bit| {
                        if flags & bit != 0 {
                            vec![value.to_owned(), "second".into()]
                        } else {
                            vec![]
                        }
                    };
                    let document = DidDocument {
                        id: value.into(),
                        verification_method: VerificationMethod {
                            id: value.into(),
                            controller: value.into(),
                            public_key_jwk: key.clone(),
                        },
                        authentication: relationship(1),
                        assertion_method: relationship(2),
                        key_agreement: relationship(4),
                    };
                    let mut expected = json!({
                        "@context": "https://www.w3.org/ns/cid/v1",
                        "id": document.id,
                        "verificationMethod": [{
                            "id": document.verification_method.id,
                            "type": "JsonWebKey",
                            "controller": document.verification_method.controller,
                            "publicKeyJwk": expected_jwk(&key),
                        }],
                    });
                    for (name, values) in [
                        ("authentication", &document.authentication),
                        ("assertionMethod", &document.assertion_method),
                        ("keyAgreement", &document.key_agreement),
                    ] {
                        if !values.is_empty() {
                            expected[name] = json!(values);
                        }
                    }
                    let actual: Value = serde_json::from_str(&document.to_json()).unwrap();
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn serialization_escapes_strings_and_omits_unused_relationships() {
        let document = DidDocument {
            id: "did:\"\\\n".into(),
            verification_method: VerificationMethod {
                id: "key".into(),
                controller: "controller".into(),
                public_key_jwk: Jwk::Rsa {
                    n: "AQ".into(),
                    e: "AQAB".into(),
                },
            },
            authentication: vec!["key".into()],
            assertion_method: vec!["key".into()],
            key_agreement: vec![],
        };
        let value: Value = serde_json::from_str(&document.to_json()).unwrap();
        assert_eq!(value["id"], document.id);
        assert_eq!(value["verificationMethod"][0]["publicKeyJwk"]["kty"], "RSA");
        assert_eq!(value["verificationMethod"][0]["type"], "JsonWebKey");
        assert!(value.get("keyAgreement").is_none());
    }
}
