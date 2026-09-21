// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native metadata decoding. All ASN.1 decoding and encoding is done by OpenSSL.

use crate::{
    x509::{Attribute, CertificateDetails, PublicKey, SubjectAlternativeName},
    CertificateBackend, Result,
};
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::{
    asn1::{Asn1Object, Asn1ObjectRef, Asn1StringRef, Asn1Time},
    error::ErrorStack,
    rsa::Rsa,
    stack::Stack,
    x509::{GeneralName, X509Name, X509NameRef, X509Ref, X509},
};
use openssl_sys as sys;
use std::{
    collections::HashSet,
    ffi::{c_int, c_long},
    ptr,
};

// Public OpenSSL APIs missing from openssl-sys. Objects returned by get0/get
// accessors remain borrowed; d2i results are immediately wrapped in owning types.
mod ffi {
    use super::*;
    pub enum X509Pubkey {}
    pub const V_ASN1_UNDEF: c_int = -1;
    // Public layout from openssl/x509v3.h; OpenSSL provides no field accessors.
    #[repr(C)]
    pub struct EdiPartyName {
        pub name_assigner: *mut sys::ASN1_STRING,
        pub party_name: *mut sys::ASN1_STRING,
    }
    #[repr(C)]
    pub struct OtherName {
        pub type_id: *mut sys::ASN1_OBJECT,
        pub value: *mut sys::ASN1_TYPE,
    }
    extern "C" {
        pub fn X509_get0_tbs_sigalg(cert: *const sys::X509) -> *const sys::X509_ALGOR;
        pub fn X509_ALGOR_cmp(a: *const sys::X509_ALGOR, b: *const sys::X509_ALGOR) -> c_int;
        pub fn X509_NAME_ENTRY_set(entry: *const sys::X509_NAME_ENTRY) -> c_int;
        pub fn i2d_re_X509_tbs(cert: *mut sys::X509, out: *mut *mut u8) -> c_int;
        pub fn i2d_ASN1_INTEGER(value: *const sys::ASN1_INTEGER, out: *mut *mut u8) -> c_int;
        pub fn i2d_ASN1_OBJECT(value: *const sys::ASN1_OBJECT, out: *mut *mut u8) -> c_int;
        pub fn i2d_ASN1_BIT_STRING(value: *const sys::ASN1_BIT_STRING, out: *mut *mut u8) -> c_int;
        pub fn ASN1_get_object(
            input: *mut *const u8,
            length: *mut c_long,
            tag: *mut c_int,
            class: *mut c_int,
            available: c_long,
        ) -> c_int;
        pub fn X509_get_X509_PUBKEY(cert: *const sys::X509) -> *mut X509Pubkey;
        pub fn X509_get0_pubkey_bitstr(cert: *const sys::X509) -> *mut sys::ASN1_BIT_STRING;
        pub fn X509_PUBKEY_get0_param(
            oid: *mut *mut sys::ASN1_OBJECT,
            bytes: *mut *const u8,
            length: *mut c_int,
            algorithm: *mut *mut sys::X509_ALGOR,
            key: *const X509Pubkey,
        ) -> c_int;
        pub fn d2i_GENERAL_NAMES(
            out: *mut *mut sys::stack_st_GENERAL_NAME,
            input: *mut *const u8,
            length: c_long,
        ) -> *mut sys::stack_st_GENERAL_NAME;
        pub fn i2d_GENERAL_NAMES(
            names: *const sys::stack_st_GENERAL_NAME,
            out: *mut *mut u8,
        ) -> c_int;
        pub fn d2i_EXTENDED_KEY_USAGE(
            out: *mut *mut sys::stack_st_ASN1_OBJECT,
            input: *mut *const u8,
            length: c_long,
        ) -> *mut sys::stack_st_ASN1_OBJECT;
        pub fn i2d_EXTENDED_KEY_USAGE(
            usages: *const sys::stack_st_ASN1_OBJECT,
            out: *mut *mut u8,
        ) -> c_int;
    }
}

pub(super) fn certificate_details(cert: &X509) -> Result<CertificateDetails> {
    validate_structure(cert)?;
    let mut subject: Vec<Vec<Attribute>> = Vec::new();
    let mut previous = None;
    for entry in cert.subject_name().entries() {
        // SAFETY: entry is borrowed from the live certificate.
        let set = unsafe { ffi::X509_NAME_ENTRY_set(entry.as_ptr()) };
        if previous != Some(set) {
            subject.push(Vec::new());
            previous = Some(set);
        }
        subject
            .last_mut()
            .ok_or("Missing subject RDN")?
            .push(Attribute {
                oid: numeric_oid(entry.object())?,
                value: attribute_string(entry.data())?,
            });
    }
    Ok(CertificateDetails {
        subject,
        subject_alt_names: subject_alt_names(cert)?,
        extended_key_usage: extended_key_usage(cert)?,
    })
}

fn validate_structure(cert: &X509Ref) -> Result<()> {
    numeric_oid(cert.signature_algorithm().object())?;
    // SAFETY: both algorithms are borrowed from cert and checked before comparison.
    unsafe {
        let inner = ffi::X509_get0_tbs_sigalg(cert.as_ptr());
        if inner.is_null() {
            return Err("Missing certificate signature algorithm".into());
        }
        if ffi::X509_ALGOR_cmp(inner, cert.signature_algorithm().as_ptr()) != 0 {
            return Err("Certificate signature algorithms disagree".into());
        }
        let spki = ffi::X509_get_X509_PUBKEY(cert.as_ptr());
        let mut oid = ptr::null_mut();
        if spki.is_null()
            || ffi::X509_PUBKEY_get0_param(
                &mut oid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                spki,
            ) != 1
            || oid.is_null()
        {
            return Err("Missing public key algorithm".into());
        }
        numeric_oid(Asn1ObjectRef::from_ptr(oid))?;
        // Match the WebCrypto decoder's 21-content-octet serial limit.
        let serial_length = ffi::i2d_ASN1_INTEGER(cert.serial_number().as_ptr(), ptr::null_mut());
        if serial_length <= 0 {
            return Err(ErrorStack::get().into());
        }
        if serial_length > 23 {
            return Err("Certificate serial number exceeds 21 octets".into());
        }
    }
    if !(0..=2).contains(&cert.version()) {
        return Err("Unsupported certificate version".into());
    }
    for time in [cert.not_before(), cert.not_after()] {
        // SAFETY: ASN1_TIME is an ASN1_STRING, borrowed for the lifetime of time.
        let value = unsafe { Asn1StringRef::from_ptr(time.as_ptr().cast()) };
        // SAFETY: value is live.
        let length = match unsafe { sys::ASN1_STRING_type(value.as_ptr()) } {
            sys::V_ASN1_UTCTIME => 13,
            sys::V_ASN1_GENERALIZEDTIME => 15,
            _ => return Err("Unsupported certificate time encoding".into()),
        };
        let bytes = value.as_slice();
        if bytes.len() != length
            || bytes.last() != Some(&b'Z')
            || !bytes[..length - 1].iter().all(u8::is_ascii_digit)
        {
            return Err("Certificate time is not canonical DER".into());
        }
        let parsed = Asn1Time::from_str_x509(std::str::from_utf8(bytes)?)?;
        if parsed < Asn1Time::from_unix(0)? {
            return Err("Certificate time precedes the supported Unix epoch".into());
        }
    }

    let mut extensions = HashSet::new();
    // SAFETY: cert owns every extension and OID; null pointers are rejected.
    unsafe {
        let count = sys::X509_get_ext_count(cert.as_ptr());
        if count < 0 {
            return Err("OpenSSL returned a negative extension count".into());
        }
        for index in 0..count {
            let extension = sys::X509_get_ext(cert.as_ptr(), index);
            if extension.is_null() {
                return Err("OpenSSL returned a null extension".into());
            }
            let oid = sys::X509_EXTENSION_get_object(extension);
            if oid.is_null() {
                return Err("OpenSSL returned a null extension OID".into());
            }
            if !extensions.insert(numeric_oid(Asn1ObjectRef::from_ptr(oid))?) {
                return Err("Duplicate certificate extension".into());
            }
        }
    }

    let der = cert.to_der()?;
    // X509::clone only increments a reference count. Decode a separate object
    // before invalidating its signed-TBS cache or replacing its cached names.
    let copy = X509::from_der(&der)?;
    let issuer = canonical_name(cert.issuer_name())?;
    let subject = canonical_name(cert.subject_name())?;
    // SAFETY: copy owns an independent X509. The setters copy their arguments.
    unsafe {
        let count = sys::X509_get_ext_count(copy.as_ptr());
        if count < 0 {
            return Err("OpenSSL returned a negative extension count".into());
        }
        for index in 0..count {
            let extension = sys::X509_get_ext(copy.as_ptr(), index);
            if extension.is_null() {
                return Err("OpenSSL returned a null extension".into());
            }
            // OpenSSL preserves noncanonical BOOLEAN bytes until explicitly set.
            let critical = i32::from(sys::X509_EXTENSION_get_critical(extension) != 0);
            if sys::X509_EXTENSION_set_critical(extension, critical) != 1 {
                return Err(ErrorStack::get().into());
            }
        }
        // X509_set_version skips equal values, even an explicitly encoded v1.
        if cert.version() == 0 && sys::X509_set_version(copy.as_ptr(), 1) != 1 {
            return Err(ErrorStack::get().into());
        }
        if sys::X509_set_issuer_name(copy.as_ptr(), issuer.as_ptr()) != 1
            || sys::X509_set_subject_name(copy.as_ptr(), subject.as_ptr()) != 1
            || sys::X509_set_version(copy.as_ptr(), cert.version().into()) != 1
            || ffi::i2d_re_X509_tbs(copy.as_ptr(), ptr::null_mut()) <= 0
        {
            return Err(ErrorStack::get().into());
        }
    }
    if copy.to_der()? != der {
        return Err("Certificate is not canonical DER".into());
    }
    Ok(())
}

fn canonical_name(name: &X509NameRef) -> Result<X509Name> {
    let rebuilt = X509Name::builder()?.build();
    let mut previous = None;
    for entry in name.entries() {
        numeric_oid(entry.object())?;
        // SAFETY: rebuilt is uniquely owned. OpenSSL copies each borrowed entry;
        // set=-1 joins the previous RDN, set=0 starts a new RDN.
        unsafe {
            let set = ffi::X509_NAME_ENTRY_set(entry.as_ptr());
            if set < 0 {
                return Err("OpenSSL returned a negative RDN index".into());
            }
            let same_rdn = previous == Some(set);
            if sys::X509_NAME_add_entry(
                rebuilt.as_ptr(),
                entry.as_ptr(),
                -1,
                if same_rdn { -1 } else { 0 },
            ) != 1
            {
                return Err(ErrorStack::get().into());
            }
            previous = Some(set);
        }
    }
    if rebuilt.to_der()? != name.to_der()? {
        return Err("Noncanonical distinguished name or unsupported empty RDN".into());
    }
    Ok(rebuilt)
}

fn numeric_oid(oid: &Asn1ObjectRef) -> Result<String> {
    // Match the WebCrypto decoder's OID representation bounds.
    // SAFETY: oid is borrowed and the null output requests only the DER length.
    let encoded_length = unsafe { ffi::i2d_ASN1_OBJECT(oid.as_ptr(), ptr::null_mut()) };
    if encoded_length <= 0 {
        return Err(ErrorStack::get().into());
    }
    if encoded_length > 41 {
        return Err("OID exceeds the supported 39 octets".into());
    }
    // SAFETY: oid is borrowed; OBJ_obj2txt supports a null sizing buffer.
    let length = unsafe { sys::OBJ_obj2txt(ptr::null_mut(), 0, oid.as_ptr(), 1) };
    if length <= 0 {
        return Err("OpenSSL could not encode an OID".into());
    }
    let capacity = length.checked_add(1).ok_or("OID is too long")?;
    let mut bytes = vec![0; capacity as usize];
    // SAFETY: bytes has the requested capacity, including the terminating NUL.
    let written = unsafe { sys::OBJ_obj2txt(bytes.as_mut_ptr().cast(), capacity, oid.as_ptr(), 1) };
    if written != length {
        return Err("OpenSSL returned an inconsistent OID length".into());
    }
    bytes.truncate(length as usize);
    let text = String::from_utf8(bytes)?;
    for (index, arc) in text.split('.').enumerate() {
        let value: u32 = arc.parse().map_err(|_| "OID arc exceeds u32")?;
        if (index == 0 && value > 2) || (index == 1 && value > 39) {
            return Err("Unsupported OID root arcs".into());
        }
    }
    Ok(text)
}

fn attribute_string(value: &Asn1StringRef) -> Result<String> {
    let bytes = value.as_slice();
    // SAFETY: value is a live ASN1_STRING.
    match unsafe { sys::ASN1_STRING_type(value.as_ptr()) } {
        sys::V_ASN1_UTF8STRING => Ok(std::str::from_utf8(bytes)?.to_owned()),
        sys::V_ASN1_PRINTABLESTRING
            if bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b)) =>
        {
            Ok(std::str::from_utf8(bytes)?.to_owned())
        }
        sys::V_ASN1_IA5STRING | sys::V_ASN1_T61STRING if bytes.is_ascii() => {
            Ok(std::str::from_utf8(bytes)?.to_owned())
        }
        sys::V_ASN1_BMPSTRING if bytes.len() % 2 == 0 => bytes
            .chunks_exact(2)
            .map(|pair| {
                let point = u16::from_be_bytes([pair[0], pair[1]]);
                char::from_u32(u32::from(point))
                    .filter(|_| point != u16::MAX)
                    .ok_or_else(|| "Invalid BMPString character".into())
            })
            .collect(),
        _ => Err("Unsupported or invalid distinguished-name string encoding".into()),
    }
}

fn encode(mut writer: impl FnMut(*mut *mut u8) -> c_int) -> Result<Vec<u8>> {
    let length = writer(ptr::null_mut());
    if length <= 0 {
        return Err(ErrorStack::get().into());
    }
    let mut bytes = vec![0; length as usize];
    let mut cursor = bytes.as_mut_ptr();
    if writer(&mut cursor) != length || cursor != bytes.as_mut_ptr().wrapping_add(bytes.len()) {
        return Err("OpenSSL returned an inconsistent DER length".into());
    }
    Ok(bytes)
}

fn subject_alt_names(cert: &X509) -> Result<Option<Vec<SubjectAlternativeName>>> {
    let Some(der) = super::Crypto::get_extension_value_by_oid(cert, "2.5.29.17")? else {
        return Ok(None);
    };
    let mut cursor = der.as_ptr();
    // SAFETY: d2i reads within der, allocates a stack, and advances cursor.
    let names = unsafe {
        let raw = ffi::d2i_GENERAL_NAMES(ptr::null_mut(), &mut cursor, der.len().try_into()?);
        if raw.is_null() {
            return Err(ErrorStack::get().into());
        }
        Stack::<GeneralName>::from_ptr(raw)
    };
    if cursor != der.as_ptr().wrapping_add(der.len())
        // SAFETY: names owns the stack; encode supplies a correctly sized buffer.
        || encode(|out| unsafe { ffi::i2d_GENERAL_NAMES(names.as_ptr(), out) })? != der
    {
        return Err("Subject alternative names are not canonical DER".into());
    }
    let mut result = Vec::with_capacity(names.len());
    for name in &names {
        // SAFETY: OpenSSL decoded the GENERAL_NAME tagged union. Its discriminator
        // determines the payload type; every pointer is checked before borrowing.
        let value = unsafe {
            let raw = &*name.as_ptr();
            match raw.type_ {
                sys::GEN_EMAIL | sys::GEN_DNS | sys::GEN_URI => {
                    if raw.d.is_null() {
                        return Err("Missing subject alternative name string".into());
                    }
                    let bytes = Asn1StringRef::from_ptr(raw.d.cast()).as_slice();
                    if !bytes.is_ascii() {
                        return Err("Subject alternative name is not IA5String".into());
                    }
                    let value = std::str::from_utf8(bytes)?.to_owned();
                    match raw.type_ {
                        sys::GEN_EMAIL => SubjectAlternativeName::Email(value),
                        sys::GEN_DNS => SubjectAlternativeName::Dns(value),
                        _ => SubjectAlternativeName::Uri(value),
                    }
                }
                sys::GEN_X400 => return Err("Unsupported x400Address".into()),
                sys::GEN_DIRNAME => {
                    if raw.d.is_null() {
                        return Err("Missing directoryName".into());
                    }
                    canonical_name(X509NameRef::from_ptr(raw.d.cast()))?;
                    SubjectAlternativeName::Other
                }
                sys::GEN_EDIPARTY => {
                    if raw.d.is_null() {
                        return Err("Missing ediPartyName".into());
                    }
                    let party = &*raw.d.cast::<ffi::EdiPartyName>();
                    if party.party_name.is_null() {
                        return Err("Missing EDI party name".into());
                    }
                    for value in [party.name_assigner, party.party_name] {
                        if !value.is_null() {
                            if sys::ASN1_STRING_type(value) == sys::V_ASN1_IA5STRING {
                                return Err("Unsupported EDI DirectoryString encoding".into());
                            }
                            attribute_string(Asn1StringRef::from_ptr(value))?;
                        }
                    }
                    SubjectAlternativeName::Other
                }
                sys::GEN_OTHERNAME => {
                    if raw.d.is_null() {
                        return Err("Missing otherName".into());
                    }
                    let other = &*raw.d.cast::<ffi::OtherName>();
                    if other.type_id.is_null() || other.value.is_null() {
                        return Err("Invalid otherName".into());
                    }
                    numeric_oid(Asn1ObjectRef::from_ptr(other.type_id))?;
                    SubjectAlternativeName::Other
                }
                sys::GEN_RID => {
                    if raw.d.is_null() {
                        return Err("Missing registeredID".into());
                    }
                    numeric_oid(Asn1ObjectRef::from_ptr(raw.d.cast()))?;
                    SubjectAlternativeName::Other
                }
                sys::GEN_IPADD => SubjectAlternativeName::Other,
                _ => return Err("Unsupported subject alternative name".into()),
            }
        };
        result.push(value);
    }
    Ok(Some(result))
}

fn extended_key_usage(cert: &X509) -> Result<Option<Vec<String>>> {
    let Some(der) = super::Crypto::get_extension_value_by_oid(cert, "2.5.29.37")? else {
        return Ok(None);
    };
    let mut cursor = der.as_ptr();
    // SAFETY: d2i reads within der and transfers ownership of its OID stack.
    let usages = unsafe {
        let raw = ffi::d2i_EXTENDED_KEY_USAGE(ptr::null_mut(), &mut cursor, der.len().try_into()?);
        if raw.is_null() {
            return Err(ErrorStack::get().into());
        }
        Stack::<Asn1Object>::from_ptr(raw)
    };
    if cursor != der.as_ptr().wrapping_add(der.len())
        // SAFETY: usages owns the stack; encode supplies a correctly sized buffer.
        || encode(|out| unsafe { ffi::i2d_EXTENDED_KEY_USAGE(usages.as_ptr(), out) })? != der
    {
        return Err("Extended key usage is not canonical DER".into());
    }
    Ok(Some(usages.iter().map(numeric_oid).collect::<Result<_>>()?))
}

/// Extract the key without validating unrelated certificate structure.
pub(super) fn public_key_components(cert: &X509) -> Result<PublicKey> {
    // SAFETY: all get0 pointers remain borrowed from cert. No EVP key decoder or
    // mathematical key check is used for EC coordinate extraction.
    unsafe {
        let spki = ffi::X509_get_X509_PUBKEY(cert.as_ptr());
        let bits = ffi::X509_get0_pubkey_bitstr(cert.as_ptr());
        if spki.is_null() || bits.is_null() {
            return Err("Missing certificate public key".into());
        }
        let encoded_bits = encode(|out| ffi::i2d_ASN1_BIT_STRING(bits, out))?;
        let mut content = encoded_bits.as_ptr();
        let mut length = 0;
        let mut tag = 0;
        let mut class = 0;
        let flags = ffi::ASN1_get_object(
            &mut content,
            &mut length,
            &mut tag,
            &mut class,
            encoded_bits.len().try_into()?,
        );
        if flags != 0
            || tag != sys::V_ASN1_BIT_STRING
            || class != 0
            || length < 1
            || content.wrapping_add(length as usize)
                != encoded_bits.as_ptr().wrapping_add(encoded_bits.len())
        {
            return Err("Invalid public key BIT STRING".into());
        }
        if *content != 0 {
            return Err("Public key has unused bits".into());
        }

        let mut oid = ptr::null_mut();
        let mut bytes = ptr::null();
        let mut length = 0;
        let mut algorithm = ptr::null_mut();
        if ffi::X509_PUBKEY_get0_param(&mut oid, &mut bytes, &mut length, &mut algorithm, spki) != 1
            || oid.is_null()
            || algorithm.is_null()
            || length <= 0
            || bytes.is_null()
        {
            return Err("Invalid certificate public key".into());
        }
        let bytes = std::slice::from_raw_parts(bytes, length as usize);
        let mut parameter_type = 0;
        let mut parameter = ptr::null();
        sys::X509_ALGOR_get0(
            ptr::null_mut(),
            &mut parameter_type,
            &mut parameter,
            algorithm,
        );
        match numeric_oid(Asn1ObjectRef::from_ptr(oid))?.as_str() {
            "1.2.840.113549.1.1.1" => {
                if parameter_type != ffi::V_ASN1_UNDEF && parameter_type != sys::V_ASN1_NULL {
                    return Err("Invalid RSA public key parameters".into());
                }
                let key = Rsa::public_key_from_der_pkcs1(bytes)?;
                // OpenSSL's RSA decoder ignores INTEGER signs. Re-encoding
                // rejects negative and nonminimal encodings before extraction.
                if key.public_key_to_der_pkcs1()? != bytes {
                    return Err("RSA public key is not canonical DER".into());
                }
                if key.n().is_negative()
                    || key.e().is_negative()
                    || key.n().num_bits() == 0
                    || key.e().num_bits() == 0
                {
                    return Err("RSA key components must be positive".into());
                }
                Ok(PublicKey::Rsa {
                    n: key.n().to_vec(),
                    e: key.e().to_vec(),
                })
            }
            "1.2.840.10045.2.1" => {
                if parameter_type != sys::V_ASN1_OBJECT || parameter.is_null() {
                    return Err("EC key requires a named curve".into());
                }
                let curve_oid = numeric_oid(Asn1ObjectRef::from_ptr(parameter.cast_mut().cast()))?;
                let (curve, width) = match curve_oid.as_str() {
                    "1.2.840.10045.3.1.7" => ("P-256", 32),
                    "1.3.132.0.34" => ("P-384", 48),
                    "1.3.132.0.35" => ("P-521", 66),
                    _ => return Err("Unsupported EC curve".into()),
                };
                if bytes.first() != Some(&4) || bytes.len() != 1 + 2 * width {
                    return Err("Expected an uncompressed EC public key".into());
                }
                Ok(PublicKey::Ec {
                    curve,
                    x: bytes[1..1 + width].to_vec(),
                    y: bytes[1 + width..].to_vec(),
                })
            }
            _ => Err("Unsupported public key algorithm".into()),
        }
    }
}
