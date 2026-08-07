// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{EcSignatureKeyAlgorithm, Result};

pub(crate) fn fixed_from_components(
    r: &[u8],
    s: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
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
    Ok(fixed)
}

pub(crate) fn ecdsa_der_to_fixed(
    signature: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
    let mut index = 0;
    if signature.get(index) != Some(&0x30) {
        return Err("ECDSA signature must be a DER SEQUENCE".into());
    }
    index += 1;

    let sequence_len = read_der_len(signature, &mut index)?;
    let sequence_end = index
        .checked_add(sequence_len)
        .ok_or("ECDSA signature DER length overflow")?;
    if sequence_end != signature.len() {
        return Err("ECDSA signature DER SEQUENCE length does not match input".into());
    }

    let r = read_der_integer_fixed(signature, &mut index, sequence_end, "r", algorithm)?;
    let s = read_der_integer_fixed(signature, &mut index, sequence_end, "s", algorithm)?;
    if index != sequence_end {
        return Err("ECDSA signature DER SEQUENCE has trailing data".into());
    }

    let mut fixed = Vec::with_capacity(algorithm.fixed_signature_byte_len());
    fixed.extend_from_slice(&r);
    fixed.extend_from_slice(&s);
    Ok(fixed)
}

fn read_der_len(input: &[u8], index: &mut usize) -> Result<usize> {
    let first = *input
        .get(*index)
        .ok_or("Unexpected end of DER while reading length")?;
    *index += 1;

    if first & 0x80 == 0 {
        return Ok(first as usize);
    }

    let len_len = (first & 0x7f) as usize;
    if len_len == 0 {
        return Err("Indefinite DER lengths are not supported".into());
    }
    if len_len > std::mem::size_of::<usize>() {
        return Err("DER length is too large".into());
    }
    if input.len().saturating_sub(*index) < len_len {
        return Err("Unexpected end of DER while reading long-form length".into());
    }
    if input[*index] == 0 {
        return Err("DER length has a redundant leading zero".into());
    }

    let mut len = 0usize;
    for byte in &input[*index..*index + len_len] {
        len = len
            .checked_mul(256)
            .and_then(|len| len.checked_add(*byte as usize))
            .ok_or("DER length overflow")?;
    }
    *index += len_len;
    if len < 0x80 {
        return Err("DER length uses non-minimal long-form encoding".into());
    }
    Ok(len)
}

fn read_der_integer_fixed(
    input: &[u8],
    index: &mut usize,
    limit: usize,
    name: &str,
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
    if *index >= limit || input.get(*index) != Some(&0x02) {
        return Err(format!("ECDSA signature DER missing INTEGER {name}").into());
    }
    *index += 1;

    let len = read_der_len(input, index)?;
    let end = index
        .checked_add(len)
        .ok_or("ECDSA signature DER INTEGER length overflow")?;
    if len == 0 || end > limit {
        return Err(format!("Invalid ECDSA signature DER INTEGER {name} length").into());
    }

    let mut component = &input[*index..end];
    *index = end;

    if component[0] & 0x80 != 0 {
        return Err(format!("ECDSA signature DER INTEGER {name} is negative").into());
    }
    if component.len() > 1 && component[0] == 0 {
        if component[1] & 0x80 == 0 {
            return Err(
                format!("ECDSA signature DER INTEGER {name} has redundant sign padding").into(),
            );
        }
        component = &component[1..];
    }

    let expected_len = algorithm.scalar_byte_len();
    if component.len() > expected_len {
        return Err(format!(
            "Invalid ECDSA {} {name} component length: expected <= {}, got {}",
            algorithm.name(),
            expected_len,
            component.len()
        )
        .into());
    }

    let mut fixed = vec![0; expected_len];
    fixed[expected_len - component.len()..].copy_from_slice(component);
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_fixed_width_components() {
        let r = [1; 32];
        let s = [2; 32];

        let fixed = fixed_from_components(&r, &s, EcSignatureKeyAlgorithm::P256).unwrap();
        assert_eq!(&fixed[..32], &r);
        assert_eq!(&fixed[32..], &s);
    }

    #[test]
    fn rejects_wrong_component_lengths() {
        assert!(fixed_from_components(&[1; 31], &[2; 32], EcSignatureKeyAlgorithm::P256).is_err());
    }

    #[test]
    fn converts_short_scalars_and_required_sign_padding() {
        let signature = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80];

        let fixed = ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P256).unwrap();
        assert_eq!(fixed.len(), 64);
        assert_eq!(fixed[31], 1);
        assert_eq!(fixed[63], 0x80);
        assert!(fixed[..31].iter().all(|byte| *byte == 0));
        assert!(fixed[32..63].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn accepts_canonical_long_form_length() {
        let mut signature = vec![0x30, 0x81, 0x88, 0x02, 66];
        signature.extend_from_slice(&[1; 66]);
        signature.extend_from_slice(&[0x02, 66]);
        signature.extend_from_slice(&[1; 66]);

        let fixed = ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P521).unwrap();
        assert_eq!(fixed, vec![1; 132]);
    }

    #[test]
    fn rejects_malformed_structure() {
        for signature in [
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01][..],
            &[0x30, 0x80][..],
            &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01][..],
            &[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01][..],
            &[0x30, 0x03, 0x02, 0x01, 0x01][..],
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00][..],
        ] {
            assert!(ecdsa_der_to_fixed(signature, EcSignatureKeyAlgorithm::P256).is_err());
        }
    }

    #[test]
    fn rejects_redundant_integer_sign_padding() {
        let signature = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];

        assert!(ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P256).is_err());
    }

    #[test]
    fn rejects_non_minimal_long_form_length() {
        let signature = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

        assert!(ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P256).is_err());
    }

    #[test]
    fn rejects_long_form_length_with_leading_zero() {
        let mut signature = vec![0x30, 0x82, 0x00, 0x80, 0x02, 61];
        signature.extend_from_slice(&[1; 61]);
        signature.extend_from_slice(&[0x02, 63]);
        signature.extend_from_slice(&[1; 63]);

        assert!(ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P521).is_err());
    }
}
