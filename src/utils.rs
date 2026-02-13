fn b16_to_hex(b16: u8) -> char {
    const ASCI_0: u8 = b'0';
    const ASCI_A: u8 = b'a';
    match b16 {
        0..=9 => (b16 + ASCI_0) as char,
        10..=15 => (b16 - 10 + ASCI_A) as char,
        _ => panic!("Invalid hex digit: {}", b16),
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut res = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        res.push(b16_to_hex(byte >> 4));
        res.push(b16_to_hex(byte & 0x0F));
    }
    res
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() {
        return Err("Hex string must contain only ASCII characters".to_string());
    }
    if s.len() % 2 != 0 {
        return Err("Hex string must have an even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_single_byte() {
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0xff]), "ff");
        assert_eq!(to_hex(&[0xab]), "ab");
    }

    #[test]
    fn to_hex_multiple_bytes() {
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn from_hex_empty() {
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn from_hex_valid() {
        assert_eq!(from_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(from_hex("00ff").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn from_hex_uppercase() {
        assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_hex_odd_length_errors() {
        from_hex("abc").unwrap_err();
    }

    #[test]
    fn from_hex_invalid_chars_errors() {
        from_hex("zz").unwrap_err();
    }

    #[test]
    fn from_hex_multibyte_utf8_errors() {
        // Multi-byte UTF-8 characters must not be accepted
        from_hex("café").unwrap_err();
        from_hex("🦀").unwrap_err();
        from_hex("0ö").unwrap_err();
    }

    #[test]
    fn roundtrip() {
        let data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(from_hex(&to_hex(&data)).unwrap(), data);
    }

    #[test]
    #[should_panic(expected = "Invalid hex digit")]
    fn b16_to_hex_panics_on_invalid() {
        b16_to_hex(16);
    }
}
