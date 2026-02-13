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
    if s.len() % 2 != 0 {
        return Err("Hex string must have an even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
