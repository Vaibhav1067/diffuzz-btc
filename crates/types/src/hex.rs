//! Minimal hex helpers so every crate encodes bytes the same way.

/// Lower-case hex encoding of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string (either case). Returns `None` on odd length or a non-hex character.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(decode("00ABff").unwrap(), vec![0x00, 0xab, 0xff]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("0").is_none());
        assert!(decode("zz").is_none());
        assert!(decode("0x00").is_none());
    }
}
