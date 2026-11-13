//! Parser for the human-readable script syntax used in Bitcoin Core's JSON vectors.
//!
//! This is a port of `ParseScript` from Core's `core_read.cpp`. Tokens are separated by
//! whitespace and are one of:
//!
//! * a decimal integer in `[-0xffffffff, 0xffffffff]`, pushed like `CScript << int64`
//!   (`-1` and `1..16` become `OP_1NEGATE` / `OP_1..OP_16`, `0` becomes `OP_0`);
//! * `0x` followed by hex: raw bytes spliced into the script *without* a push opcode;
//! * a single-quoted string: its bytes as a minimally prefixed data push;
//! * an opcode name with or without `OP_` (only `RESERVED` and `NOP..NOP10` have names).

use diffuzz_types::hex;
use diffuzz_types::script::{opcode_from_vector_name, push_data, push_int};

/// Why a script string could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmError {
    /// Integer token outside `[-0xffffffff, 0xffffffff]`.
    NumberOutOfRange(String),
    /// `0x` token with invalid or odd-length hex.
    BadHex(String),
    /// Token is not a number, hex, quoted string or known opcode.
    UnknownToken(String),
}

impl std::fmt::Display for AsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsmError::NumberOutOfRange(t) => write!(f, "number out of range: {t}"),
            AsmError::BadHex(t) => write!(f, "bad hex token: {t}"),
            AsmError::UnknownToken(t) => write!(f, "unknown token: {t}"),
        }
    }
}

impl std::error::Error for AsmError {}

fn is_number(tok: &str) -> bool {
    let digits = tok.strip_prefix('-').unwrap_or(tok);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Assemble a vector-syntax script string into script bytes.
pub fn parse_script(s: &str) -> Result<Vec<u8>, AsmError> {
    let mut out = Vec::new();
    // Core splits on space, tab and newline only.
    for tok in s.split([' ', '\t', '\n']).filter(|t| !t.is_empty()) {
        if is_number(tok) {
            let n: i64 = tok
                .parse()
                .map_err(|_| AsmError::NumberOutOfRange(tok.to_string()))?;
            if !(-0xffff_ffff..=0xffff_ffff).contains(&n) {
                return Err(AsmError::NumberOutOfRange(tok.to_string()));
            }
            push_int(&mut out, n);
        } else if let Some(h) = tok.strip_prefix("0x") {
            let bytes = hex::decode(h).ok_or_else(|| AsmError::BadHex(tok.to_string()))?;
            out.extend_from_slice(&bytes);
        } else if tok.len() >= 2 && tok.starts_with('\'') && tok.ends_with('\'') {
            push_data(&mut out, &tok.as_bytes()[1..tok.len() - 1]);
        } else if let Some(op) = opcode_from_vector_name(tok) {
            out.push(op);
        } else {
            return Err(AsmError::UnknownToken(tok.to_string()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(s: &str) -> String {
        hex::encode(&parse_script(s).unwrap())
    }

    #[test]
    fn numbers() {
        assert_eq!(asm("0"), "00");
        assert_eq!(asm("1"), "51");
        assert_eq!(asm("16"), "60");
        assert_eq!(asm("-1"), "4f");
        assert_eq!(asm("17"), "0111");
        assert_eq!(asm("-2"), "0182");
        assert_eq!(asm("128"), "028000");
        assert_eq!(asm("2147483647"), "04ffffff7f");
        assert_eq!(asm("4294967295"), "05ffffffff00");
        assert_eq!(asm("-4294967295"), "05ffffffff80");
        assert!(matches!(
            parse_script("4294967296"),
            Err(AsmError::NumberOutOfRange(_))
        ));
        assert!(matches!(
            parse_script("99999999999999999999"),
            Err(AsmError::NumberOutOfRange(_))
        ));
    }

    #[test]
    fn raw_hex_is_not_a_push() {
        assert_eq!(asm("0x51"), "51");
        assert_eq!(asm("0x02 0x0100"), "020100");
        assert_eq!(asm("0x4c 0x01 0xff"), "4c01ff");
        assert_eq!(asm("0x"), "");
        assert!(matches!(parse_script("0x5"), Err(AsmError::BadHex(_))));
        assert!(matches!(parse_script("0xzz"), Err(AsmError::BadHex(_))));
    }

    #[test]
    fn strings() {
        assert_eq!(asm("'a'"), "0161");
        assert_eq!(asm("''"), "00");
        assert_eq!(asm("'Az'"), "02417a");
        let long = format!("'{}'", "b".repeat(76));
        assert!(asm(&long).starts_with("4c4c62"));
    }

    #[test]
    fn opcodes_and_whitespace() {
        assert_eq!(asm("DUP HASH160 EQUALVERIFY CHECKSIG"), "76a988ac");
        assert_eq!(asm("OP_DUP  OP_CHECKSIG"), "76ac");
        assert_eq!(asm("1\tNOP\n2"), "516152");
        assert_eq!(asm(""), "");
        assert_eq!(asm("RESERVED CHECKLOCKTIMEVERIFY NOP10"), "50b1b9");
        assert!(matches!(
            parse_script("FOO"),
            Err(AsmError::UnknownToken(_))
        ));
        assert!(matches!(parse_script("-"), Err(AsmError::UnknownToken(_))));
        assert!(matches!(
            parse_script("1NEGATE"),
            Err(AsmError::UnknownToken(_))
        ));
    }

    #[test]
    fn real_vector_lines() {
        // script_tests.json: ["0x4c 0x01 0x07","7 EQUAL","", "OK", "0x4c is OP_PUSHDATA1"]
        assert_eq!(asm("0x4c 0x01 0x07"), "4c0107");
        assert_eq!(asm("7 EQUAL"), "5787");
        // ["'Az'", "0x02 0x417a EQUAL" ...]
        assert_eq!(asm("0x02 0x417a EQUAL"), "02417a87");
        assert_eq!(asm("1 0x01 0xb9 HASH160 EQUAL"), "5101b9a987");
    }
}
