//! Script building blocks: opcode names, push encoding, script numbers, and a tolerant
//! instruction iterator used for disassembly, mutation and bucketing.

/// Opcode constants used across the workspace.
#[allow(missing_docs)]
pub mod op {
    pub const OP_0: u8 = 0x00;
    pub const PUSHDATA1: u8 = 0x4c;
    pub const PUSHDATA2: u8 = 0x4d;
    pub const PUSHDATA4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const RESERVED: u8 = 0x50;
    pub const OP_1: u8 = 0x51;
    pub const OP_16: u8 = 0x60;
    pub const NOP: u8 = 0x61;
    pub const VER: u8 = 0x62;
    pub const IF: u8 = 0x63;
    pub const NOTIF: u8 = 0x64;
    pub const VERIF: u8 = 0x65;
    pub const VERNOTIF: u8 = 0x66;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const VERIFY: u8 = 0x69;
    pub const RETURN: u8 = 0x6a;
    pub const TOALTSTACK: u8 = 0x6b;
    pub const FROMALTSTACK: u8 = 0x6c;
    pub const DROP2: u8 = 0x6d;
    pub const DUP2: u8 = 0x6e;
    pub const DUP3: u8 = 0x6f;
    pub const OVER2: u8 = 0x70;
    pub const ROT2: u8 = 0x71;
    pub const SWAP2: u8 = 0x72;
    pub const IFDUP: u8 = 0x73;
    pub const DEPTH: u8 = 0x74;
    pub const DROP: u8 = 0x75;
    pub const DUP: u8 = 0x76;
    pub const NIP: u8 = 0x77;
    pub const OVER: u8 = 0x78;
    pub const PICK: u8 = 0x79;
    pub const ROLL: u8 = 0x7a;
    pub const ROT: u8 = 0x7b;
    pub const SWAP: u8 = 0x7c;
    pub const TUCK: u8 = 0x7d;
    pub const CAT: u8 = 0x7e;
    pub const SIZE: u8 = 0x82;
    pub const EQUAL: u8 = 0x87;
    pub const EQUALVERIFY: u8 = 0x88;
    pub const ADD1: u8 = 0x8b;
    pub const SUB1: u8 = 0x8c;
    pub const NEGATE: u8 = 0x8f;
    pub const ABS: u8 = 0x90;
    pub const NOT: u8 = 0x91;
    pub const NOTEQUAL0: u8 = 0x92;
    pub const ADD: u8 = 0x93;
    pub const SUB: u8 = 0x94;
    pub const BOOLAND: u8 = 0x9a;
    pub const BOOLOR: u8 = 0x9b;
    pub const NUMEQUAL: u8 = 0x9c;
    pub const NUMEQUALVERIFY: u8 = 0x9d;
    pub const NUMNOTEQUAL: u8 = 0x9e;
    pub const LESSTHAN: u8 = 0x9f;
    pub const GREATERTHAN: u8 = 0xa0;
    pub const LESSTHANOREQUAL: u8 = 0xa1;
    pub const GREATERTHANOREQUAL: u8 = 0xa2;
    pub const MIN: u8 = 0xa3;
    pub const MAX: u8 = 0xa4;
    pub const WITHIN: u8 = 0xa5;
    pub const RIPEMD160: u8 = 0xa6;
    pub const SHA1: u8 = 0xa7;
    pub const SHA256: u8 = 0xa8;
    pub const HASH160: u8 = 0xa9;
    pub const HASH256: u8 = 0xaa;
    pub const CODESEPARATOR: u8 = 0xab;
    pub const CHECKSIG: u8 = 0xac;
    pub const CHECKSIGVERIFY: u8 = 0xad;
    pub const CHECKMULTISIG: u8 = 0xae;
    pub const CHECKMULTISIGVERIFY: u8 = 0xaf;
    pub const NOP1: u8 = 0xb0;
    pub const CLTV: u8 = 0xb1;
    pub const CSV: u8 = 0xb2;
    pub const NOP4: u8 = 0xb3;
    pub const NOP10: u8 = 0xb9;
    pub const CHECKSIGADD: u8 = 0xba;
}

const NAMES_61: [&str; 90] = [
    "NOP",
    "VER",
    "IF",
    "NOTIF",
    "VERIF",
    "VERNOTIF",
    "ELSE",
    "ENDIF",
    "VERIFY",
    "RETURN",
    "TOALTSTACK",
    "FROMALTSTACK",
    "2DROP",
    "2DUP",
    "3DUP",
    "2OVER",
    "2ROT",
    "2SWAP",
    "IFDUP",
    "DEPTH",
    "DROP",
    "DUP",
    "NIP",
    "OVER",
    "PICK",
    "ROLL",
    "ROT",
    "SWAP",
    "TUCK",
    "CAT",
    "SUBSTR",
    "LEFT",
    "RIGHT",
    "SIZE",
    "INVERT",
    "AND",
    "OR",
    "XOR",
    "EQUAL",
    "EQUALVERIFY",
    "RESERVED1",
    "RESERVED2",
    "1ADD",
    "1SUB",
    "2MUL",
    "2DIV",
    "NEGATE",
    "ABS",
    "NOT",
    "0NOTEQUAL",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "LSHIFT",
    "RSHIFT",
    "BOOLAND",
    "BOOLOR",
    "NUMEQUAL",
    "NUMEQUALVERIFY",
    "NUMNOTEQUAL",
    "LESSTHAN",
    "GREATERTHAN",
    "LESSTHANOREQUAL",
    "GREATERTHANOREQUAL",
    "MIN",
    "MAX",
    "WITHIN",
    "RIPEMD160",
    "SHA1",
    "SHA256",
    "HASH160",
    "HASH256",
    "CODESEPARATOR",
    "CHECKSIG",
    "CHECKSIGVERIFY",
    "CHECKMULTISIG",
    "CHECKMULTISIGVERIFY",
    "NOP1",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "NOP4",
    "NOP5",
    "NOP6",
    "NOP7",
    "NOP8",
    "NOP9",
    "NOP10",
    "CHECKSIGADD",
];

/// Name of a non-push opcode without the `OP_` prefix, following Bitcoin Core's `GetOpName`.
/// Returns `None` for direct pushes (0x01..=0x4b) and undefined opcodes (above 0xba).
pub fn opcode_name(opcode: u8) -> Option<&'static str> {
    match opcode {
        0x00 => Some("0"),
        0x4c => Some("PUSHDATA1"),
        0x4d => Some("PUSHDATA2"),
        0x4e => Some("PUSHDATA4"),
        0x4f => Some("1NEGATE"),
        0x50 => Some("RESERVED"),
        0x51..=0x60 => Some(
            [
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
                "16",
            ][(opcode - 0x51) as usize],
        ),
        0x61..=0xba => Some(NAMES_61[(opcode - 0x61) as usize]),
        _ => None,
    }
}

/// Look up an opcode by name the way Core's test-vector script parser does: only `RESERVED` and
/// opcodes from `NOP` (0x61) to `NOP10` (0xb9) are addressable by name, with or without `OP_`.
pub fn opcode_from_vector_name(name: &str) -> Option<u8> {
    let name = name.strip_prefix("OP_").unwrap_or(name);
    if name == "RESERVED" {
        return Some(op::RESERVED);
    }
    NAMES_61[..=(op::NOP10 - 0x61) as usize]
        .iter()
        .position(|n| *n == name)
        .map(|i| 0x61 + i as u8)
}

/// Minimal little-endian sign-magnitude encoding of a script number (`CScriptNum::serialize`).
pub fn scriptnum_encode(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    let last = out.len() - 1;
    if out[last] & 0x80 != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        out[last] |= 0x80;
    }
    out
}

/// Append a data push using the smallest length prefix (`CScript << vector`). Note that, like
/// Core, this never turns small values into `OP_n`; an empty slice becomes `OP_0`.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < op::PUSHDATA1 as usize {
        script.push(n as u8);
    } else if n <= 0xff {
        script.push(op::PUSHDATA1);
        script.push(n as u8);
    } else if n <= 0xffff {
        script.push(op::PUSHDATA2);
        script.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        script.push(op::PUSHDATA4);
        script.extend_from_slice(&(n as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// Append an integer the way `CScript << int64` does: `OP_1NEGATE`, `OP_0`, `OP_1..OP_16` for
/// small values, otherwise a minimal script-number push.
pub fn push_int(script: &mut Vec<u8>, n: i64) {
    if n == -1 || (1..=16).contains(&n) {
        script.push((n + i64::from(op::OP_1) - 1) as u8);
    } else if n == 0 {
        script.push(op::OP_0);
    } else {
        push_data(script, &scriptnum_encode(n));
    }
}

/// One decoded script element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction<'a> {
    /// Byte offset of the opcode within the script.
    pub offset: usize,
    /// The opcode byte.
    pub opcode: u8,
    /// Pushed data for push opcodes (0x01..=0x4e); `None` otherwise.
    pub data: Option<&'a [u8]>,
}

/// Decode a script into instructions. Returns the instructions decoded so far and `false` as the
/// second element if the script ends inside a push (the remainder is then dropped).
pub fn instructions(script: &[u8]) -> (Vec<Instruction<'_>>, bool) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < script.len() {
        let offset = pos;
        let opcode = script[pos];
        pos += 1;
        let len = match opcode {
            0x01..=0x4b => Some(opcode as usize),
            op::PUSHDATA1 => match script.get(pos) {
                Some(n) => {
                    pos += 1;
                    Some(*n as usize)
                }
                None => return (out, false),
            },
            op::PUSHDATA2 => match script.get(pos..pos + 2) {
                Some(b) => {
                    pos += 2;
                    Some(u16::from_le_bytes([b[0], b[1]]) as usize)
                }
                None => return (out, false),
            },
            op::PUSHDATA4 => match script.get(pos..pos + 4) {
                Some(b) => {
                    pos += 4;
                    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
                }
                None => return (out, false),
            },
            _ => None,
        };
        let data = match len {
            Some(n) => match pos.checked_add(n).and_then(|end| script.get(pos..end)) {
                Some(d) => {
                    pos += n;
                    Some(d)
                }
                None => return (out, false),
            },
            None => None,
        };
        out.push(Instruction {
            offset,
            opcode,
            data,
        });
    }
    (out, true)
}

/// Human-readable disassembly: opcode names, `0x..` for pushed data, `[error]` if truncated.
pub fn disassemble(script: &[u8]) -> String {
    let (ins, complete) = instructions(script);
    let mut parts: Vec<String> = ins
        .iter()
        .map(|i| match i.data {
            Some([]) => "<>".to_string(),
            Some(d) => format!("0x{}", crate::hex::encode(d)),
            None => match opcode_name(i.opcode) {
                Some(n) => n.to_string(),
                None => format!("OP_UNKNOWN_{:02x}", i.opcode),
            },
        })
        .collect();
    if !complete {
        parts.push("[error]".to_string());
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn names() {
        assert_eq!(opcode_name(0x61), Some("NOP"));
        assert_eq!(opcode_name(0xac), Some("CHECKSIG"));
        assert_eq!(opcode_name(0xb1), Some("CHECKLOCKTIMEVERIFY"));
        assert_eq!(opcode_name(0xb9), Some("NOP10"));
        assert_eq!(opcode_name(0xba), Some("CHECKSIGADD"));
        assert_eq!(opcode_name(0xbb), None);
        assert_eq!(opcode_name(0x05), None);
        assert_eq!(opcode_name(0x60), Some("16"));
        assert_eq!(opcode_name(op::HASH160), Some("HASH160"));
        assert_eq!(opcode_name(op::WITHIN), Some("WITHIN"));
        assert_eq!(opcode_name(op::SIZE), Some("SIZE"));
    }

    #[test]
    fn vector_names() {
        assert_eq!(opcode_from_vector_name("NOP"), Some(0x61));
        assert_eq!(opcode_from_vector_name("OP_CHECKSIG"), Some(0xac));
        assert_eq!(opcode_from_vector_name("RESERVED"), Some(0x50));
        assert_eq!(opcode_from_vector_name("NOP10"), Some(0xb9));
        // Not addressable by name in Core's parser.
        assert_eq!(opcode_from_vector_name("CHECKSIGADD"), None);
        assert_eq!(opcode_from_vector_name("1NEGATE"), None);
        assert_eq!(opcode_from_vector_name("PUSHDATA1"), None);
        assert_eq!(opcode_from_vector_name("bogus"), None);
    }

    #[test]
    fn scriptnum() {
        assert_eq!(scriptnum_encode(0), Vec::<u8>::new());
        assert_eq!(scriptnum_encode(1), vec![0x01]);
        assert_eq!(scriptnum_encode(-1), vec![0x81]);
        assert_eq!(scriptnum_encode(127), vec![0x7f]);
        assert_eq!(scriptnum_encode(128), vec![0x80, 0x00]);
        assert_eq!(scriptnum_encode(-128), vec![0x80, 0x80]);
        assert_eq!(scriptnum_encode(255), vec![0xff, 0x00]);
        assert_eq!(scriptnum_encode(256), vec![0x00, 0x01]);
        assert_eq!(scriptnum_encode(0x7fff_ffff), vec![0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(scriptnum_encode(-0x7fff_ffff), vec![0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            scriptnum_encode(0xffff_ffff),
            vec![0xff, 0xff, 0xff, 0xff, 0x00]
        );
    }

    #[test]
    fn pushes() {
        let mut s = Vec::new();
        push_int(&mut s, 0);
        push_int(&mut s, -1);
        push_int(&mut s, 1);
        push_int(&mut s, 16);
        push_int(&mut s, 17);
        push_int(&mut s, -2);
        assert_eq!(hex::encode(&s), "004f51600111 0182".replace(' ', ""));

        let mut s = Vec::new();
        push_data(&mut s, &[]);
        push_data(&mut s, &[1]);
        push_data(&mut s, &[0u8; 75]);
        assert_eq!(&s[..4], &[0x00, 0x01, 0x01, 75]);
        let mut s = Vec::new();
        push_data(&mut s, &[0u8; 76]);
        assert_eq!(&s[..2], &[0x4c, 76]);
        let mut s = Vec::new();
        push_data(&mut s, &[0u8; 256]);
        assert_eq!(&s[..3], &[0x4d, 0x00, 0x01]);
        let mut s = Vec::new();
        push_data(&mut s, &vec![0u8; 65536]);
        assert_eq!(&s[..5], &[0x4e, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn decode_and_disassemble() {
        let s = hex::decode("76a90211228800ac").unwrap();
        let (ins, ok) = instructions(&s);
        assert!(ok);
        assert_eq!(ins.len(), 6);
        assert_eq!(ins[2].data, Some(&[0x11u8, 0x22][..]));
        assert_eq!(ins[3].offset, 5);
        assert_eq!(disassemble(&s), "DUP HASH160 0x1122 EQUALVERIFY 0 CHECKSIG");

        let (ins, ok) = instructions(&[0x51, 0x05, 0x01]);
        assert!(!ok);
        assert_eq!(ins.len(), 1);
        assert_eq!(disassemble(&[0x51, 0x05, 0x01]), "1 [error]");
        assert_eq!(disassemble(&[0x4c, 0x00, 0xff]), "<> OP_UNKNOWN_ff");
        assert!(!instructions(&[0x4c]).1);
        assert!(!instructions(&[0x4d, 0x01]).1);
        assert!(!instructions(&[0x4e, 0xff, 0xff, 0xff, 0xff]).1);
    }
}
