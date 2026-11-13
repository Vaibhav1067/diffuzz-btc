//! Structural features of a case: what kind of output it spends and which opcodes its scripts
//! contain. Used as cheap "coverage" by the fuzz loop and as part of a bucket's signature.

use diffuzz_types::script::instructions;
use diffuzz_types::tx::Tx;
use diffuzz_types::{Case, hex};

/// A 256-bit set of opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct OpcodeSet(pub [u64; 4]);

impl OpcodeSet {
    /// Add an opcode.
    pub fn insert(&mut self, opcode: u8) {
        self.0[(opcode >> 6) as usize] |= 1 << (opcode & 63);
    }

    /// Membership test.
    pub fn contains(&self, opcode: u8) -> bool {
        self.0[(opcode >> 6) as usize] & (1 << (opcode & 63)) != 0
    }

    /// Number of distinct opcodes.
    pub fn len(&self) -> u32 {
        self.0.iter().map(|w| w.count_ones()).sum()
    }

    /// True if no opcode is present.
    pub fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }

    /// The opcodes in ascending order.
    pub fn opcodes(&self) -> Vec<u8> {
        (0..=255u8).filter(|o| self.contains(*o)).collect()
    }

    /// Compact hex form (32 bytes, most significant word first).
    pub fn to_hex(&self) -> String {
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }

    /// Opcode names joined by spaces (`OP_UNKNOWN_xx` style names for undefined ones).
    pub fn names(&self) -> String {
        self.opcodes()
            .iter()
            .map(|o| match diffuzz_types::script::opcode_name(*o) {
                Some(n) => n.to_string(),
                None => format!("0x{o:02x}"),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// If `script` is a witness program (`OP_n <2..=40 bytes>`), its version and program.
pub fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    let version = match script[0] {
        0x00 => 0,
        v @ 0x51..=0x60 => v - 0x50,
        _ => return None,
    };
    if script[1] as usize + 2 != script.len() {
        return None;
    }
    Some((version, &script[2..]))
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

/// The decoded parts of a case that feature extraction needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parts {
    /// scriptPubKey of the output being spent.
    pub script_pubkey: Vec<u8>,
    /// scriptSig of the input under test.
    pub script_sig: Vec<u8>,
    /// Witness stack of the input under test.
    pub witness: Vec<Vec<u8>>,
    /// The P2SH redeem script, when the output is P2SH and the scriptSig ends in a push.
    pub redeem_script: Option<Vec<u8>>,
    /// The script committed to by the witness program (P2WSH script or tapscript leaf).
    pub witness_script: Option<Vec<u8>>,
    /// Output type, see [`wrapper_type`].
    pub wrapper: &'static str,
}

fn classify_program(
    version: u8,
    program: &[u8],
    witness: &[Vec<u8>],
    nested: bool,
) -> (&'static str, Option<Vec<u8>>) {
    match (version, program.len()) {
        (0, 20) => (if nested { "p2sh-p2wpkh" } else { "p2wpkh" }, None),
        (0, 32) => (
            if nested { "p2sh-p2wsh" } else { "p2wsh" },
            witness.last().cloned(),
        ),
        (0, _) => (
            if nested {
                "p2sh-witness-v0-bad"
            } else {
                "witness-v0-bad"
            },
            None,
        ),
        (1, 32) if !nested => {
            // Strip the annex, then one element is a key-path spend and more is a script path
            // whose leaf script sits before the control block.
            let mut n = witness.len();
            if n >= 2 && witness[n - 1].first() == Some(&0x50) {
                n -= 1;
            }
            match n {
                0 => ("p2tr-empty", None),
                1 => ("p2tr-key", None),
                _ => ("p2tr-script", Some(witness[n - 2].clone())),
            }
        }
        _ => (
            if nested {
                "p2sh-witness-future"
            } else {
                "witness-future"
            },
            None,
        ),
    }
}

/// Decode the parts of a case relevant to feature extraction. Undecodable cases yield
/// `wrapper == "undecodable"`.
pub fn parts(case: &Case) -> Parts {
    let undecodable = Parts {
        wrapper: "undecodable",
        ..Parts::default()
    };
    let idx = case.input_index as usize;
    let Some(spk) = case
        .prevouts
        .get(idx)
        .and_then(|p| hex::decode(&p.script_pubkey_hex))
    else {
        return undecodable;
    };
    let Some(tx) = hex::decode(&case.tx_hex).and_then(|raw| Tx::deserialize(&raw).ok()) else {
        return undecodable;
    };
    let Some(input) = tx.inputs.get(idx) else {
        return undecodable;
    };

    let mut p = Parts {
        script_pubkey: spk.clone(),
        script_sig: input.script_sig.clone(),
        witness: input.witness.clone(),
        redeem_script: None,
        witness_script: None,
        wrapper: "bare",
    };
    if let Some((version, program)) = witness_program(&spk) {
        let (wrapper, ws) = classify_program(version, program, &input.witness, false);
        p.wrapper = wrapper;
        p.witness_script = ws;
    } else if is_p2sh(&spk) {
        p.wrapper = "p2sh";
        let (ins, complete) = instructions(&input.script_sig);
        if complete && let Some(redeem) = ins.last().and_then(|i| i.data) {
            p.redeem_script = Some(redeem.to_vec());
            if let Some((version, program)) = witness_program(redeem) {
                let (wrapper, ws) = classify_program(version, program, &input.witness, true);
                p.wrapper = wrapper;
                p.witness_script = ws;
            }
        }
    }
    p
}

/// The kind of output a case spends: `bare`, `p2sh`, `p2wpkh`, `p2wsh`, `p2sh-p2wpkh`,
/// `p2sh-p2wsh`, `p2tr-key`, `p2tr-script`, `p2tr-empty`, `witness-v0-bad`, `witness-future`,
/// their `p2sh-` nested forms, or `undecodable`.
pub fn wrapper_type(case: &Case) -> &'static str {
    parts(case).wrapper
}

fn add_script(set: &mut OpcodeSet, script: &[u8]) {
    for i in instructions(script).0 {
        // Pushes and small-number opcodes say little about which code runs.
        if i.data.is_none() && !matches!(i.opcode, 0x00 | 0x4f | 0x51..=0x60) {
            set.insert(i.opcode);
        }
    }
}

/// The set of non-push opcodes appearing in any script of the case: scriptSig, scriptPubKey,
/// P2SH redeem script and witness script / tapscript leaf.
pub fn opcode_set(case: &Case) -> OpcodeSet {
    let p = parts(case);
    let mut set = OpcodeSet::default();
    add_script(&mut set, &p.script_sig);
    add_script(&mut set, &p.script_pubkey);
    for s in [&p.redeem_script, &p.witness_script].into_iter().flatten() {
        add_script(&mut set, s);
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::Prevout;
    use diffuzz_types::tx::{TxIn, TxOut};

    fn case(spk: &[u8], script_sig: &[u8], witness: Vec<Vec<u8>>) -> Case {
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                script_sig: script_sig.to_vec(),
                witness,
                ..TxIn::default()
            }],
            outputs: vec![TxOut::default()],
            lock_time: 0,
        };
        Case {
            tx_hex: hex::encode(&tx.serialize()),
            input_index: 0,
            prevouts: vec![Prevout {
                script_pubkey_hex: hex::encode(spk),
                amount_sats: 1,
            }],
            flags: vec![],
            origin: None,
        }
    }

    fn program(version_op: u8, len: usize) -> Vec<u8> {
        let mut s = vec![version_op, len as u8];
        s.extend(std::iter::repeat_n(0xaa, len));
        s
    }

    fn p2sh() -> Vec<u8> {
        let mut s = vec![0xa9, 0x14];
        s.extend([0u8; 20]);
        s.push(0x87);
        s
    }

    #[test]
    fn opcode_set_basics() {
        let mut s = OpcodeSet::default();
        assert!(s.is_empty());
        for o in [0x00u8, 0x3f, 0x40, 0x76, 0xac, 0xff] {
            s.insert(o);
            assert!(s.contains(o));
        }
        assert_eq!(s.len(), 6);
        assert_eq!(s.opcodes(), vec![0x00, 0x3f, 0x40, 0x76, 0xac, 0xff]);
        assert!(!s.contains(0x77));
        assert_eq!(s.to_hex().len(), 64);
        let mut t = OpcodeSet::default();
        t.insert(0x76);
        t.insert(0xac);
        t.insert(0xee);
        assert_eq!(t.names(), "DUP CHECKSIG 0xee");
    }

    #[test]
    fn witness_program_detection() {
        assert_eq!(
            witness_program(&program(0x00, 20)).map(|p| (p.0, p.1.len())),
            Some((0, 20))
        );
        assert_eq!(witness_program(&program(0x51, 32)).map(|p| p.0), Some(1));
        assert_eq!(witness_program(&program(0x60, 2)).map(|p| p.0), Some(16));
        assert!(witness_program(&program(0x00, 1)).is_none(), "too short");
        assert!(witness_program(&program(0x00, 41)).is_none(), "too long");
        assert!(
            witness_program(&[0x4f, 0x02, 1, 2]).is_none(),
            "OP_1NEGATE is not a version"
        );
        assert!(
            witness_program(&[0x00, 0x03, 1, 2]).is_none(),
            "length byte mismatch"
        );
    }

    #[test]
    fn wrapper_types() {
        assert_eq!(wrapper_type(&case(&[0x51], &[], vec![])), "bare");
        assert_eq!(
            wrapper_type(&case(&program(0x00, 20), &[], vec![])),
            "p2wpkh"
        );
        assert_eq!(
            wrapper_type(&case(&program(0x00, 32), &[], vec![vec![0x51]])),
            "p2wsh"
        );
        assert_eq!(
            wrapper_type(&case(&program(0x00, 21), &[], vec![])),
            "witness-v0-bad"
        );
        assert_eq!(
            wrapper_type(&case(&program(0x52, 32), &[], vec![])),
            "witness-future"
        );
        assert_eq!(
            wrapper_type(&case(&program(0x51, 2), &[], vec![])),
            "witness-future"
        );

        let tr = program(0x51, 32);
        assert_eq!(wrapper_type(&case(&tr, &[], vec![])), "p2tr-empty");
        assert_eq!(wrapper_type(&case(&tr, &[], vec![vec![1; 64]])), "p2tr-key");
        assert_eq!(
            wrapper_type(&case(&tr, &[], vec![vec![1; 64], vec![0x50]])),
            "p2tr-key"
        );
        assert_eq!(
            wrapper_type(&case(&tr, &[], vec![vec![0x51], vec![0xc0; 33]])),
            "p2tr-script"
        );

        assert_eq!(wrapper_type(&case(&p2sh(), &[0x01, 0x51], vec![])), "p2sh");
        let mut nested = vec![22u8];
        nested.extend(program(0x00, 20));
        assert_eq!(wrapper_type(&case(&p2sh(), &nested, vec![])), "p2sh-p2wpkh");
        let mut nested = vec![34u8];
        nested.extend(program(0x00, 32));
        assert_eq!(
            wrapper_type(&case(&p2sh(), &nested, vec![vec![0x51]])),
            "p2sh-p2wsh"
        );
        // Unparseable scriptSig: still P2SH, no redeem script.
        assert_eq!(wrapper_type(&case(&p2sh(), &[0x05, 0x01], vec![])), "p2sh");

        let mut bad = case(&[0x51], &[], vec![]);
        bad.tx_hex = "zz".into();
        assert_eq!(wrapper_type(&bad), "undecodable");
        let mut bad = case(&[0x51], &[], vec![]);
        bad.input_index = 9;
        assert_eq!(wrapper_type(&bad), "undecodable");
    }

    #[test]
    fn opcode_sets_include_committed_scripts() {
        // P2WSH with witness script `DUP CHECKSIG`.
        let c = case(&program(0x00, 32), &[], vec![vec![0x01], vec![0x76, 0xac]]);
        assert_eq!(opcode_set(&c).opcodes(), vec![0x76, 0xac]);
        // P2SH: HASH160/EQUAL from the scriptPubKey plus NOP from the redeem script.
        let c = case(&p2sh(), &[0x01, 0x61], vec![]);
        assert_eq!(opcode_set(&c).opcodes(), vec![0x61, 0x87, 0xa9]);
        // Tapscript leaf before the control block, annex ignored.
        let c = case(
            &program(0x51, 32),
            &[],
            vec![vec![0xba, 0x93], vec![0xc0; 33], vec![0x50, 0xac]],
        );
        assert_eq!(opcode_set(&c).opcodes(), vec![0x93, 0xba]);
        // Pushes and small numbers are not counted.
        let c = case(&[0x51, 0x02, 0xac, 0xac, 0x00, 0x4f, 0x75], &[], vec![]);
        assert_eq!(opcode_set(&c).opcodes(), vec![0x75]);
    }
}
