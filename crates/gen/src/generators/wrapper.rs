//! Output-type edge cases: P2SH rules, witness program shapes and lengths, witness/scriptSig
//! malleation, size limits of redeem and witness scripts.

use diffuzz_types::script::{op, push_data};
use diffuzz_types::{Case, Flag};

use super::Generator;
use crate::rng::Rng;
use crate::spend::{p2sh_script, p2wsh_script, random_flags, sha256, skeleton, to_case};

/// The cases this generator can produce.
pub const TEMPLATES: [&str; 16] = [
    "witness-program-shape",
    "p2wsh-ok",
    "p2wsh-mismatch",
    "p2wsh-empty-witness",
    "p2wpkh-bad-witness-count",
    "witness-malleated",
    "p2sh-witness-malleated",
    "witness-unexpected",
    "p2sh-ok",
    "p2sh-mismatch",
    "p2sh-not-push-only",
    "p2sh-redeem-size",
    "p2sh-in-p2sh",
    "p2wsh-script-size",
    "p2wsh-item-size",
    "p2wsh-stack-count",
];

/// A script of exactly `len` bytes that leaves a single true element (`len >= 1`).
fn true_script_of_len(len: usize) -> Vec<u8> {
    // `<push n> DROP` units followed by OP_1; NOPs absorb any remainder.
    let mut s = Vec::with_capacity(len);
    let body = len.saturating_sub(1);
    while s.len() < body {
        let left = body - s.len();
        if left >= 5 {
            let n = (left - 4).min(520);
            if n >= 256 {
                s.push(op::PUSHDATA2);
                s.extend_from_slice(&(n as u16).to_le_bytes());
                s.extend(std::iter::repeat_n(0x11, n));
                s.push(op::DROP);
                continue;
            }
        }
        if left >= 2 {
            let n = (left - 2).min(75);
            s.push(n as u8);
            s.extend(std::iter::repeat_n(0x11, n));
            s.push(op::DROP);
        } else {
            s.push(op::NOP);
        }
    }
    s.push(op::OP_1);
    s
}

fn witness_program(version: u8, program: &[u8]) -> Vec<u8> {
    let mut s = vec![if version == 0 { 0x00 } else { 0x50 + version }];
    push_data(&mut s, program);
    s
}

/// Output-type edge cases.
#[derive(Debug, Clone, Default)]
pub struct WrapperGen;

impl WrapperGen {
    /// Build the named template (see [`TEMPLATES`]).
    pub fn build(&self, rng: &mut Rng, name: &str, flags: Vec<Flag>) -> Case {
        let mut sk = skeleton(rng);
        let idx = sk.index;
        let mut spk: Vec<u8>;
        let mut script_sig: Vec<u8> = Vec::new();
        let mut witness: Vec<Vec<u8>> = Vec::new();
        let ok_script = vec![op::OP_1];

        match name {
            "witness-program-shape" => {
                // Any version, any program length, any witness. Version 0 demands 20 or 32
                // bytes; version 1 with 32 bytes is taproot; the rest are anyone-can-spend.
                // Lengths outside 2..=40 are not witness programs at all.
                let version = *rng.pick(&[0u8, 0, 1, 1, 2, 15, 16]);
                let len = *rng.pick(&[1usize, 2, 3, 19, 20, 21, 31, 32, 33, 40, 41]);
                let program = if len == 2 && rng.chance(50) {
                    vec![0x4e, 0x73] // pay-to-anchor
                } else {
                    rng.bytes(len)
                };
                spk = witness_program(version, &program);
                for _ in 0..rng.weighted(&[40, 30, 20, 10]) {
                    let n = *rng.pick(&[0usize, 1, 32, 64, 65]);
                    witness.push(rng.bytes(n));
                }
                if rng.chance(30) {
                    // The same program, nested in P2SH.
                    push_data(&mut script_sig, &spk);
                    spk = p2sh_script(&spk);
                }
            }
            "p2wsh-ok" => {
                spk = p2wsh_script(&ok_script);
                witness = vec![ok_script];
            }
            "p2wsh-mismatch" => {
                spk = p2wsh_script(&ok_script);
                witness = vec![vec![op::OP_1, op::NOP]];
            }
            "p2wsh-empty-witness" => {
                spk = p2wsh_script(&ok_script);
            }
            "p2wpkh-bad-witness-count" => {
                spk = vec![0x00, 0x14];
                spk.extend_from_slice(&rng.bytes(20));
                for _ in 0..*rng.pick(&[0usize, 1, 3]) {
                    witness.push(rng.bytes(33));
                }
            }
            "witness-malleated" => {
                // Native witness spend with a non-empty scriptSig.
                spk = p2wsh_script(&ok_script);
                witness = vec![ok_script];
                script_sig = rng
                    .pick(&[vec![op::OP_0], vec![op::OP_1], vec![op::NOP]])
                    .clone();
            }
            "p2sh-witness-malleated" => {
                // Nested witness spend whose scriptSig is not exactly one push of the program.
                let program = p2wsh_script(&ok_script);
                spk = p2sh_script(&program);
                witness = vec![ok_script];
                match rng.below(3) {
                    0 => {
                        script_sig.push(op::OP_0);
                        push_data(&mut script_sig, &program);
                    }
                    1 => {
                        // Non-minimal push of the redeem script.
                        script_sig.push(op::PUSHDATA1);
                        script_sig.push(program.len() as u8);
                        script_sig.extend_from_slice(&program);
                    }
                    _ => {
                        push_data(&mut script_sig, &program);
                        push_data(&mut script_sig, &program);
                    }
                }
            }
            "witness-unexpected" => {
                // A non-witness output spent with witness data present.
                spk = rng
                    .pick(&[ok_script.clone(), p2sh_script(&ok_script)])
                    .clone();
                if spk.len() == 23 {
                    push_data(&mut script_sig, &ok_script);
                }
                witness = vec![rng.bytes(1)];
            }
            "p2sh-ok" => {
                spk = p2sh_script(&ok_script);
                push_data(&mut script_sig, &ok_script);
            }
            "p2sh-mismatch" => {
                spk = p2sh_script(&ok_script);
                push_data(&mut script_sig, &[op::OP_1, op::NOP]);
            }
            "p2sh-not-push-only" => {
                // BIP16 requires a push-only scriptSig.
                spk = p2sh_script(&ok_script);
                script_sig.push(*rng.pick(&[op::NOP, op::OP_1, op::DUP, op::CODESEPARATOR]));
                if script_sig[0] == op::OP_1 {
                    script_sig.push(op::DROP);
                }
                push_data(&mut script_sig, &ok_script);
            }
            "p2sh-redeem-size" => {
                // A redeem script must fit in one 520-byte push.
                let len = *rng.pick(&[519usize, 520, 521, 600]);
                let redeem = true_script_of_len(len);
                spk = p2sh_script(&redeem);
                push_data(&mut script_sig, &redeem);
            }
            "p2sh-in-p2sh" => {
                // P2SH is not recursive: the inner P2SH script is evaluated as a plain script.
                let inner = if rng.chance(50) {
                    ok_script.clone()
                } else {
                    vec![op::OP_0]
                };
                let redeem = p2sh_script(&inner);
                spk = p2sh_script(&redeem);
                push_data(&mut script_sig, &inner);
                push_data(&mut script_sig, &redeem);
            }
            "p2wsh-script-size" => {
                let len = *rng.pick(&[9_999usize, 10_000, 10_001]);
                let ws = true_script_of_len(len);
                spk = p2wsh_script(&ws);
                witness = vec![ws];
            }
            "p2wsh-item-size" => {
                let len = *rng.pick(&[519usize, 520, 521]);
                let ws = vec![op::DROP, op::OP_1];
                spk = p2wsh_script(&ws);
                witness = vec![vec![0x22; len], ws];
            }
            _ => {
                // Witness stack depth around the 1000-element limit.
                let count = *rng.pick(&[998usize, 999, 1000, 1001]);
                let ws = vec![op::DEPTH, op::DROP, op::OP_1];
                let mut spk_hash = vec![0x00, 0x20];
                spk_hash.extend_from_slice(&sha256(&ws));
                spk = spk_hash;
                witness = vec![vec![0x01]; count];
                witness.push(ws);
            }
        }

        sk.prevouts[idx].0 = spk;
        sk.tx.inputs[idx].script_sig = script_sig;
        sk.tx.inputs[idx].witness = witness;
        to_case(&sk, flags, format!("gen/wrapper/{name}"))
    }
}

impl Generator for WrapperGen {
    fn name(&self) -> &'static str {
        "wrapper"
    }

    fn generate(&self, rng: &mut Rng) -> Case {
        let name = if rng.chance(35) {
            TEMPLATES[0]
        } else {
            *rng.pick(&TEMPLATES)
        };
        let flags = random_flags(rng);
        self.build(rng, name, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::script::instructions;

    #[test]
    fn true_script_sizes_are_exact() {
        for len in [
            1usize, 2, 3, 6, 77, 78, 260, 261, 519, 520, 521, 600, 9_999, 10_000, 10_001,
        ] {
            let s = true_script_of_len(len);
            assert_eq!(s.len(), len, "len {len}");
            assert_eq!(*s.last().unwrap(), op::OP_1);
            let (ins, complete) = instructions(&s);
            assert!(complete, "len {len} must parse");
            let non_push = ins.iter().filter(|i| i.opcode > 0x60).count();
            assert!(non_push <= 201, "len {len} uses {non_push} ops");
        }
    }

    #[test]
    fn witness_program_encoding() {
        assert_eq!(witness_program(0, &[0xaa; 20])[..2], [0x00, 0x14]);
        assert_eq!(witness_program(1, &[0xaa; 32])[..2], [0x51, 0x20]);
        assert_eq!(
            witness_program(16, &[0xaa, 0xbb]),
            vec![0x60, 0x02, 0xaa, 0xbb]
        );
    }

    #[test]
    fn every_template_builds_deterministically() {
        let g = WrapperGen;
        for name in TEMPLATES {
            let a = g.build(&mut Rng::new(3), name, Flag::CONSENSUS.to_vec());
            let b = g.build(&mut Rng::new(3), name, Flag::CONSENSUS.to_vec());
            assert_eq!(a, b);
            assert_eq!(
                a.origin.as_deref(),
                Some(format!("gen/wrapper/{name}").as_str())
            );
        }
    }
}
