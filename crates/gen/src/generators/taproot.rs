//! Taproot cases: key-path spends, script-path commitments (depth, leaf version, control block,
//! annex) and tapscript rules (CHECKSIGADD, OP_SUCCESS, pubkey types, minimal IF, the sigops
//! budget, empty and invalid signatures).

use diffuzz_types::script::{op, push_data, push_int};
use diffuzz_types::{Case, Flag};

use super::Generator;
use crate::keys::test_key;
use crate::rng::Rng;
use crate::spend::{
    CbTamper, Damage, Internal, Item, SchnorrSpec, TapParams, Wrapper, is_single, orphan_single,
    random_flags, skeleton, to_case, wrap, wrap_keypath,
};

/// The cases this generator can produce.
pub const TEMPLATES: [&str; 14] = [
    "keypath",
    "scriptpath-tree",
    "leaf-version",
    "control-block",
    "checksig",
    "checksigadd",
    "pubkey-type",
    "op-success",
    "minimal-if",
    "sigops-budget",
    "checkmultisig-disabled",
    "codeseparator",
    "annex",
    "witness-limits",
];

/// Opcodes that are `OP_SUCCESSx` in tapscript (BIP342).
pub fn is_op_success(opcode: u8) -> bool {
    matches!(opcode, 80 | 98 | 126..=129 | 131..=134 | 137..=138 | 141..=142 | 149..=153 | 187..=254)
}

const SUCCESS_SAMPLES: [u8; 12] = [80, 98, 126, 129, 131, 134, 137, 141, 149, 153, 187, 254];
const HASH_TYPES: [u8; 12] = [0, 0, 0, 1, 2, 3, 0x81, 0x82, 0x83, 0x04, 0x80, 0xff];

fn random_path(rng: &mut Rng, depth: usize) -> Vec<[u8; 32]> {
    (0..depth)
        .map(|_| {
            let mut node = [0u8; 32];
            node.copy_from_slice(&rng.bytes(32));
            node
        })
        .collect()
}

fn random_schnorr(rng: &mut Rng, key: u32) -> SchnorrSpec {
    SchnorrSpec {
        key,
        hash_type: if rng.chance(50) {
            0
        } else {
            *rng.pick(&HASH_TYPES)
        },
        damage: if rng.chance(60) {
            Damage::None
        } else {
            *rng.pick(&Damage::SCHNORR)
        },
        codesep_pos: 0xffff_ffff,
    }
}

/// Taproot and tapscript cases.
#[derive(Debug, Clone, Default)]
pub struct TaprootGen;

impl TaprootGen {
    /// Build the named template. With `valid` set, every random choice that could invalidate
    /// the spend is fixed to its valid value (used to prove success paths are reachable).
    pub fn build(&self, rng: &mut Rng, name: &str, valid: bool, flags: Vec<Flag>) -> Case {
        let mut sk = skeleton(rng);
        let key = 60 + rng.below(8) as u32;
        let mut tap = TapParams::default();
        if rng.chance(50) {
            tap.internal = Internal::Key(70 + rng.below(4) as u32);
        }
        let mut script = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        let sig = |rng: &mut Rng, k: u32| {
            Item::Schnorr(if valid {
                SchnorrSpec::valid(k)
            } else {
                random_schnorr(rng, k)
            })
        };

        match name {
            "keypath" => {
                let spec = if valid {
                    SchnorrSpec::valid(key)
                } else {
                    random_schnorr(rng, key)
                };
                let root = if rng.chance(40) {
                    let mut r = [0u8; 32];
                    r.copy_from_slice(&rng.bytes(32));
                    Some(r)
                } else {
                    None
                };
                let annex = if rng.chance(25) {
                    let mut a = vec![0x50];
                    let len = *rng.pick(&[0usize, 1, 32]);
                    a.extend(rng.bytes(len));
                    Some(a)
                } else {
                    None
                };
                // BIP341 defines no digest for SIGHASH_SINGLE without a matching output.
                let suffix = if is_single(spec.hash_type) && rng.chance(40) {
                    orphan_single(&mut sk, rng);
                    "/single-no-output"
                } else {
                    ""
                };
                wrap_keypath(&mut sk, &spec, root, annex);
                if !valid && rng.chance(10) {
                    // An extra witness element turns this into a (bogus) script-path spend.
                    sk.tx.inputs[sk.index].witness.push(rng.bytes(33));
                }
                return to_case(&sk, flags, format!("gen/taproot/keypath{suffix}"));
            }
            "scriptpath-tree" => {
                // Merkle path length, including the maximum of 128 and one beyond it.
                let depth = if valid {
                    *rng.pick(&[0usize, 1, 2, 7, 127, 128])
                } else {
                    *rng.pick(&[0usize, 1, 2, 7, 127, 128, 129])
                };
                tap.path = random_path(rng, depth);
                script.push(op::OP_1);
            }
            "leaf-version" => {
                // Unknown leaf versions succeed without executing the script at all.
                // 0x50 is special: with an even output key the control block then starts with
                // the annex tag and is taken for an annex, which breaks the spend.
                tap.leaf_version = if valid {
                    *rng.pick(&[0xc0u8, 0xc2, 0xc4, 0x00, 0x02, 0xfe, 0xbe])
                } else {
                    *rng.pick(&[0xc0u8, 0xc2, 0xc4, 0x50, 0x00, 0x02, 0xfe, 0xbe])
                };
                let depth = rng.below(3);
                tap.path = random_path(rng, depth);
                if valid || rng.chance(50) {
                    script.push(op::OP_1);
                } else {
                    // Garbage that would fail under tapscript rules.
                    script = rng
                        .pick(&[vec![op::OP_0], vec![0x4c], vec![op::RETURN], vec![]])
                        .clone();
                }
            }
            "control-block" => {
                let depth = rng.below(3);
                tap.path = random_path(rng, depth);
                tap.tamper = if valid {
                    CbTamper::None
                } else {
                    *rng.pick(&[
                        CbTamper::FlipParity,
                        CbTamper::DropByte,
                        CbTamper::ExtraByte,
                        CbTamper::FlipKeyBit,
                        CbTamper::FlipPathBit,
                    ])
                };
                script.push(op::OP_1);
            }
            "checksig" => {
                push_data(&mut script, &test_key(key).xonly());
                match if valid { 0 } else { rng.below(3) } {
                    0 => script.push(op::CHECKSIG),
                    1 => script.extend_from_slice(&[op::CHECKSIGVERIFY, op::OP_1]),
                    // An empty signature makes CHECKSIG push false without failing.
                    _ => script.extend_from_slice(&[op::CHECKSIG, op::NOT]),
                }
                items.push(sig(rng, key));
            }
            "checksigadd" => {
                // k-of-n: <pk1> CHECKSIG <pk2> CHECKSIGADD ... <k> NUMEQUAL
                let n = if valid { 3 } else { rng.range(1, 5) };
                let keys: Vec<u32> = (0..n as u32).map(|i| 80 + i).collect();
                let signers: Vec<bool> = (0..n)
                    .map(|i| if valid { i != 1 } else { rng.chance(65) })
                    .collect();
                for (i, k) in keys.iter().enumerate() {
                    push_data(&mut script, &test_key(*k).xonly());
                    script.push(if i == 0 {
                        op::CHECKSIG
                    } else {
                        op::CHECKSIGADD
                    });
                }
                let have = signers.iter().filter(|s| **s).count() as i64;
                let want = if valid || rng.chance(75) {
                    have
                } else {
                    have + 1
                };
                push_int(&mut script, want);
                script.push(op::NUMEQUAL);
                // Witness order is the reverse of key order.
                for (i, k) in keys.iter().enumerate().rev() {
                    items.push(if signers[i] {
                        sig(rng, *k)
                    } else {
                        Item::Data(Vec::new())
                    });
                }
            }
            "pubkey-type" => {
                // 32 bytes: BIP340 key. 0 bytes: failure. Any other length: an unknown key
                // type, for which a non-empty signature is accepted without verification.
                let len = if valid {
                    32
                } else {
                    *rng.pick(&[0usize, 1, 31, 32, 33, 64, 65])
                };
                let mut pk = test_key(key).xonly().to_vec();
                pk.resize(len, 0x77);
                if !valid && len == 32 && rng.chance(30) {
                    pk = vec![0xff; 32]; // not a valid x coordinate
                }
                push_data(&mut script, &pk);
                script.push(op::CHECKSIG);
                items.push(if valid || rng.chance(70) {
                    sig(rng, key)
                } else {
                    let len = *rng.pick(&[0usize, 1, 64, 65]);
                    Item::Data(rng.bytes(len))
                });
            }
            "op-success" => {
                // An OP_SUCCESSx anywhere makes the script succeed, provided the script can be
                // decoded up to that point. What follows may be undecodable.
                let prefix: &[u8] = match if valid { 0 } else { rng.below(5) } {
                    0 => &[],
                    1 => &[op::OP_0, op::VERIFY],
                    2 => &[op::RETURN],
                    3 => &[0x4c], // truncated PUSHDATA1 *before* the success opcode
                    _ => &[0x02, 0xaa, 0xbb], // a push that merely contains bytes
                };
                script.extend_from_slice(prefix);
                script.push(*rng.pick(&SUCCESS_SAMPLES));
                match rng.below(4) {
                    0 => {}
                    1 => script.push(op::OP_0),
                    2 => script.extend_from_slice(&[0x4d, 0xff]), // truncated push *after*
                    _ => script.extend(rng.bytes(4)),
                }
            }
            "minimal-if" => {
                // Tapscript makes MINIMALIF consensus: the argument must be empty or 0x01.
                let arg: Vec<u8> = if valid {
                    rng.pick(&[vec![], vec![1]]).clone()
                } else {
                    rng.pick(&[
                        vec![],
                        vec![1],
                        vec![2],
                        vec![0],
                        vec![1, 0],
                        vec![0x80],
                        vec![1, 1],
                    ])
                    .clone()
                };
                let truthy = arg == [1];
                items.push(Item::Data(arg));
                let notif = rng.chance(30);
                script.push(if notif { op::NOTIF } else { op::IF });
                // Whichever branch runs for a valid argument leaves true.
                let (taken, other) = if truthy != notif {
                    (op::OP_1, op::OP_0)
                } else {
                    (op::OP_0, op::OP_1)
                };
                script.extend_from_slice(&[taken, op::ELSE, other, op::ENDIF]);
            }
            "sigops-budget" => {
                // Budget is 50 + witness size; each executed check of a non-empty signature
                // costs 50. Re-checking one signature many times exhausts it.
                let checks = if valid {
                    1
                } else {
                    *rng.pick(&[1usize, 2, 3, 4, 6, 12, 40])
                };
                let padding = if rng.chance(40) {
                    *rng.pick(&[100usize, 400, 520])
                } else {
                    0
                };
                if padding > 0 {
                    items.push(Item::Data(vec![0x55; padding]));
                }
                items.push(Item::Schnorr(SchnorrSpec::valid(key)));
                push_data(&mut script, &test_key(key).xonly());
                for _ in 0..checks {
                    script.extend_from_slice(&[op::DUP2, op::CHECKSIGVERIFY]);
                }
                script.extend_from_slice(&[op::DROP2]);
                if padding > 0 {
                    script.push(op::DROP);
                }
                script.push(op::OP_1);
            }
            "checkmultisig-disabled" => {
                script.push(op::OP_0);
                script.push(op::OP_0);
                push_data(&mut script, &test_key(key).xonly());
                script.push(op::OP_1);
                script.push(*rng.pick(&[op::CHECKMULTISIG, op::CHECKMULTISIGVERIFY]));
                if valid {
                    // There is no valid use of CHECKMULTISIG in tapscript; the valid variant
                    // of this template simply does not execute it.
                    script = vec![op::OP_0, op::IF, op::CHECKMULTISIG, op::ENDIF, op::OP_1];
                }
            }
            "codeseparator" => {
                // The signature commits to the position of the last executed CODESEPARATOR.
                push_data(&mut script, &test_key(key).xonly());
                script.push(op::CODESEPARATOR);
                script.push(op::CHECKSIG);
                let pos = if valid || rng.chance(60) {
                    1
                } else {
                    *rng.pick(&[0u32, 2, 0xffff_ffff])
                };
                let mut spec = if valid {
                    SchnorrSpec::valid(key)
                } else {
                    random_schnorr(rng, key)
                };
                spec.codesep_pos = pos;
                items.push(Item::Schnorr(spec));
            }
            "annex" => {
                // The annex is the last witness element when it starts with 0x50 and at least
                // two elements are present. Signatures commit to it.
                let len = *rng.pick(&[0usize, 1, 100]);
                let mut annex = vec![if valid || rng.chance(80) { 0x50 } else { 0x51 }];
                annex.extend(rng.bytes(len));
                tap.annex = Some(annex);
                push_data(&mut script, &test_key(key).xonly());
                script.push(op::CHECKSIG);
                items.push(sig(rng, key));
            }
            _ => {
                // Initial stack limits: element size 520 and stack depth 1000.
                if rng.chance(50) {
                    let len = if valid {
                        520
                    } else {
                        *rng.pick(&[519usize, 520, 521])
                    };
                    items.push(Item::Data(vec![0x66; len]));
                    script.extend_from_slice(&[op::DROP, op::OP_1]);
                } else {
                    let count = if valid {
                        999
                    } else {
                        *rng.pick(&[999usize, 1000, 1001])
                    };
                    for _ in 0..count {
                        items.push(Item::Data(vec![0x01]));
                    }
                    // Tapscript has no opcode-count limit, so the stack can be cleared.
                    script.extend(std::iter::repeat_n(op::DROP2, count / 2));
                    if count % 2 == 1 {
                        script.push(op::DROP);
                    }
                    script.push(op::OP_1);
                }
            }
        }
        let single = items
            .iter()
            .any(|i| matches!(i, Item::Schnorr(s) if is_single(s.hash_type)));
        let suffix = if single && rng.chance(40) {
            orphan_single(&mut sk, rng);
            "/single-no-output"
        } else {
            ""
        };
        wrap(&mut sk, Wrapper::Tapscript, &script, &items, &tap);
        to_case(&sk, flags, format!("gen/taproot/{name}{suffix}"))
    }

    /// A case of the named template that must verify under every consensus flag.
    pub fn valid_case(&self, rng: &mut Rng, name: &str) -> Case {
        self.build(rng, name, true, Flag::CONSENSUS.to_vec())
    }
}

impl Generator for TaprootGen {
    fn name(&self) -> &'static str {
        "taproot"
    }

    fn generate(&self, rng: &mut Rng) -> Case {
        let name = *rng.pick(&TEMPLATES);
        let valid = rng.chance(15);
        let flags = random_flags(rng);
        self.build(rng, name, valid, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_success_set_matches_bip342() {
        let count = (0u16..=255).filter(|o| is_op_success(*o as u8)).count();
        // 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254
        assert_eq!(count, 1 + 1 + 4 + 4 + 2 + 2 + 5 + 68);
        for o in SUCCESS_SAMPLES {
            assert!(is_op_success(o));
        }
        for o in [op::CHECKSIG, op::CHECKSIGADD, op::NOP, 0x82, 0x87, 0xff] {
            assert!(!is_op_success(o), "{o:#x}");
        }
    }

    #[test]
    fn every_template_builds_deterministically() {
        let g = TaprootGen;
        for name in TEMPLATES {
            for valid in [true, false] {
                let a = g.build(&mut Rng::new(8), name, valid, Flag::CONSENSUS.to_vec());
                let b = g.build(&mut Rng::new(8), name, valid, Flag::CONSENSUS.to_vec());
                assert_eq!(a, b, "{name}");
                let origin = a.origin.as_deref().unwrap_or_default();
                assert!(
                    origin.starts_with(&format!("gen/taproot/{name}")),
                    "{origin}"
                );
                let spk = &a.prevouts[a.input_index as usize].script_pubkey_hex;
                assert!(
                    spk.starts_with("5120") && spk.len() == 68,
                    "{name}: not P2TR"
                );
            }
        }
    }
}
