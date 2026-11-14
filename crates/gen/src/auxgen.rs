//! Seeded generator for the secondary surface: `txinfo` decodes and `sighash` requests
//! (legacy, BIP143, BIP341 key path and script path, with and without annex).
//!
//! Like the case generators, operation `n` of seed `s` depends only on `(s, n)`.

use diffuzz_types::auxop::{AuxOp, SighashKind};
use diffuzz_types::taproot::tapleaf_hash;
use diffuzz_types::tx::{Tx, TxIn, TxOut};
use diffuzz_types::{Prevout, hex};

use crate::rng::Rng;

/// Hash types worth hitting often: the defined ones plus classic edge values.
const ECDSA_HASH_TYPES: [u32; 10] = [1, 2, 3, 0x81, 0x82, 0x83, 0, 4, 0x41, 0xffff_ff01];
const TAPROOT_HASH_TYPES: [u32; 9] = [0, 1, 2, 3, 0x81, 0x82, 0x83, 4, 0x80];

/// Short random script: a mix of opcodes, pushes and `OP_CODESEPARATOR`s, sometimes ending
/// in a truncated push.
fn script(rng: &mut Rng) -> Vec<u8> {
    let mut s = Vec::new();
    for _ in 0..rng.below(12) {
        match rng.below(6) {
            0 => s.push(0xab),
            1 => {
                let n = rng.range(1, 40);
                s.push(n as u8);
                s.extend(rng.bytes(n));
            }
            2 => {
                let n = rng.below(80);
                s.extend([0x4c, n as u8]);
                s.extend(rng.bytes(n));
            }
            3 => s.push(*rng.pick(&[0x76, 0xa9, 0x87, 0x88, 0xac, 0xad, 0xba, 0x51, 0x00])),
            _ => s.push(rng.byte()),
        }
    }
    if rng.chance(5) {
        s.extend([0x4d, 0xff]); // truncated PUSHDATA2
    }
    s
}

fn value(rng: &mut Rng) -> u64 {
    match rng.below(5) {
        0 => 0,
        1 => 21_000_000 * 100_000_000,
        2 => rng.next_u64() >> 1,
        _ => rng.next_u64() % 10_000_000_000,
    }
}

fn tx(rng: &mut Rng, inputs: usize) -> Tx {
    let mut t = Tx {
        version: *rng.pick(&[1, 2, 3, 0xffff_ffff]),
        lock_time: if rng.chance(50) {
            0
        } else {
            rng.next_u64() as u32
        },
        ..Tx::default()
    };
    let witness = rng.chance(40);
    for _ in 0..inputs {
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(&rng.bytes(32));
        t.inputs.push(TxIn {
            prev_txid,
            prev_vout: if rng.chance(80) {
                rng.below(4) as u32
            } else {
                u32::MAX
            },
            script_sig: if rng.chance(50) { vec![] } else { script(rng) },
            sequence: *rng.pick(&[0, 0xffff_fffe, 0xffff_ffff, 0x0040_0001]),
            witness: if witness {
                (0..rng.below(4))
                    .map(|_| {
                        let n = rng.below(80);
                        rng.bytes(n)
                    })
                    .collect()
            } else {
                vec![]
            },
        });
    }
    // Zero outputs on purpose sometimes: SIGHASH_SINGLE without a matching output.
    for _ in 0..rng.below(4) {
        t.outputs.push(TxOut {
            value: value(rng),
            script_pubkey: script(rng),
        });
    }
    t
}

/// Mutate a serialized transaction at the byte level (flip, insert, delete, truncate,
/// segwit-marker games).
fn mutate_bytes(rng: &mut Rng, raw: &mut Vec<u8>) {
    for _ in 0..rng.range(1, 4) {
        if raw.is_empty() {
            raw.push(rng.byte());
            continue;
        }
        let i = rng.below(raw.len());
        match rng.below(6) {
            0 => raw[i] ^= 1 << rng.below(8),
            1 => raw[i] = rng.byte(),
            2 => raw.insert(i, rng.byte()),
            3 => {
                raw.remove(i);
            }
            4 => raw.truncate(i),
            _ => {
                // Insert or damage the segwit marker/flag after the version.
                if raw.len() > 5 {
                    if rng.chance(50) {
                        raw.splice(4..4, [0x00, *rng.pick(&[0x01, 0x00, 0x02])]);
                    } else {
                        raw[4] = 0x00;
                    }
                }
            }
        }
    }
}

/// Operation number `n` of stream `seed`. `seed_txs` (hex) are corpus transactions used as
/// mutation donors for `txinfo`; may be empty.
pub fn aux_op(seed: u64, n: u64, seed_txs: &[String]) -> AuxOp {
    let mut rng = Rng::new(seed ^ 0x6175_7867_656e).fork(n);
    let rng = &mut rng;
    if rng.chance(30) {
        let mut raw = match seed_txs.is_empty() || rng.chance(30) {
            true => {
                let n_in = rng.below(4);
                tx(rng, n_in).serialize()
            }
            false => hex::decode(rng.pick(seed_txs)).unwrap_or_default(),
        };
        if rng.chance(80) {
            mutate_bytes(rng, &mut raw);
        }
        return AuxOp::Txinfo {
            tx_hex: hex::encode(&raw),
        };
    }

    let inputs = rng.range(1, 5);
    let t = tx(rng, inputs);
    let input_index = if rng.chance(3) {
        inputs as u32
    } else {
        rng.below(inputs) as u32
    };
    let kind = *rng.pick(&[
        SighashKind::Legacy,
        SighashKind::Bip143,
        SighashKind::Bip341,
    ]);
    let mut script_hex = hex::encode(&script(rng));
    let mut prevouts = vec![];
    let mut annex_hex = None;
    let mut leaf_hash_hex = None;
    let mut codesep_pos = u32::MAX;
    let hash_type = match kind {
        SighashKind::Bip341 => {
            prevouts = (0..inputs)
                .map(|_| {
                    let spk = if rng.chance(70) {
                        let mut s = vec![0x51, 0x20];
                        s.extend(rng.bytes(32));
                        s
                    } else {
                        script(rng)
                    };
                    Prevout {
                        script_pubkey_hex: hex::encode(&spk),
                        amount_sats: value(rng),
                    }
                })
                .collect();
            if rng.chance(25) {
                let mut a = vec![0x50];
                let n = rng.below(40);
                a.extend(rng.bytes(n));
                annex_hex = Some(hex::encode(&a));
            }
            if rng.chance(50) {
                // Script path: btcd derives the leaf hash from script_hex, the others take
                // leaf_hash_hex, so the two must agree.
                let leaf = script(rng);
                leaf_hash_hex = Some(hex::encode(&tapleaf_hash(0xc0, &leaf)));
                script_hex = hex::encode(&leaf);
                if rng.chance(30) {
                    codesep_pos = rng.below(20) as u32;
                }
            } else {
                script_hex = String::new();
            }
            if rng.chance(85) {
                *rng.pick(&TAPROOT_HASH_TYPES)
            } else {
                u32::from(rng.byte())
            }
        }
        _ => {
            if rng.chance(85) {
                *rng.pick(&ECDSA_HASH_TYPES)
            } else {
                rng.next_u64() as u32
            }
        }
    };
    AuxOp::Sighash {
        kind,
        tx_hex: hex::encode(&t.serialize()),
        input_index,
        script_hex,
        hash_type,
        amount_sats: value(rng),
        prevouts,
        annex_hex,
        leaf_hash_hex,
        codesep_pos,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_varied() {
        let seeds = vec!["0100000000000000000000".to_string()];
        assert_eq!(aux_op(7, 3, &seeds), aux_op(7, 3, &seeds));
        let ops: Vec<AuxOp> = (0..400).map(|n| aux_op(7, n, &seeds)).collect();
        let txinfo = ops
            .iter()
            .filter(|o| matches!(o, AuxOp::Txinfo { .. }))
            .count();
        assert!(txinfo > 50 && txinfo < 250, "{txinfo}");
        let kinds = |k: SighashKind| {
            ops.iter()
                .filter(|o| matches!(o, AuxOp::Sighash { kind, .. } if *kind == k))
                .count()
        };
        for k in [
            SighashKind::Legacy,
            SighashKind::Bip143,
            SighashKind::Bip341,
        ] {
            assert!(kinds(k) > 30, "{k:?}");
        }
        let script_path = ops
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    AuxOp::Sighash {
                        leaf_hash_hex: Some(_),
                        ..
                    }
                )
            })
            .count();
        assert!(script_path > 10);
        assert_ne!(aux_op(7, 3, &seeds), aux_op(8, 3, &seeds));
    }

    #[test]
    fn script_path_leaf_hash_matches_script() {
        for n in 0..300 {
            if let AuxOp::Sighash {
                leaf_hash_hex: Some(h),
                script_hex,
                ..
            } = aux_op(1, n, &[])
            {
                let s = hex::decode(&script_hex).unwrap();
                assert_eq!(h, hex::encode(&tapleaf_hash(0xc0, &s)));
            }
        }
    }
}
