//! Our sighash implementations (crates/gen/src/sighash.rs, used to sign every generated case)
//! against rust-bitcoin's, through the rust-bitcoin adapter. Legacy, BIP143 and BIP341 (key and
//! script path, with and without annex) must produce identical digests, and agree on when no
//! digest exists.

#![no_main]

use arbitrary::Arbitrary;
use diffuzz_gen::sighash::{self, TapscriptContext};
use diffuzz_types::auxop::{AuxOp, AuxRequest, SighashKind};
use diffuzz_types::taproot::tapleaf_hash;
use diffuzz_types::tx::Tx;
use diffuzz_types::{Prevout, hex};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    tx: Vec<u8>,
    index: u8,
    kind: u8,
    script: Vec<u8>,
    hash_type: u32,
    amount: u64,
    prevouts: Vec<(Vec<u8>, u64)>,
    annex: Option<Vec<u8>>,
    leaf: Option<(Vec<u8>, u32)>,
}

struct Op {
    kind: SighashKind,
    script_hex: String,
    hash_type: u32,
    amount_sats: u64,
    prevouts: Vec<Prevout>,
    annex_hex: Option<String>,
    leaf_hash_hex: Option<String>,
    codesep_pos: u32,
}

fuzz_target!(|inp: Input| {
    let Ok(tx) = Tx::deserialize(&inp.tx) else {
        return;
    };
    // Only transactions both parsers read identically are comparable.
    let Ok(theirs) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&inp.tx) else {
        return;
    };
    if tx.inputs.is_empty() || theirs.input.len() != tx.inputs.len() {
        return;
    }
    let index = usize::from(inp.index) % tx.inputs.len();

    let (op, ours) = match inp.kind % 3 {
        0 => (
            Op {
                kind: SighashKind::Legacy,
                script_hex: hex::encode(&inp.script),
                hash_type: inp.hash_type,
                amount_sats: 0,
                prevouts: vec![],
                annex_hex: None,
                leaf_hash_hex: None,
                codesep_pos: u32::MAX,
            },
            Some(sighash::legacy(&tx, index, &inp.script, inp.hash_type)),
        ),
        1 => (
            Op {
                kind: SighashKind::Bip143,
                script_hex: hex::encode(&inp.script),
                hash_type: inp.hash_type,
                amount_sats: inp.amount,
                prevouts: vec![],
                annex_hex: None,
                leaf_hash_hex: None,
                codesep_pos: u32::MAX,
            },
            Some(sighash::bip143(&tx, index, &inp.script, inp.amount, inp.hash_type)),
        ),
        _ => {
            if inp.prevouts.is_empty() {
                return;
            }
            let prevouts: Vec<(Vec<u8>, u64)> = (0..tx.inputs.len())
                .map(|i| inp.prevouts[i % inp.prevouts.len()].clone())
                .collect();
            let hash_type = inp.hash_type & 0xff;
            let annex = inp.annex.map(|mut a| {
                a.insert(0, 0x50);
                a
            });
            let ctx = inp.leaf.as_ref().map(|(leaf, pos)| TapscriptContext {
                leaf_hash: tapleaf_hash(0xc0, leaf),
                codesep_pos: *pos,
            });
            let ours =
                sighash::bip341(&tx, index, &prevouts, hash_type as u8, annex.as_deref(), ctx);
            (
                Op {
                    kind: SighashKind::Bip341,
                    script_hex: inp
                        .leaf
                        .as_ref()
                        .map(|(l, _)| hex::encode(l))
                        .unwrap_or_default(),
                    hash_type,
                    amount_sats: 0,
                    prevouts: prevouts
                        .iter()
                        .map(|(s, a)| Prevout {
                            script_pubkey_hex: hex::encode(s),
                            amount_sats: *a,
                        })
                        .collect(),
                    annex_hex: annex.as_ref().map(|a| hex::encode(a)),
                    leaf_hash_hex: ctx.map(|c| hex::encode(&c.leaf_hash)),
                    codesep_pos: ctx.map_or(u32::MAX, |c| c.codesep_pos),
                },
                ours,
            )
        }
    };
    let req = AuxRequest {
        id: 1,
        op: AuxOp::Sighash {
            kind: op.kind,
            tx_hex: hex::encode(&inp.tx),
            input_index: index as u32,
            script_hex: op.script_hex,
            hash_type: op.hash_type,
            amount_sats: op.amount_sats,
            prevouts: op.prevouts,
            annex_hex: op.annex_hex,
            leaf_hash_hex: op.leaf_hash_hex,
            codesep_pos: op.codesep_pos,
        },
    };
    let theirs = diffuzz_adapter_rust_bitcoin::handle_aux(&req);
    if theirs.unsupported {
        return; // documented adapter limits (non-canonical BIP143 hash types)
    }
    match ours {
        Some(d) => assert_eq!(
            theirs.digest.as_deref(),
            Some(hex::encode(&d).as_str()),
            "digest mismatch; rust-bitcoin said {theirs:?}"
        ),
        None => assert!(
            !theirs.ok,
            "ours defines no digest, rust-bitcoin returned {theirs:?}"
        ),
    }
});
