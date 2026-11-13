//! Signature-hash algorithms: legacy, BIP143 (segwit v0) and BIP341 (taproot).
//!
//! The generators need these to produce *valid* signatures, which is the only way to reach the
//! success paths of signature checks. They are an independent implementation written from the
//! BIPs; their correctness is established by the generator tests, which require signatures made
//! here to verify in Bitcoin Core.

use diffuzz_types::script::{instructions, op};
use diffuzz_types::taproot::tagged_hash;
use diffuzz_types::tx::{Tx, sha256d, write_compact_size};
use sha2::{Digest, Sha256};

/// `SIGHASH_ALL`
pub const SIGHASH_ALL: u8 = 0x01;
/// `SIGHASH_NONE`
pub const SIGHASH_NONE: u8 = 0x02;
/// `SIGHASH_SINGLE`
pub const SIGHASH_SINGLE: u8 = 0x03;
/// `SIGHASH_ANYONECANPAY`
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Remove every `OP_CODESEPARATOR` from a script the way Core's legacy signature serializer
/// does: opcodes are parsed in order, and an unparsable tail is kept verbatim.
pub fn strip_codeseparators(script: &[u8]) -> Vec<u8> {
    let (ins, _) = instructions(script);
    let mut out = Vec::with_capacity(script.len());
    let mut start = 0;
    for i in &ins {
        if i.opcode == op::CODESEPARATOR {
            out.extend_from_slice(&script[start..i.offset]);
            start = i.offset + 1;
        }
    }
    out.extend_from_slice(&script[start..]);
    out
}

/// Remove every occurrence of the push of `data` from `script` (Core's `FindAndDelete`, applied
/// to signatures in legacy scripts). Matching is done at opcode boundaries only.
pub fn find_and_delete(script: &[u8], data: &[u8]) -> Vec<u8> {
    let mut pattern = Vec::new();
    diffuzz_types::script::push_data(&mut pattern, data);
    if pattern.is_empty() {
        return script.to_vec();
    }
    let (ins, _) = instructions(script);
    let mut boundaries: Vec<usize> = ins.iter().map(|i| i.offset).collect();
    boundaries.push(script.len());
    let mut out = Vec::with_capacity(script.len());
    let mut pos = 0;
    let mut bi = 0;
    while pos < script.len() {
        while bi < boundaries.len() && boundaries[bi] < pos {
            bi += 1;
        }
        let at_boundary = boundaries.get(bi) == Some(&pos);
        if at_boundary && script[pos..].starts_with(&pattern) {
            pos += pattern.len();
            continue;
        }
        // Copy up to the next opcode boundary (or the end, for an unparsable tail).
        let next = boundaries
            .iter()
            .copied()
            .find(|b| *b > pos)
            .unwrap_or(script.len());
        out.extend_from_slice(&script[pos..next]);
        pos = next;
    }
    out
}

/// Legacy (pre-segwit) signature hash.
///
/// `script_code` must already have had `FindAndDelete` applied by the caller if needed;
/// `OP_CODESEPARATOR`s are stripped here. `hash_type` is the full 32-bit value that is
/// serialized into the preimage (the signature only carries its low byte).
pub fn legacy(tx: &Tx, index: usize, script_code: &[u8], hash_type: u32) -> [u8; 32] {
    let base = hash_type & 0x1f;
    let acp = hash_type & u32::from(SIGHASH_ANYONECANPAY) != 0;
    // The SIGHASH_SINGLE bug: signing an input with no matching output hashes the number one.
    if base == u32::from(SIGHASH_SINGLE) && index >= tx.outputs.len() {
        let mut one = [0u8; 32];
        one[0] = 1;
        return one;
    }
    let code = strip_codeseparators(script_code);
    let mut s = Vec::new();
    s.extend_from_slice(&tx.version.to_le_bytes());

    let inputs: Vec<usize> = if acp {
        vec![index]
    } else {
        (0..tx.inputs.len()).collect()
    };
    write_compact_size(&mut s, inputs.len() as u64);
    for i in inputs {
        let input = &tx.inputs[i];
        s.extend_from_slice(&input.prev_txid);
        s.extend_from_slice(&input.prev_vout.to_le_bytes());
        if i == index {
            write_compact_size(&mut s, code.len() as u64);
            s.extend_from_slice(&code);
        } else {
            s.push(0);
        }
        let zero_seq =
            i != index && (base == u32::from(SIGHASH_NONE) || base == u32::from(SIGHASH_SINGLE));
        s.extend_from_slice(&(if zero_seq { 0 } else { input.sequence }).to_le_bytes());
    }

    if base == u32::from(SIGHASH_NONE) {
        s.push(0);
    } else if base == u32::from(SIGHASH_SINGLE) {
        write_compact_size(&mut s, index as u64 + 1);
        for _ in 0..index {
            // "Null" output: value -1, empty script.
            s.extend_from_slice(&u64::MAX.to_le_bytes());
            s.push(0);
        }
        let o = &tx.outputs[index];
        s.extend_from_slice(&o.value.to_le_bytes());
        write_compact_size(&mut s, o.script_pubkey.len() as u64);
        s.extend_from_slice(&o.script_pubkey);
    } else {
        write_compact_size(&mut s, tx.outputs.len() as u64);
        for o in &tx.outputs {
            s.extend_from_slice(&o.value.to_le_bytes());
            write_compact_size(&mut s, o.script_pubkey.len() as u64);
            s.extend_from_slice(&o.script_pubkey);
        }
    }
    s.extend_from_slice(&tx.lock_time.to_le_bytes());
    s.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&s)
}

fn outputs_blob(tx: &Tx) -> Vec<u8> {
    let mut b = Vec::new();
    for o in &tx.outputs {
        b.extend_from_slice(&o.value.to_le_bytes());
        write_compact_size(&mut b, o.script_pubkey.len() as u64);
        b.extend_from_slice(&o.script_pubkey);
    }
    b
}

/// BIP143 signature hash for segwit v0. `script_code` is used verbatim (no stripping).
pub fn bip143(tx: &Tx, index: usize, script_code: &[u8], amount: u64, hash_type: u32) -> [u8; 32] {
    let base = hash_type & 0x1f;
    let acp = hash_type & u32::from(SIGHASH_ANYONECANPAY) != 0;
    let single = base == u32::from(SIGHASH_SINGLE);
    let none = base == u32::from(SIGHASH_NONE);

    let mut hash_prevouts = [0u8; 32];
    if !acp {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.prev_txid);
            b.extend_from_slice(&i.prev_vout.to_le_bytes());
        }
        hash_prevouts = sha256d(&b);
    }
    let mut hash_sequence = [0u8; 32];
    if !acp && !single && !none {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.sequence.to_le_bytes());
        }
        hash_sequence = sha256d(&b);
    }
    let mut hash_outputs = [0u8; 32];
    if !single && !none {
        hash_outputs = sha256d(&outputs_blob(tx));
    } else if single && index < tx.outputs.len() {
        let o = &tx.outputs[index];
        let mut b = Vec::new();
        b.extend_from_slice(&o.value.to_le_bytes());
        write_compact_size(&mut b, o.script_pubkey.len() as u64);
        b.extend_from_slice(&o.script_pubkey);
        hash_outputs = sha256d(&b);
    }

    let input = &tx.inputs[index];
    let mut s = Vec::new();
    s.extend_from_slice(&tx.version.to_le_bytes());
    s.extend_from_slice(&hash_prevouts);
    s.extend_from_slice(&hash_sequence);
    s.extend_from_slice(&input.prev_txid);
    s.extend_from_slice(&input.prev_vout.to_le_bytes());
    write_compact_size(&mut s, script_code.len() as u64);
    s.extend_from_slice(script_code);
    s.extend_from_slice(&amount.to_le_bytes());
    s.extend_from_slice(&input.sequence.to_le_bytes());
    s.extend_from_slice(&hash_outputs);
    s.extend_from_slice(&tx.lock_time.to_le_bytes());
    s.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&s)
}

/// Script-path context for a BIP341 signature hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapscriptContext {
    /// `TapLeaf` hash of the executing script.
    pub leaf_hash: [u8; 32],
    /// Opcode position of the last executed `OP_CODESEPARATOR`, or `0xffffffff`.
    pub codesep_pos: u32,
}

/// BIP341 signature hash.
///
/// `prevouts` are the spent outputs of *all* inputs as `(scriptPubKey, amount)`. Returns `None`
/// where BIP341 defines no hash: an undefined `hash_type`, or `SIGHASH_SINGLE` without a
/// matching output.
pub fn bip341(
    tx: &Tx,
    index: usize,
    prevouts: &[(Vec<u8>, u64)],
    hash_type: u8,
    annex: Option<&[u8]>,
    tapscript: Option<TapscriptContext>,
) -> Option<[u8; 32]> {
    if !matches!(hash_type, 0x00..=0x03 | 0x81..=0x83) {
        return None;
    }
    let output_type = if hash_type == 0 {
        SIGHASH_ALL
    } else {
        hash_type & 0x03
    };
    let acp = hash_type & SIGHASH_ANYONECANPAY != 0;
    if prevouts.len() != tx.inputs.len() || index >= tx.inputs.len() {
        return None;
    }

    let mut s = vec![0x00, hash_type];
    s.extend_from_slice(&tx.version.to_le_bytes());
    s.extend_from_slice(&tx.lock_time.to_le_bytes());
    if !acp {
        let mut outpoints = Vec::new();
        let mut amounts = Vec::new();
        let mut scripts = Vec::new();
        let mut sequences = Vec::new();
        for (i, (spk, amount)) in tx.inputs.iter().zip(prevouts) {
            outpoints.extend_from_slice(&i.prev_txid);
            outpoints.extend_from_slice(&i.prev_vout.to_le_bytes());
            amounts.extend_from_slice(&amount.to_le_bytes());
            write_compact_size(&mut scripts, spk.len() as u64);
            scripts.extend_from_slice(spk);
            sequences.extend_from_slice(&i.sequence.to_le_bytes());
        }
        s.extend_from_slice(&sha256(&outpoints));
        s.extend_from_slice(&sha256(&amounts));
        s.extend_from_slice(&sha256(&scripts));
        s.extend_from_slice(&sha256(&sequences));
    }
    if output_type == SIGHASH_ALL {
        s.extend_from_slice(&sha256(&outputs_blob(tx)));
    }
    let spend_type = u8::from(tapscript.is_some()) * 2 + u8::from(annex.is_some());
    s.push(spend_type);
    if acp {
        let input = &tx.inputs[index];
        let (spk, amount) = &prevouts[index];
        s.extend_from_slice(&input.prev_txid);
        s.extend_from_slice(&input.prev_vout.to_le_bytes());
        s.extend_from_slice(&amount.to_le_bytes());
        write_compact_size(&mut s, spk.len() as u64);
        s.extend_from_slice(spk);
        s.extend_from_slice(&input.sequence.to_le_bytes());
    } else {
        s.extend_from_slice(&(index as u32).to_le_bytes());
    }
    if let Some(annex) = annex {
        let mut b = Vec::new();
        write_compact_size(&mut b, annex.len() as u64);
        b.extend_from_slice(annex);
        s.extend_from_slice(&sha256(&b));
    }
    if output_type == SIGHASH_SINGLE {
        let o = tx.outputs.get(index)?;
        let mut b = Vec::new();
        b.extend_from_slice(&o.value.to_le_bytes());
        write_compact_size(&mut b, o.script_pubkey.len() as u64);
        b.extend_from_slice(&o.script_pubkey);
        s.extend_from_slice(&sha256(&b));
    }
    if let Some(ctx) = tapscript {
        s.extend_from_slice(&ctx.leaf_hash);
        s.push(0x00); // key version
        s.extend_from_slice(&ctx.codesep_pos.to_le_bytes());
    }
    Some(tagged_hash("TapSighash", &s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::hex;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn strips_codeseparators_at_opcode_boundaries_only() {
        assert_eq!(strip_codeseparators(&h("51ab52ab")), h("5152"));
        // 0xab inside a push is data, not an opcode.
        assert_eq!(strip_codeseparators(&h("01ab51")), h("01ab51"));
        // Unparsable tail (push of 5 with 1 byte) is kept verbatim.
        assert_eq!(strip_codeseparators(&h("ab5105ab")), h("5105ab"));
        assert_eq!(strip_codeseparators(&[]), Vec::<u8>::new());
    }

    #[test]
    fn find_and_delete_matches_whole_pushes() {
        // Remove push of 0xaabb.
        assert_eq!(
            find_and_delete(&h("5102aabb5202aabb"), &h("aabb")),
            h("5152")
        );
        // The bytes 02aabb inside a larger push must not match.
        assert_eq!(
            find_and_delete(&h("0402aabb0051"), &h("aabb")),
            h("0402aabb0051")
        );
        assert_eq!(find_and_delete(&h("5152"), &h("aabb")), h("5152"));
        // Deleting the empty push removes OP_0.
        assert_eq!(find_and_delete(&h("005100"), &[]), h("51"));
    }

    // BIP143 "Native P2WPKH" example: second input, amount 6 BTC, SIGHASH_ALL.
    #[test]
    fn bip143_reference_vector() {
        let tx = Tx::deserialize(&h("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")).unwrap();
        let script_code = h("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
        let digest = bip143(&tx, 1, &script_code, 600_000_000, 1);
        assert_eq!(
            hex::encode(&digest),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    #[test]
    fn legacy_single_bug_and_basic_properties() {
        let tx = Tx::deserialize(&h("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff01202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac11000000")).unwrap();
        // Input 1 has no output 1: SIGHASH_SINGLE hashes to "one".
        let one = legacy(&tx, 1, &[0x51], 3);
        assert_eq!(one[0], 1);
        assert!(one[1..].iter().all(|b| *b == 0));
        assert_eq!(legacy(&tx, 1, &[0x51], 0x83), one);
        // Input 0 has a matching output: a real hash.
        assert_ne!(legacy(&tx, 0, &[0x51], 3), one);
        // The full 32-bit hash type is committed.
        assert_ne!(
            legacy(&tx, 0, &[0x51], 1),
            legacy(&tx, 0, &[0x51], 0x0100_0001)
        );
        // Codeseparators in scriptCode do not affect the hash.
        assert_eq!(legacy(&tx, 0, &[0xab, 0x51], 1), legacy(&tx, 0, &[0x51], 1));
        // Different modes differ.
        let all = legacy(&tx, 0, &[0x51], 1);
        assert_ne!(all, legacy(&tx, 0, &[0x51], 2));
        assert_ne!(all, legacy(&tx, 0, &[0x51], 0x81));
    }

    // Every key-path sighash in the BIPs repository's wallet-test-vectors.json.
    #[test]
    fn bip341_reference_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/bip341/wallet-test-vectors.json"
        );
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut checked = 0;
        for group in json["keyPathSpending"].as_array().unwrap() {
            let tx =
                Tx::deserialize(&h(group["given"]["rawUnsignedTx"].as_str().unwrap())).unwrap();
            let prevouts: Vec<(Vec<u8>, u64)> = group["given"]["utxosSpent"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| {
                    (
                        h(u["scriptPubKey"].as_str().unwrap()),
                        u["amountSats"].as_u64().unwrap(),
                    )
                })
                .collect();
            for input in group["inputSpending"].as_array().unwrap() {
                let index = input["given"]["txinIndex"].as_u64().unwrap() as usize;
                let hash_type = input["given"]["hashType"].as_u64().unwrap() as u8;
                let expected = input["intermediary"]["sigHash"].as_str().unwrap();
                let got = bip341(&tx, index, &prevouts, hash_type, None, None).unwrap();
                assert_eq!(
                    hex::encode(&got),
                    expected,
                    "input {index} type {hash_type:#x}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 7);
    }

    #[test]
    fn bip341_undefined_inputs() {
        let tx = Tx {
            version: 2,
            inputs: vec![diffuzz_types::tx::TxIn::default()],
            outputs: vec![],
            lock_time: 0,
        };
        let prevouts = vec![(vec![0x51], 1u64)];
        assert!(bip341(&tx, 0, &prevouts, 0, None, None).is_some());
        for bad in [0x04u8, 0x10, 0x80, 0x84, 0xff] {
            assert!(
                bip341(&tx, 0, &prevouts, bad, None, None).is_none(),
                "{bad:#x}"
            );
        }
        // SIGHASH_SINGLE with no output at this index.
        assert!(bip341(&tx, 0, &prevouts, 3, None, None).is_none());
        assert!(bip341(&tx, 0, &[], 0, None, None).is_none());
        // Annex and tapscript context change the digest.
        let base = bip341(&tx, 0, &prevouts, 0, None, None).unwrap();
        assert_ne!(
            bip341(&tx, 0, &prevouts, 0, Some(&[0x50]), None).unwrap(),
            base
        );
        let ctx = TapscriptContext {
            leaf_hash: [1; 32],
            codesep_pos: 0xffff_ffff,
        };
        let script = bip341(&tx, 0, &prevouts, 0, None, Some(ctx)).unwrap();
        assert_ne!(script, base);
        let ctx2 = TapscriptContext {
            leaf_hash: [1; 32],
            codesep_pos: 0,
        };
        assert_ne!(
            bip341(&tx, 0, &prevouts, 0, None, Some(ctx2)).unwrap(),
            script
        );
    }
}
