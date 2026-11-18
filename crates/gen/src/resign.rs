//! Re-signing: after a mutation changed signed data, replace every signature made by a test key
//! with a fresh one over the mutated transaction, so mutants can reach success paths again.
//!
//! Only spends whose signing context can be recovered from the case itself are handled: bare
//! and P2SH legacy scripts, P2WPKH and P2WSH (also nested in P2SH), and taproot script-path
//! spends with leaf version 0xc0. Taproot key-path spends (the merkle root is not in the case)
//! and scripts containing `OP_CODESEPARATOR` (which separator executed is not known) are left
//! alone. Signatures are assigned to test keys in script order, which matches how the
//! generators build multisig. Anything that cannot be re-signed is kept byte for byte.

use std::collections::HashMap;
use std::sync::OnceLock;

use diffuzz_types::script::{Instruction, instructions, op, push_data};
use diffuzz_types::taproot::tapleaf_hash;
use diffuzz_types::tx::Tx;
use diffuzz_types::{Case, hex};

use crate::keys::{DerQuirk, der_encode, test_key};
use crate::sighash;
use crate::spend::p2pkh_script;

/// Test-key indices searched when mapping a public key back to its key.
const KEY_RANGE: u32 = 128;

/// Public key bytes (compressed, uncompressed and x-only) to test-key index.
fn key_index() -> &'static HashMap<Vec<u8>, u32> {
    static MAP: OnceLock<HashMap<Vec<u8>, u32>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        for i in 0..KEY_RANGE {
            let k = test_key(i);
            m.insert(k.compressed().to_vec(), i);
            m.insert(k.uncompressed().to_vec(), i);
            m.insert(k.xonly().to_vec(), i);
        }
        m
    })
}

/// Test keys whose public keys are pushed by `script`, in order.
fn keys_in(script: &[u8], len: usize) -> Vec<u32> {
    instructions(script)
        .0
        .iter()
        .filter_map(|i| {
            i.data
                .filter(|d| d.len() == len || (len == 33 && d.len() == 65))
        })
        .filter_map(|d| key_index().get(d).copied())
        .collect()
}

fn looks_like_ecdsa(item: &[u8]) -> bool {
    item.len() >= 9 && item.len() <= 73 && item[0] == 0x30
}

fn looks_like_schnorr(item: &[u8]) -> bool {
    item.len() == 64 || item.len() == 65
}

fn has_codeseparator(script: &[u8]) -> bool {
    instructions(script)
        .0
        .iter()
        .any(|i| i.opcode == op::CODESEPARATOR)
}

fn ecdsa_resign(digest: [u8; 32], key: u32, hash_type: u8) -> Vec<u8> {
    let (r, s) = test_key(key).sign_ecdsa(digest);
    let mut sig = der_encode(&r, &s, DerQuirk::Strict);
    sig.push(hash_type);
    sig
}

/// ECDSA candidate keys: test keys pushed by the script, then test public keys among the stack
/// items themselves (P2PKH-style spends carry the key next to the signature).
fn ecdsa_keys(code: &[u8], items: &[Vec<u8>]) -> Vec<u32> {
    let mut keys = keys_in(code, 33);
    keys.extend(
        items
            .iter()
            .filter_map(|i| key_index().get(i.as_slice()).copied()),
    );
    keys
}

/// Re-sign legacy items. `code` is the scriptCode before `FindAndDelete`.
fn resign_legacy(tx: &Tx, index: usize, code: &[u8], items: &mut [Vec<u8>]) -> usize {
    let keys = ecdsa_keys(code, items);
    let mut done = 0;
    let mut k = 0;
    for item in items.iter_mut() {
        if !looks_like_ecdsa(item) {
            continue;
        }
        let Some(&key) = keys.get(k) else { break };
        k += 1;
        let ht = item[item.len() - 1];
        let stripped = sighash::find_and_delete(code, item);
        let digest = sighash::legacy(tx, index, &stripped, u32::from(ht));
        *item = ecdsa_resign(digest, key, ht);
        done += 1;
    }
    done
}

fn resign_v0(
    tx: &Tx,
    index: usize,
    code: &[u8],
    amount: u64,
    items: &mut [Vec<u8>],
    extra_keys: &[u32],
) -> usize {
    let mut keys = ecdsa_keys(code, items);
    keys.extend_from_slice(extra_keys);
    let mut done = 0;
    let mut k = 0;
    for item in items.iter_mut() {
        if !looks_like_ecdsa(item) {
            continue;
        }
        let Some(&key) = keys.get(k) else { break };
        k += 1;
        let ht = item[item.len() - 1];
        let digest = sighash::bip143(tx, index, code, amount, u32::from(ht));
        *item = ecdsa_resign(digest, key, ht);
        done += 1;
    }
    done
}

/// Re-encode a scriptSig, replacing push `n` (counting pushes only) with `new[n]` where given.
fn rebuild_pushes(script: &[u8], ins: &[Instruction<'_>], new: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut n = 0;
    for (i, ins_i) in ins.iter().enumerate() {
        let end = ins.get(i + 1).map_or(script.len(), |x| x.offset);
        match (ins_i.data, new.get(n)) {
            (Some(_), Some(Some(repl))) => push_data(&mut out, repl),
            _ => out.extend_from_slice(&script[ins_i.offset..end]),
        }
        if ins_i.data.is_some() {
            n += 1;
        }
    }
    out
}

/// Re-sign the test-key signatures of the input under test. Returns the case unchanged when
/// nothing could be re-signed.
pub fn resign(case: &Case) -> Case {
    try_resign(case).unwrap_or_else(|| case.clone())
}

fn try_resign(case: &Case) -> Option<Case> {
    let mut tx = Tx::deserialize(&hex::decode(&case.tx_hex)?).ok()?;
    let index = case.input_index as usize;
    let prevouts: Vec<(Vec<u8>, u64)> = case
        .prevouts
        .iter()
        .map(|p| Some((hex::decode(&p.script_pubkey_hex)?, p.amount_sats)))
        .collect::<Option<_>>()?;
    let (spk, amount) = prevouts.get(index)?.clone();
    let input = tx.inputs.get(index)?.clone();

    let (ss_ins, ss_complete) = instructions(&input.script_sig);
    let ss_pushes: Vec<Vec<u8>> = ss_ins
        .iter()
        .filter_map(|i| i.data.map(<[u8]>::to_vec))
        .collect();
    let is_p2sh = spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87;
    // The program actually spent: the redeem script for P2SH, else the scriptPubKey.
    let program = if is_p2sh {
        ss_pushes.last()?.clone()
    } else {
        spk.clone()
    };
    let witness_version = match program.as_slice() {
        [0x00, n, rest @ ..] if usize::from(*n) == rest.len() => Some(0),
        [0x51, 0x20, rest @ ..] if rest.len() == 32 && !is_p2sh => Some(1),
        _ => None,
    };

    let done = match witness_version {
        None => {
            if !ss_complete || has_codeseparator(&program) {
                return None;
            }
            // Signatures are the pushes before the redeem script (P2SH) or all pushes.
            let n_sigs = ss_pushes.len() - usize::from(is_p2sh);
            let mut items: Vec<Vec<u8>> = ss_pushes[..n_sigs].to_vec();
            let done = resign_legacy(&tx, index, &program, &mut items);
            let mut new: Vec<Option<Vec<u8>>> = items.into_iter().map(Some).collect();
            new.extend(std::iter::repeat_n(None, ss_pushes.len() - n_sigs));
            tx.inputs[index].script_sig = rebuild_pushes(&input.script_sig, &ss_ins, &new);
            done
        }
        Some(0) => {
            let mut w = input.witness.clone();
            let done = if program.len() == 22 {
                // P2WPKH: <sig> <pubkey>, scriptCode is the P2PKH script of the pubkey.
                if w.len() != 2 {
                    return None;
                }
                let code = p2pkh_script(&w[1]);
                let key: Vec<u32> = key_index()
                    .get(w[1].as_slice())
                    .copied()
                    .into_iter()
                    .collect();
                let (sigs, _) = w.split_at_mut(1);
                resign_v0(&tx, index, &code, amount, sigs, &key)
            } else {
                let (last, sigs) = w.split_last_mut()?;
                if has_codeseparator(last) {
                    return None;
                }
                let code = last.clone();
                resign_v0(&tx, index, &code, amount, sigs, &[])
            };
            tx.inputs[index].witness = w;
            done
        }
        _ => {
            let mut w = input.witness.clone();
            let annex = if w.len() >= 2 && w.last().is_some_and(|a| a.first() == Some(&0x50)) {
                w.pop()
            } else {
                None
            };
            if w.len() < 2 {
                return None; // key path
            }
            let control = w.pop()?;
            let tapscript = w.pop()?;
            if control.first().map(|c| c & 0xfe) != Some(0xc0) || has_codeseparator(&tapscript) {
                return None;
            }
            let leaf_hash = tapleaf_hash(0xc0, &tapscript);
            // CHECKSIG/CHECKSIGADD consume the top of the stack first, so the last witness item
            // pairs with the first key pushed by the script; empty items take a slot too.
            let keys = keys_in(&tapscript, 32);
            let mut done = 0;
            for (item, &key) in w.iter_mut().rev().zip(&keys) {
                if !looks_like_schnorr(item) {
                    continue;
                }
                let ht = if item.len() == 65 { item[64] } else { 0 };
                let ctx = sighash::TapscriptContext {
                    leaf_hash,
                    codesep_pos: u32::MAX,
                };
                let Some(digest) =
                    sighash::bip341(&tx, index, &prevouts, ht, annex.as_deref(), Some(ctx))
                else {
                    continue;
                };
                let mut sig = test_key(key).sign_schnorr(digest).to_vec();
                if item.len() == 65 {
                    sig.push(ht);
                }
                *item = sig;
                done += 1;
            }
            w.push(tapscript);
            w.push(control);
            w.extend(annex);
            tx.inputs[index].witness = w;
            done
        }
    };
    if done == 0 {
        return None;
    }
    let mut out = case.clone();
    out.tx_hex = hex::encode(&tx.serialize());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::Generator;
    use crate::generators::sig::SigGen;
    use crate::generators::taproot::TaprootGen;
    use crate::rng::Rng;

    /// Change the lock time: invalidates every signature but nothing else.
    fn bump_locktime(case: &Case) -> Case {
        let mut tx = Tx::deserialize(&hex::decode(&case.tx_hex).unwrap()).unwrap();
        tx.lock_time = tx.lock_time.wrapping_add(1);
        let mut out = case.clone();
        out.tx_hex = hex::encode(&tx.serialize());
        out
    }

    #[test]
    fn resigning_is_deterministic_and_changes_signatures() {
        let mut changed = 0;
        for seed in 0..200 {
            let case = SigGen.generate(&mut Rng::new(seed));
            let mutated = bump_locktime(&case);
            let a = resign(&mutated);
            assert_eq!(a, resign(&mutated));
            if a != mutated {
                changed += 1;
            }
        }
        assert!(changed > 50, "only {changed} of 200 cases re-signed");
    }

    #[test]
    fn skips_unparsable_and_keypath() {
        let mut c = SigGen.generate(&mut Rng::new(1));
        c.tx_hex = "zz".into();
        assert_eq!(resign(&c), c);
        let k = TaprootGen.build(&mut Rng::new(3), "keypath", true, vec![]);
        assert_eq!(resign(&bump_locktime(&k)), bump_locktime(&k));
    }
}
