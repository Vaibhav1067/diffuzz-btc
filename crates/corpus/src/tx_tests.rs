//! Loader for Bitcoin Core's `tx_valid.json` and `tx_invalid.json`.
//!
//! Each non-comment entry is
//! `[[[prevout_txid, prevout_index, prevout_scriptPubKey, amount?], ...], tx_hex, flags]`.
//!
//! * `tx_valid.json`: `flags` are the flags to **exclude**. Core verifies with every flag except
//!   those and expects success. We verify with every *consensus* flag except those, which is
//!   implied (removing flags never invalidates; Core's test asserts exactly this).
//! * `tx_invalid.json`: `flags` are the flags under which the transaction must fail. `BADTX`
//!   marks failures of context-free transaction checks rather than scripts; those and vectors
//!   that need policy flags are skipped.
//!
//! One [`Case`] is produced per input. A valid vector needs all inputs accepted; an invalid one
//! needs at least one rejected.

use std::collections::HashMap;

use diffuzz_types::tx::Tx;
use diffuzz_types::{Case, Flag, Prevout, hex};
use serde_json::Value;

use crate::asm::parse_script;
use crate::script_tests::{parse_flags, trim_flags};
use crate::{LoadError, Loaded, SkipReason, Skipped, VectorTest, err};

fn is_comment(entry: &[Value]) -> bool {
    entry.first().is_some_and(Value::is_string)
}

/// Load `tx_valid.json` (`valid = true`) or `tx_invalid.json` (`valid = false`).
pub fn load(json: &str, valid: bool) -> Result<Loaded, LoadError> {
    let file = if valid {
        "tx_valid.json"
    } else {
        "tx_invalid.json"
    };
    let root: Vec<Value> = serde_json::from_str(json).map_err(|e| err(file, e.to_string()))?;
    let mut loaded = Loaded::default();

    for (idx, entry) in root.iter().enumerate() {
        let name = format!("{file}#{idx}");
        let loc = name.as_str();
        let entry = entry
            .as_array()
            .ok_or_else(|| err(loc, "entry is not an array"))?;
        if is_comment(entry) {
            loaded.comments += 1;
            continue;
        }
        if entry.len() != 3 {
            return Err(err(loc, "expected [prevouts, tx, flags]"));
        }
        let flag_str = entry[2]
            .as_str()
            .ok_or_else(|| err(loc, "flags not a string"))?;

        let flags = if valid {
            let excluded = parse_flags(flag_str).map_err(|e| err(loc, e))?;
            let mut flags: Vec<Flag> = Flag::CONSENSUS
                .iter()
                .copied()
                .filter(|f| !excluded.contains(f))
                .collect();
            trim_flags(&mut flags);
            flags
        } else {
            if flag_str.split(',').any(|f| f.trim() == "BADTX") {
                loaded.skipped.push(Skipped {
                    name,
                    reason: SkipReason::BadTx,
                });
                continue;
            }
            let flags = parse_flags(flag_str).map_err(|e| err(loc, e))?;
            if flags.iter().any(|f| !f.is_consensus()) {
                loaded.skipped.push(Skipped {
                    name,
                    reason: SkipReason::PolicyFlags,
                });
                continue;
            }
            if flags.contains(&Flag::Witness) && !flags.contains(&Flag::P2sh) {
                loaded.skipped.push(Skipped {
                    name,
                    reason: SkipReason::UnsupportedFlagCombination,
                });
                continue;
            }
            flags
        };

        // Map of outpoint -> spent output.
        let mut map: HashMap<([u8; 32], u32), Prevout> = HashMap::new();
        let inputs = entry[0]
            .as_array()
            .ok_or_else(|| err(loc, "prevouts not an array"))?;
        for p in inputs {
            let p = p
                .as_array()
                .ok_or_else(|| err(loc, "prevout not an array"))?;
            if p.len() < 3 || p.len() > 4 {
                return Err(err(loc, "prevout must have 3 or 4 fields"));
            }
            let txid_hex = p[0]
                .as_str()
                .ok_or_else(|| err(loc, "prevout txid not a string"))?;
            let mut txid: [u8; 32] = hex::decode(txid_hex)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| err(loc, "prevout txid is not 32 bytes of hex"))?;
            txid.reverse(); // displayed big-endian, serialized little-endian
            let n = p[1]
                .as_i64()
                .ok_or_else(|| err(loc, "prevout index not an integer"))?;
            let vout = if n == -1 {
                0xffff_ffff
            } else {
                u32::try_from(n).map_err(|_| err(loc, "prevout index out of range"))?
            };
            let spk = parse_script(
                p[2].as_str()
                    .ok_or_else(|| err(loc, "script not a string"))?,
            )
            .map_err(|e| err(loc, format!("prevout script: {e}")))?;
            let amount = match p.get(3) {
                Some(v) => v
                    .as_u64()
                    .ok_or_else(|| err(loc, "amount not a non-negative int"))?,
                None => 0,
            };
            map.insert(
                (txid, vout),
                Prevout {
                    script_pubkey_hex: hex::encode(&spk),
                    amount_sats: amount,
                },
            );
        }

        let tx_hex = entry[1]
            .as_str()
            .ok_or_else(|| err(loc, "tx not a string"))?;
        let raw = hex::decode(tx_hex).ok_or_else(|| err(loc, "tx is not hex"))?;
        let tx = Tx::deserialize(&raw).map_err(|e| err(loc, format!("tx decode: {e}")))?;
        let mut prevouts = Vec::with_capacity(tx.inputs.len());
        for (i, input) in tx.inputs.iter().enumerate() {
            let p = map
                .get(&(input.prev_txid, input.prev_vout))
                .ok_or_else(|| err(loc, format!("input {i} spends an unlisted prevout")))?;
            prevouts.push(p.clone());
        }

        let cases = (0..tx.inputs.len())
            .map(|i| Case {
                tx_hex: tx_hex.to_ascii_lowercase(),
                input_index: i as u32,
                prevouts: prevouts.clone(),
                flags: flags.clone(),
                origin: Some(format!("{name}:{i}")),
            })
            .collect();
        loaded.tests.push(VectorTest {
            name,
            comment: String::new(),
            cases,
            expect_valid: valid,
            expected_error: None,
        });
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    // First real vector of tx_valid.json (a 2011 mainnet P2PKH spend with odd DER padding).
    const VALID: &str = r#"[
      ["comment line"],
      [[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1", 0, "1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]],
      "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "DERSIG,LOW_S,STRICTENC"]
    ]"#;

    #[test]
    fn valid_vector() {
        let l = load(VALID, true).unwrap();
        assert_eq!(l.comments, 1);
        assert_eq!(l.tests.len(), 1);
        let t = &l.tests[0];
        assert!(t.expect_valid);
        assert_eq!(t.name, "tx_valid.json#1");
        assert_eq!(t.cases.len(), 1);
        let c = &t.cases[0];
        // All consensus flags except the excluded DERSIG.
        assert_eq!(
            c.flags,
            vec![
                Flag::P2sh,
                Flag::Nulldummy,
                Flag::Cltv,
                Flag::Csv,
                Flag::Witness,
                Flag::Taproot
            ]
        );
        assert_eq!(c.prevouts.len(), 1);
        assert!(c.prevouts[0].script_pubkey_hex.starts_with("514104cc71"));
        assert!(c.prevouts[0].script_pubkey_hex.ends_with("52ae"));
        assert_eq!(c.prevouts[0].amount_sats, 0);
        assert_eq!(c.origin.as_deref(), Some("tx_valid.json#1:0"));
    }

    #[test]
    fn excluding_p2sh_also_drops_witness() {
        let json = VALID.replace("DERSIG,LOW_S,STRICTENC", "P2SH");
        let l = load(&json, true).unwrap();
        let flags = &l.tests[0].cases[0].flags;
        assert!(!flags.contains(&Flag::P2sh));
        assert!(!flags.contains(&Flag::Witness));
        assert!(flags.contains(&Flag::Taproot));
    }

    #[test]
    fn invalid_vector_flag_handling() {
        let as_invalid =
            |flags: &str| load(&VALID.replace("DERSIG,LOW_S,STRICTENC", flags), false).unwrap();
        let l = as_invalid("P2SH,CHECKLOCKTIMEVERIFY");
        assert_eq!(l.tests[0].cases[0].flags, vec![Flag::P2sh, Flag::Cltv]);
        assert!(!l.tests[0].expect_valid);
        assert_eq!(as_invalid("NONE").tests[0].cases[0].flags, vec![]);
        assert_eq!(as_invalid("BADTX").skipped[0].reason, SkipReason::BadTx);
        assert_eq!(
            as_invalid("P2SH,CONST_SCRIPTCODE").skipped[0].reason,
            SkipReason::PolicyFlags
        );
        assert_eq!(
            as_invalid("WITNESS").skipped[0].reason,
            SkipReason::UnsupportedFlagCombination
        );
    }

    #[test]
    fn amount_and_coinbase_index() {
        let json = r#"[[[["0000000000000000000000000000000000000000000000000000000000000000", -1, "1", 5000]],
          "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0151ffffffff010000000000000000015100000000", "NONE"]]"#;
        let l = load(json, true).unwrap();
        assert_eq!(l.tests[0].cases[0].prevouts[0].amount_sats, 5000);
    }

    #[test]
    fn missing_prevout_is_a_load_error() {
        let json = VALID.replace("60a20bd9", "70a20bd9");
        let e = load(&json, true).unwrap_err();
        assert!(e.message.contains("unlisted prevout"), "{e}");
    }
}
