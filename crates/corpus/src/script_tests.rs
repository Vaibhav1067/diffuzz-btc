//! Loader for Bitcoin Core's `script_tests.json`.
//!
//! Each entry is a JSON array, one of:
//!
//! * `["comment"]`: ignored;
//! * `[scriptSig, scriptPubKey, flags, expected_error, comment?]`;
//! * `[[wit..., amount], scriptSig, scriptPubKey, flags, expected_error, comment?]` where the
//!   leading array holds hex witness stack items followed by the spent amount in BTC.
//!
//! Tapscript vectors use three placeholders, expanded exactly as Core's test does: a witness
//! item `#SCRIPT# <asm>` is assembled, `#CONTROLBLOCK#` becomes the control block of a
//! single-leaf tree over that script with the NUMS internal key, and the scriptPubKey
//! `0x51 0x20 #TAPROOTOUTPUT#` becomes the matching P2TR output.
//!
//! Like Core's `DoTest`, each vector becomes a one-input transaction spending a synthetic
//! "crediting" transaction that carries the scriptPubKey.
//!
//! ## Flags
//!
//! Vectors name the exact flags to verify with, and most include policy flags. The main oracle
//! is consensus-only, so:
//!
//! * consensus-only vectors run unchanged;
//! * vectors with policy flags that expect `OK` run with the policy flags removed. This is sound
//!   because every script flag only adds restrictions: valid under a flag set implies valid
//!   under any subset (Core's `tx_tests` asserts the same property for `tx_valid.json`). The
//!   one dependency is that WITNESS requires P2SH, handled by [`trim_flags`];
//! * vectors with policy flags that expect an error are skipped, because the error may come
//!   from the policy flag.

use diffuzz_types::tx::{Tx, TxIn, TxOut};
use diffuzz_types::{Case, Flag, Prevout, hex, normalize_flags, taproot};
use serde_json::Value;

use crate::asm::parse_script;
use crate::{LoadError, Loaded, SkipReason, Skipped, VectorTest, err};

/// Parse a comma-separated flag list as used in Core's vectors. `""` and `"NONE"` mean no flags.
pub fn parse_flags(s: &str) -> Result<Vec<Flag>, String> {
    let mut out = Vec::new();
    for name in s
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty() && *n != "NONE")
    {
        out.push(Flag::from_name(name).ok_or_else(|| format!("unknown flag {name}"))?);
    }
    normalize_flags(&mut out);
    Ok(out)
}

/// Drop flags whose prerequisites are missing, mirroring `TrimFlags` in Core's `tx_tests.cpp`:
/// WITNESS requires P2SH. (CLEANSTACK's requirement is irrelevant to consensus-only sets.)
pub fn trim_flags(flags: &mut Vec<Flag>) {
    if !flags.contains(&Flag::P2sh) {
        flags.retain(|f| *f != Flag::Witness);
    }
}

/// Build the (crediting, spending) transaction pair exactly like Core's script test harness.
pub fn build_spend(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: Vec<Vec<u8>>,
    amount: u64,
) -> Tx {
    let credit = Tx {
        version: 1,
        inputs: vec![TxIn {
            prev_txid: [0u8; 32],
            prev_vout: 0xffff_ffff,
            script_sig: vec![0x00, 0x00],
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: script_pubkey.to_vec(),
        }],
        lock_time: 0,
    };
    Tx {
        version: 1,
        inputs: vec![TxIn {
            prev_txid: credit.txid(),
            prev_vout: 0,
            script_sig: script_sig.to_vec(),
            sequence: 0xffff_ffff,
            witness,
        }],
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: Vec::new(),
        }],
        lock_time: 0,
    }
}

fn str_at<'a>(entry: &'a [Value], i: usize, loc: &str) -> Result<&'a str, LoadError> {
    entry
        .get(i)
        .and_then(Value::as_str)
        .ok_or_else(|| err(loc, format!("field {i}: not a string")))
}

/// Load `script_tests.json` from its JSON text.
pub fn load(json: &str) -> Result<Loaded, LoadError> {
    let file = "script_tests.json";
    let root: Vec<Value> = serde_json::from_str(json).map_err(|e| err(file, e.to_string()))?;
    let mut loaded = Loaded::default();

    for (idx, entry) in root.iter().enumerate() {
        let name = format!("{file}#{idx}");
        let loc = name.as_str();
        let entry = entry
            .as_array()
            .ok_or_else(|| err(loc, "entry is not an array"))?;
        if entry.len() == 1 {
            loaded.comments += 1;
            continue;
        }

        let mut witness = Vec::new();
        let mut taproot_output: Option<[u8; 32]> = None;
        let mut amount = 0u64;
        let mut off = 0;
        if let Some(w) = entry.first().and_then(Value::as_array) {
            let (value, items) = w
                .split_last()
                .ok_or_else(|| err(loc, "empty witness array"))?;
            let btc = value
                .as_f64()
                .ok_or_else(|| err(loc, "witness amount is not a number"))?;
            if !(0.0..=21_000_000.0).contains(&btc) {
                return Err(err(loc, "witness amount out of range"));
            }
            amount = (btc * 1e8).round() as u64;
            for item in items {
                let s = item
                    .as_str()
                    .ok_or_else(|| err(loc, "witness item is not a string"))?;
                if let Some(asm) = s.strip_prefix("#SCRIPT#") {
                    // A tapscript given in assembly rather than hex.
                    witness
                        .push(parse_script(asm).map_err(|e| err(loc, format!("#SCRIPT#: {e}")))?);
                } else if s == "#CONTROLBLOCK#" {
                    // Auto-generated control block for a single-leaf tree over the previous
                    // witness item, with Core's NUMS_H as internal key.
                    let script = witness
                        .last()
                        .ok_or_else(|| err(loc, "#CONTROLBLOCK# without script"))?;
                    let leaf = taproot::tapleaf_hash(taproot::LEAF_TAPSCRIPT, script);
                    let (key, odd) = taproot::tweak_output_key(&taproot::NUMS_H, Some(&leaf))
                        .ok_or_else(|| err(loc, "taproot tweak failed"))?;
                    taproot_output = Some(key);
                    witness.push(taproot::control_block(
                        taproot::LEAF_TAPSCRIPT,
                        odd,
                        &taproot::NUMS_H,
                        &[],
                    ));
                } else {
                    witness
                        .push(hex::decode(s).ok_or_else(|| err(loc, "witness item is not hex"))?);
                }
            }
            off = 1;
        }
        if entry.len() < off + 4 {
            return Err(err(loc, "too few fields"));
        }

        let script_sig = parse_script(str_at(entry, off, loc)?)
            .map_err(|e| err(loc, format!("scriptSig: {e}")))?;
        let spk_str = str_at(entry, off + 1, loc)?;
        let script_pubkey = if spk_str == "0x51 0x20 #TAPROOTOUTPUT#" {
            let key =
                taproot_output.ok_or_else(|| err(loc, "#TAPROOTOUTPUT# without #CONTROLBLOCK#"))?;
            taproot::p2tr_script(&key)
        } else {
            parse_script(spk_str).map_err(|e| err(loc, format!("scriptPubKey: {e}")))?
        };
        let mut flags = parse_flags(str_at(entry, off + 2, loc)?).map_err(|e| err(loc, e))?;
        let expected = str_at(entry, off + 3, loc)?;
        let comment = entry
            .get(off + 4)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let expect_valid = expected == "OK";

        if flags.iter().any(|f| !f.is_consensus()) {
            if !expect_valid {
                loaded.skipped.push(Skipped {
                    name,
                    reason: SkipReason::PolicyFlags,
                });
                continue;
            }
            flags.retain(|f| f.is_consensus());
            trim_flags(&mut flags);
        } else if flags.contains(&Flag::Witness) && !flags.contains(&Flag::P2sh) {
            loaded.skipped.push(Skipped {
                name,
                reason: SkipReason::UnsupportedFlagCombination,
            });
            continue;
        }

        let tx = build_spend(&script_sig, &script_pubkey, witness, amount);
        let case = Case {
            tx_hex: hex::encode(&tx.serialize()),
            input_index: 0,
            prevouts: vec![Prevout {
                script_pubkey_hex: hex::encode(&script_pubkey),
                amount_sats: amount,
            }],
            flags,
            origin: Some(name.clone()),
        };
        loaded.tests.push(VectorTest {
            name,
            comment,
            cases: vec![case],
            expect_valid,
            expected_error: (!expect_valid).then(|| expected.to_string()),
        });
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags() {
        assert_eq!(parse_flags("").unwrap(), vec![]);
        assert_eq!(parse_flags("NONE").unwrap(), vec![]);
        assert_eq!(
            parse_flags("WITNESS,P2SH").unwrap(),
            vec![Flag::P2sh, Flag::Witness]
        );
        assert_eq!(
            parse_flags("CHECKLOCKTIMEVERIFY").unwrap(),
            vec![Flag::Cltv]
        );
        assert!(parse_flags("P2SH,BOGUS").is_err());

        let mut f = vec![Flag::Witness, Flag::Taproot];
        trim_flags(&mut f);
        assert_eq!(f, vec![Flag::Taproot]);
        let mut f = vec![Flag::P2sh, Flag::Witness];
        trim_flags(&mut f);
        assert_eq!(f, vec![Flag::P2sh, Flag::Witness]);
    }

    #[test]
    fn spend_shape_matches_core_harness() {
        let tx = build_spend(&[0x51], &[0x51, 0x87], vec![], 0);
        let raw = tx.serialize();
        // version 1, one input, 36-byte outpoint, 1-byte scriptSig 0x51, final sequence,
        // one zero-value output with empty script, locktime 0.
        assert_eq!(raw.len(), 4 + 1 + 36 + 2 + 4 + 1 + 8 + 1 + 4);
        assert_eq!(&raw[..5], &[1, 0, 0, 0, 1]);
        assert_eq!(&raw[37..41], &[0, 0, 0, 0]);
        assert_eq!(&raw[41..43], &[1, 0x51]);
        assert!(!tx.has_witness());
        // The crediting txid depends on scriptPubKey and amount.
        assert_ne!(
            tx.inputs[0].prev_txid,
            build_spend(&[0x51], &[0x51], vec![], 0).inputs[0].prev_txid
        );
        assert_ne!(
            tx.inputs[0].prev_txid,
            build_spend(&[0x51], &[0x51, 0x87], vec![], 1).inputs[0].prev_txid
        );
    }

    #[test]
    fn loads_each_entry_shape() {
        let json = r#"[
            ["Format is: comment"],
            ["1", "2 EQUALVERIFY 1 EQUAL", "P2SH", "EQUALVERIFY", "fails"],
            ["1", "1 EQUAL", "P2SH,STRICTENC", "OK"],
            ["1", "NOP1", "P2SH,DISCOURAGE_UPGRADABLE_NOPS", "DISCOURAGE_UPGRADABLE_NOPS"],
            [["51", 0.00000001], "", "0 0x20 0x4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260", "P2SH,WITNESS", "OK", "wit"],
            ["1", "1", "WITNESS,MINIMALIF", "OK"]
        ]"#;
        let l = load(json).unwrap();
        assert_eq!(l.comments, 1);
        assert_eq!(l.tests.len(), 4);
        assert_eq!(l.skipped.len(), 1);
        assert_eq!(l.skipped[0].name, "script_tests.json#3");
        assert_eq!(l.skipped[0].reason, SkipReason::PolicyFlags);

        let t = &l.tests[0];
        assert!(!t.expect_valid);
        assert_eq!(t.expected_error.as_deref(), Some("EQUALVERIFY"));
        assert_eq!(t.comment, "fails");
        assert_eq!(t.cases[0].flags, vec![Flag::P2sh]);
        assert_eq!(
            t.cases[0].prevouts[0].script_pubkey_hex,
            "5288 5187".replace(' ', "")
        );

        // Policy flag stripped from an OK vector.
        assert!(l.tests[1].expect_valid);
        assert_eq!(l.tests[1].cases[0].flags, vec![Flag::P2sh]);

        // Witness vector: amount in sats, witness serialized into the tx.
        let w = &l.tests[2].cases[0];
        assert_eq!(w.prevouts[0].amount_sats, 1);
        let tx = Tx::deserialize(&hex::decode(&w.tx_hex).unwrap()).unwrap();
        assert_eq!(tx.inputs[0].witness, vec![vec![0x51]]);
        assert_eq!(tx.outputs[0].value, 1);

        // WITNESS without P2SH after stripping policy flags is trimmed away.
        assert_eq!(l.tests[3].cases[0].flags, vec![]);
        assert_eq!(l.skip_summary().get(&SkipReason::PolicyFlags), Some(&1));
    }

    #[test]
    fn tapscript_placeholders() {
        let json = r##"[[["abcdef", "#SCRIPT# 1 IF SHA256 ENDIF SIZE SWAP DROP 32 EQUAL", "#CONTROLBLOCK#", 0.00000001],
            "", "0x51 0x20 #TAPROOTOUTPUT#", "P2SH,WITNESS,TAPROOT", "OK", "c"]]"##;
        let l = load(json).unwrap();
        let c = &l.tests[0].cases[0];
        assert_eq!(c.flags, vec![Flag::P2sh, Flag::Witness, Flag::Taproot]);
        let tx = Tx::deserialize(&hex::decode(&c.tx_hex).unwrap()).unwrap();
        let w = &tx.inputs[0].witness;
        assert_eq!(w.len(), 3);
        assert_eq!(hex::encode(&w[1]), "5163a868827c750120 87".replace(' ', ""));
        assert_eq!(w[2].len(), 33);
        assert_eq!(w[2][0] & 0xfe, 0xc0);
        assert_eq!(&w[2][1..], &taproot::NUMS_H);
        let spk = hex::decode(&c.prevouts[0].script_pubkey_hex).unwrap();
        assert_eq!(spk.len(), 34);
        assert_eq!(&spk[..2], &[0x51, 0x20]);
        // The output key commits to the script.
        let leaf = taproot::tapleaf_hash(0xc0, &w[1]);
        let (key, odd) = taproot::tweak_output_key(&taproot::NUMS_H, Some(&leaf)).unwrap();
        assert_eq!(&spk[2..], &key);
        assert_eq!(w[2][0] & 1 == 1, odd);

        assert!(load(r##"[[["#CONTROLBLOCK#", 0], "", "1", "", "OK"]]"##).is_err());
        assert!(load(r##"[[["00", 0], "", "0x51 0x20 #TAPROOTOUTPUT#", "", "OK"]]"##).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(load("{}").is_err());
        assert!(load(r#"[["1", "FOO", "", "OK"]]"#).is_err());
        assert!(load(r#"[["1", "1", "WAT", "OK"]]"#).is_err());
        assert!(load(r#"[["1", "1"]]"#).is_err());
    }
}
