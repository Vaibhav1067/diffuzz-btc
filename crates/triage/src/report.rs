//! Human-readable report of divergence buckets, and export of a case in Bitcoin Core's
//! transaction test-vector format.

use std::fmt::Write as _;

use diffuzz_types::script::{disassemble, instructions, opcode_from_vector_name, opcode_name};
use diffuzz_types::tx::Tx;
use diffuzz_types::{Case, Flag, Outcome, Verdict, hex};

use crate::bucket::Bucket;
use crate::features::parts;

fn outcome_text(v: &Verdict) -> String {
    match &v.outcome {
        Outcome::Ok => "accepts".to_string(),
        Outcome::Fail {
            error_class,
            raw_error,
        } => {
            format!(
                "rejects: {error_class} ({})",
                raw_error.lines().next().unwrap_or("")
            )
        }
        Outcome::Crash { detail } => format!("CRASH: {}", detail.lines().next().unwrap_or("")),
        Outcome::Timeout => "TIMEOUT".to_string(),
    }
}

/// Render one case: flags, hex, and a disassembly of every script involved.
pub fn describe_case(case: &Case) -> String {
    let mut s = String::new();
    let p = parts(case);
    let flags: Vec<&str> = case.flags.iter().map(|f| f.name()).collect();
    let _ = writeln!(s, "- output type: `{}`", p.wrapper);
    let _ = writeln!(
        s,
        "- flags: `{}`",
        if flags.is_empty() {
            "NONE".into()
        } else {
            flags.join(",")
        }
    );
    let _ = writeln!(s, "- input index: {}", case.input_index);
    let _ = writeln!(s, "- transaction: `{}`", case.tx_hex);
    for (i, prev) in case.prevouts.iter().enumerate() {
        let _ = writeln!(
            s,
            "- prevout {i}: {} sat, scriptPubKey `{}`",
            prev.amount_sats, prev.script_pubkey_hex
        );
    }
    let _ = writeln!(s, "\n```");
    let _ = writeln!(s, "scriptPubKey : {}", disassemble(&p.script_pubkey));
    let _ = writeln!(s, "scriptSig    : {}", disassemble(&p.script_sig));
    if let Some(r) = &p.redeem_script {
        let _ = writeln!(s, "redeemScript : {}", disassemble(r));
    }
    if let Some(w) = &p.witness_script {
        let _ = writeln!(s, "witnessScript: {}", disassemble(w));
    }
    for (i, item) in p.witness.iter().enumerate() {
        let shown = if item.is_empty() {
            "<>".to_string()
        } else {
            hex::encode(item)
        };
        let _ = writeln!(s, "witness[{i}]   : {shown}");
    }
    let _ = writeln!(s, "```");
    s
}

/// Render the full report. `repro_impls` is the `--impls` value to show in reproduction
/// commands; `case_paths[i]` is where bucket `i`'s representative was saved.
pub fn render(buckets: &[Bucket], repro_impls: &str, case_paths: &[String]) -> String {
    let mut s = String::new();
    let total: usize = buckets.iter().map(|b| b.count).sum();
    let _ = writeln!(s, "# Divergence report\n");
    let _ = writeln!(s, "{total} finding(s) in {} bucket(s).\n", buckets.len());
    if buckets.is_empty() {
        let _ = writeln!(s, "Nothing to report.");
        return s;
    }
    let _ = writeln!(s, "| # | Findings | Signature |");
    let _ = writeln!(s, "|---:|---:|---|");
    for (i, b) in buckets.iter().enumerate() {
        let _ = writeln!(s, "| {} | {} | `{}` |", i + 1, b.count, b.key);
    }
    for (i, b) in buckets.iter().enumerate() {
        let _ = writeln!(s, "\n## Bucket {}: `{}`\n", i + 1, b.key);
        let _ = writeln!(
            s,
            "{} finding(s); {} minimized. Representative reduced from {} to {} bytes in {} oracle calls.\n",
            b.count, b.minimized, b.stats.bytes_before, b.stats.bytes_after, b.stats.attempts
        );
        let _ = writeln!(s, "### Verdicts\n");
        let _ = writeln!(s, "| Implementation | Version | Verdict |");
        let _ = writeln!(s, "|---|---|---|");
        for v in &b.verdicts {
            let _ = writeln!(
                s,
                "| {} | {} | {} |",
                v.impl_name,
                v.impl_version,
                outcome_text(v).replace('|', "\\|")
            );
        }
        let _ = writeln!(s, "\n### Minimal case\n");
        s.push_str(&describe_case(&b.representative));
        if !b.variants.is_empty() {
            let _ = writeln!(s, "\n### Variants among minimized samples\n");
            for (sig, n) in &b.variants {
                let _ = writeln!(s, "- {n} x `{sig}`");
            }
        }
        let _ = writeln!(s, "\n### Reproduce\n");
        let path = case_paths
            .get(i)
            .map(String::as_str)
            .unwrap_or("<case.json>");
        let _ = writeln!(
            s,
            "```\ndiffuzz check --case {path} --impls {repro_impls}\n```"
        );
        if !b.sources.is_empty() {
            let _ = writeln!(s, "\nExample sources: {}", b.sources.join(", "));
        }
    }
    s
}

/// Render a script in the syntax of Core's JSON vectors such that Core's `ParseScript` (and
/// `diffuzz_corpus::asm::parse_script`) reproduces the exact bytes.
pub fn to_vector_asm(script: &[u8]) -> String {
    let (ins, _) = instructions(script);
    let mut parts: Vec<String> = Vec::new();
    let mut parsed_end = 0;
    for ins_i in &ins {
        let prefix_len = match ins_i.opcode {
            0x4c => 2,
            0x4d => 3,
            0x4e => 5,
            _ => 1,
        };
        match ins_i.data {
            Some(data) => {
                // Push opcode and length bytes as raw hex, then the data as raw hex: this keeps
                // non-minimal pushes exactly as they are.
                let prefix = &script[ins_i.offset..ins_i.offset + prefix_len];
                parts.push(format!("0x{}", hex::encode(prefix)));
                if !data.is_empty() {
                    parts.push(format!("0x{}", hex::encode(data)));
                }
                parsed_end = ins_i.offset + prefix_len + data.len();
            }
            None => {
                parts.push(match ins_i.opcode {
                    0x00 => "0".to_string(),
                    0x4f => "-1".to_string(),
                    o @ 0x51..=0x60 => (o - 0x50).to_string(),
                    o => match opcode_name(o).filter(|n| opcode_from_vector_name(n) == Some(o)) {
                        Some(name) => name.to_string(),
                        None => format!("0x{o:02x}"),
                    },
                });
                parsed_end = ins_i.offset + 1;
            }
        }
    }
    // Anything after the last complete instruction (a truncated push), verbatim.
    if parsed_end < script.len() {
        parts.push(format!("0x{}", hex::encode(&script[parsed_end..])));
    }
    parts.join(" ")
}

/// A case in the format of Core's `tx_valid.json` / `tx_invalid.json`:
/// `[[[prevout_txid, index, scriptPubKey, amount], ...], tx_hex, flags]`.
///
/// For a valid vector `flags` lists the consensus flags to *exclude* (those not set on the
/// case); for an invalid one, the flags under which it must fail. Core's own tests also run
/// policy flags for valid vectors, so a valid export must be checked with Core's test suite
/// before it is proposed upstream. Returns `None` if the case cannot be decoded.
pub fn export_tx_vector(case: &Case, valid: bool) -> Option<String> {
    let tx = Tx::deserialize(&hex::decode(&case.tx_hex)?).ok()?;
    if tx.inputs.len() != case.prevouts.len() {
        return None;
    }
    let mut prevouts = Vec::new();
    for (input, prev) in tx.inputs.iter().zip(&case.prevouts) {
        let mut txid = input.prev_txid;
        txid.reverse();
        let index = if input.prev_vout == 0xffff_ffff {
            -1
        } else {
            i64::from(input.prev_vout)
        };
        let asm = to_vector_asm(&hex::decode(&prev.script_pubkey_hex)?);
        prevouts.push(format!(
            "[\"{}\", {index}, \"{asm}\", {}]",
            hex::encode(&txid),
            prev.amount_sats
        ));
    }
    let name = |f: &Flag| match f {
        Flag::Cltv => "CHECKLOCKTIMEVERIFY",
        Flag::Csv => "CHECKSEQUENCEVERIFY",
        other => other.name(),
    };
    let flags: Vec<&str> = if valid {
        Flag::CONSENSUS
            .iter()
            .filter(|f| !case.flags.contains(f))
            .map(name)
            .collect()
    } else {
        case.flags.iter().map(name).collect()
    };
    let flags = if flags.is_empty() {
        "NONE".to_string()
    } else {
        flags.join(",")
    };
    Some(format!(
        "[[{}],\n\"{}\", \"{flags}\"]",
        prevouts.join(",\n  "),
        case.tx_hex
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bucket::{Finding, bucketize};
    use diffuzz_types::tx::{TxIn, TxOut};
    use diffuzz_types::{ErrorClass, Prevout};

    fn case(spk: &[u8]) -> Case {
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_txid: {
                    let mut t = [0u8; 32];
                    t[0] = 0xaa;
                    t
                },
                prev_vout: 1,
                script_sig: vec![0x51],
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut::default()],
            lock_time: 0,
        };
        Case {
            tx_hex: hex::encode(&tx.serialize()),
            input_index: 0,
            prevouts: vec![Prevout {
                script_pubkey_hex: hex::encode(spk),
                amount_sats: 7,
            }],
            flags: vec![Flag::P2sh, Flag::Cltv],
            origin: None,
        }
    }

    #[test]
    fn vector_asm_round_trips() {
        let scripts: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00, 0x4f, 0x51, 0x60],
            vec![0x76, 0xa9, 0x02, 0xaa, 0xbb, 0x88, 0xac],
            vec![0x4c, 0x01, 0x07, 0x4d, 0x02, 0x00, 0x01, 0x02],
            vec![0xba, 0xbb, 0xff, 0x50, 0x4c, 0x00],
            vec![0x51, 0x05, 0x01],       // truncated direct push
            vec![0x61, 0x4c],             // truncated PUSHDATA1
            vec![0x4e, 0xff, 0xff],       // truncated PUSHDATA4 header
            vec![0x02, 0xaa, 0xbb, 0x4d], // complete push then truncated
        ];
        for s in scripts {
            let asm = to_vector_asm(&s);
            let back = diffuzz_corpus_asm(&asm);
            assert_eq!(back, s, "asm {asm:?}");
        }
        assert_eq!(
            to_vector_asm(&[0x76, 0xa9, 0x02, 0xaa, 0xbb, 0x88, 0xac]),
            "DUP HASH160 0x02 0xaabb EQUALVERIFY CHECKSIG"
        );
        assert_eq!(to_vector_asm(&[0x00, 0x4f, 0x60, 0xba]), "0 -1 16 0xba");
    }

    /// A tiny re-implementation of the vector syntax, enough for the tokens we emit, so this
    /// crate does not depend on the corpus crate just for a test.
    fn diffuzz_corpus_asm(asm: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for tok in asm.split(' ').filter(|t| !t.is_empty()) {
            if let Some(h) = tok.strip_prefix("0x") {
                out.extend(hex::decode(h).unwrap());
            } else if let Ok(n) = tok.parse::<i64>() {
                diffuzz_types::script::push_int(&mut out, n);
            } else {
                out.push(opcode_from_vector_name(tok).unwrap());
            }
        }
        out
    }

    #[test]
    fn exports_tx_vectors() {
        let c = case(&[0x76, 0xac]);
        let invalid = export_tx_vector(&c, false).unwrap();
        assert!(
            invalid.contains("\"P2SH,CHECKLOCKTIMEVERIFY\""),
            "{invalid}"
        );
        // Display byte order: the 0xaa first byte ends up last.
        assert!(
            invalid.contains("00aa\", 1, \"DUP CHECKSIG\", 7]"),
            "{invalid}"
        );
        assert!(invalid.contains(&c.tx_hex));
        let json: serde_json::Value = serde_json::from_str(&invalid).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 3);

        let valid = export_tx_vector(&c, true).unwrap();
        assert!(
            valid.contains("\"DERSIG,NULLDUMMY,CHECKSEQUENCEVERIFY,WITNESS,TAPROOT\""),
            "{valid}"
        );
        let mut all = c.clone();
        all.flags = Flag::CONSENSUS.to_vec();
        assert!(export_tx_vector(&all, true).unwrap().contains("\"NONE\""));
        let mut bad = c;
        bad.tx_hex = "00".into();
        assert!(export_tx_vector(&bad, true).is_none());
    }

    #[test]
    fn report_contains_everything_needed_to_act() {
        let run = |c: &Case| {
            let spk = hex::decode(&c.prevouts[0].script_pubkey_hex).unwrap();
            let b = if spk.contains(&0xac) {
                Outcome::Fail {
                    error_class: ErrorClass::SigDer,
                    raw_error: "bad | sig\nmore".into(),
                }
            } else {
                Outcome::Ok
            };
            vec![
                Verdict {
                    impl_name: "core".into(),
                    impl_version: "26.0".into(),
                    outcome: Outcome::Ok,
                },
                Verdict {
                    impl_name: "btcd".into(),
                    impl_version: "v2".into(),
                    outcome: b,
                },
            ]
        };
        let c = case(&[0x61, 0x76, 0xac]);
        let findings = vec![Finding {
            verdicts: run(&c),
            case: c,
            source: "f1.json".into(),
        }];
        let buckets = bucketize(&findings, &mut { run }, 2, 1_000);
        let text = render(&buckets, "core,btcd", &["min/a.json".to_string()]);
        for needle in [
            "1 finding(s) in 1 bucket(s)",
            "core=OK btcd=FAIL [btcd:SIG_DER]",
            "| btcd | v2 | rejects: SIG_DER (bad \\| sig) |",
            "| core | 26.0 | accepts |",
            "scriptPubKey : CHECKSIG",
            "diffuzz check --case min/a.json --impls core,btcd",
            "Example sources: f1.json",
            "output type: `bare`",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
        assert!(render(&[], "x", &[]).contains("Nothing to report"));
    }
}
