//! Bucketing: turn thousands of diverging cases into a handful of root causes.
//!
//! Findings are first grouped coarsely by *how the implementations disagree* (who accepts, who
//! rejects, with which error class). A sample of each group is then minimized, and the
//! minimized cases are described by a fine signature (output type, flags, opcode set). So
//! 10,000 hits of one root cause show up as one bucket with a count and a minimal
//! representative, while the fine signatures reveal whether a bucket hides several variants.

use std::collections::BTreeMap;

use diffuzz_minimize::{Stats, minimize};
use diffuzz_types::{Case, Outcome, Verdict};

use crate::features::{opcode_set, wrapper_type};

/// One saved finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The case.
    pub case: Case,
    /// Every implementation's verdict when the finding was recorded.
    pub verdicts: Vec<Verdict>,
    /// Where it came from (file name), for the report.
    pub source: String,
}

fn vote_label(v: &Verdict) -> &'static str {
    match &v.outcome {
        Outcome::Ok => "OK",
        Outcome::Fail { error_class, .. } if error_class.is_abstention() => "ABSTAIN",
        Outcome::Fail { .. } => "FAIL",
        Outcome::Crash { .. } => "CRASH",
        Outcome::Timeout => "TIMEOUT",
    }
}

/// The accept/reject pattern, e.g. `core=OK btcd=FAIL`. Two results with the same pattern are
/// "the same divergence" for minimization purposes.
pub fn vote_pattern(verdicts: &[Verdict]) -> String {
    verdicts
        .iter()
        .map(|v| format!("{}={}", v.impl_name, vote_label(v)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Coarse bucket key: the vote pattern plus each rejecting implementation's error class.
pub fn coarse_key(verdicts: &[Verdict]) -> String {
    let errors: Vec<String> = verdicts
        .iter()
        .filter_map(|v| match &v.outcome {
            Outcome::Fail { error_class, .. } => Some(format!("{}:{error_class}", v.impl_name)),
            _ => None,
        })
        .collect();
    format!("{} [{}]", vote_pattern(verdicts), errors.join(" "))
}

/// Fine signature of a (minimized) case: output type, flags and opcode set.
pub fn fine_key(case: &Case) -> String {
    let mut flags = case.flags.clone();
    diffuzz_types::normalize_flags(&mut flags);
    let flags: Vec<&str> = flags.iter().map(|f| f.name()).collect();
    format!(
        "{} | flags: {} | opcodes: {}",
        wrapper_type(case),
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(",")
        },
        {
            let names = opcode_set(case).names();
            if names.is_empty() {
                "none".to_string()
            } else {
                names
            }
        }
    )
}

/// A group of findings with one root-cause signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// Coarse key shared by every finding in the bucket.
    pub key: String,
    /// Number of findings.
    pub count: usize,
    /// The smallest minimized case.
    pub representative: Case,
    /// Verdicts for the representative (re-verified after minimization).
    pub verdicts: Vec<Verdict>,
    /// Fine signatures of the minimized samples, with how many samples had each.
    pub variants: BTreeMap<String, usize>,
    /// How many findings were minimized (the rest were only counted).
    pub minimized: usize,
    /// Minimizer statistics for the representative.
    pub stats: Stats,
    /// A few source names, for traceability.
    pub sources: Vec<String>,
}

fn case_size(case: &Case) -> usize {
    case.tx_hex.len()
        + case
            .prevouts
            .iter()
            .map(|p| p.script_pubkey_hex.len())
            .sum::<usize>()
}

/// Group `findings` into buckets, minimizing up to `per_bucket` findings of each.
///
/// `run` evaluates a case on every implementation; it is used both to confirm that a finding
/// still reproduces and as the minimizer's oracle ("same vote pattern"). Findings that no
/// longer reproduce are placed in a bucket keyed `NOT REPRODUCED`. Buckets are returned largest
/// first.
pub fn bucketize(
    findings: &[Finding],
    run: &mut dyn FnMut(&Case) -> Vec<Verdict>,
    per_bucket: usize,
    max_attempts: u64,
) -> Vec<Bucket> {
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        groups.entry(coarse_key(&f.verdicts)).or_default().push(f);
    }

    let mut buckets = Vec::new();
    let mut stale: Vec<&Finding> = Vec::new();
    for (key, mut group) in groups {
        // Smallest first: cheap to minimize and most likely already near-minimal.
        group.sort_by_key(|f| (case_size(&f.case), f.source.clone()));
        let mut best: Option<(Case, Vec<Verdict>, Stats)> = None;
        let mut variants: BTreeMap<String, usize> = BTreeMap::new();
        let mut minimized = 0;
        let mut stale_here = 0;
        for f in group.iter().take(per_bucket.max(1)) {
            let pattern = vote_pattern(&f.verdicts);
            if vote_pattern(&run(&f.case)) != pattern {
                stale.push(f);
                stale_here += 1;
                continue;
            }
            let (min, stats) = minimize(
                &f.case,
                &mut |c| vote_pattern(&run(c)) == pattern,
                max_attempts,
            );
            minimized += 1;
            *variants.entry(fine_key(&min)).or_insert(0) += 1;
            let better = best
                .as_ref()
                .is_none_or(|(b, _, _)| case_size(&min) < case_size(b));
            if better {
                let verdicts = run(&min);
                best = Some((min, verdicts, stats));
            }
        }
        let Some((representative, verdicts, stats)) = best else {
            continue;
        };
        buckets.push(Bucket {
            key,
            count: group.len() - stale_here,
            representative,
            verdicts,
            variants,
            minimized,
            stats,
            sources: group.iter().take(5).map(|f| f.source.clone()).collect(),
        });
    }
    if let Some(first) = stale.first() {
        buckets.push(Bucket {
            key: "NOT REPRODUCED".to_string(),
            count: stale.len(),
            representative: first.case.clone(),
            verdicts: run(&first.case),
            variants: BTreeMap::new(),
            minimized: 0,
            stats: Stats::default(),
            sources: stale.iter().take(5).map(|f| f.source.clone()).collect(),
        });
    }
    buckets.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
    buckets
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::tx::{Tx, TxIn, TxOut};
    use diffuzz_types::{ErrorClass, Flag, Prevout, hex};

    fn v(name: &str, outcome: Outcome) -> Verdict {
        Verdict {
            impl_name: name.into(),
            impl_version: "1".into(),
            outcome,
        }
    }

    fn fail(class: ErrorClass) -> Outcome {
        Outcome::Fail {
            error_class: class,
            raw_error: "raw".into(),
        }
    }

    fn case(spk: &[u8], filler: usize) -> Case {
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                script_sig: vec![0x51; filler],
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
                amount_sats: 0,
            }],
            flags: vec![Flag::P2sh, Flag::Witness],
            origin: None,
        }
    }

    /// Fake implementations: "a" accepts everything; "b" rejects scripts containing 0xac with
    /// SIG_DER and scripts containing 0x6a with OP_RETURN.
    fn run(case: &Case) -> Vec<Verdict> {
        let spk = hex::decode(&case.prevouts[0].script_pubkey_hex).unwrap();
        let b = if spk.contains(&0xac) {
            fail(ErrorClass::SigDer)
        } else if spk.contains(&0x6a) {
            fail(ErrorClass::OpReturn)
        } else {
            Outcome::Ok
        };
        vec![v("a", Outcome::Ok), v("b", b)]
    }

    #[test]
    fn keys() {
        let verdicts = vec![v("core", Outcome::Ok), v("btcd", fail(ErrorClass::SigDer))];
        assert_eq!(vote_pattern(&verdicts), "core=OK btcd=FAIL");
        assert_eq!(coarse_key(&verdicts), "core=OK btcd=FAIL [btcd:SIG_DER]");
        let odd = vec![
            v("a", Outcome::Timeout),
            v(
                "b",
                Outcome::Crash {
                    detail: String::new(),
                },
            ),
            v("c", fail(ErrorClass::Unsupported)),
        ];
        assert_eq!(vote_pattern(&odd), "a=TIMEOUT b=CRASH c=ABSTAIN");
        let c = case(&[0x76, 0xac], 0);
        assert_eq!(
            fine_key(&c),
            "bare | flags: P2SH,WITNESS | opcodes: DUP CHECKSIG"
        );
        let mut plain = case(&[0x51], 0);
        plain.flags.clear();
        assert_eq!(fine_key(&plain), "bare | flags: none | opcodes: none");
    }

    #[test]
    fn many_hits_of_one_cause_become_one_bucket() {
        let mut findings = Vec::new();
        for i in 0..40 {
            let c = case(&[0x61, 0x76, 0xac, 0x61, 0x51], i);
            findings.push(Finding {
                verdicts: run(&c),
                case: c,
                source: format!("der-{i}"),
            });
        }
        for i in 0..3 {
            let c = case(&[0x51, 0x6a], i);
            findings.push(Finding {
                verdicts: run(&c),
                case: c,
                source: format!("ret-{i}"),
            });
        }
        let buckets = bucketize(&findings, &mut run, 4, 5_000);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].count, 40);
        assert_eq!(buckets[0].key, "a=OK b=FAIL [b:SIG_DER]");
        assert_eq!(buckets[0].minimized, 4);
        assert_eq!(
            buckets[0].representative.prevouts[0].script_pubkey_hex,
            "ac"
        );
        assert!(buckets[0].representative.flags.is_empty());
        assert_eq!(buckets[0].variants.len(), 1, "{:?}", buckets[0].variants);
        assert_eq!(vote_pattern(&buckets[0].verdicts), "a=OK b=FAIL");
        assert_eq!(buckets[0].sources.len(), 5);
        assert_eq!(buckets[1].count, 3);
        assert_eq!(
            buckets[1].representative.prevouts[0].script_pubkey_hex,
            "6a"
        );
    }

    #[test]
    fn findings_that_no_longer_reproduce_are_reported_separately() {
        let c = case(&[0x51], 0);
        // Recorded as a divergence, but the implementations now agree.
        let recorded = vec![v("a", Outcome::Ok), v("b", fail(ErrorClass::EvalFalse))];
        let findings = vec![Finding {
            case: c,
            verdicts: recorded,
            source: "old".into(),
        }];
        let buckets = bucketize(&findings, &mut run, 3, 100);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].key, "NOT REPRODUCED");
        assert_eq!(buckets[0].count, 1);
        assert!(bucketize(&[], &mut run, 3, 100).is_empty());
    }
}
