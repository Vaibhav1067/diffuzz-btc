//! Phase 6 acceptance: an artificial bug (an adapter with a deliberately wrong flag mapping)
//! must be detected by differential comparison, minimized to a small case, bucketed as one
//! root cause, and reported with everything needed to reproduce it.
//!
//! The two "implementations" are both Bitcoin Core, called in-process. The buggy one drops the
//! NULLDUMMY flag before verifying, i.e. it behaves like an adapter whose flag table forgot
//! BIP147.

#![allow(clippy::unwrap_used)]

use diffuzz_gen::generators::{Generator, Mix, Weights};
use diffuzz_gen::rng::Rng;
use diffuzz_triage::bucket::{Finding, bucketize, vote_pattern};
use diffuzz_triage::report::{export_tx_vector, render};
use diffuzz_types::tx::Tx;
use diffuzz_types::{Case, ErrorClass, Flag, Outcome, Request, Verdict, hex};

fn core_verdict(name: &str, req: &Request) -> Verdict {
    let outcome = match diffuzz_adapter_core::verify(req) {
        Ok(()) => Outcome::Ok,
        Err((error_class, raw_error)) => Outcome::Fail {
            error_class,
            raw_error,
        },
    };
    Verdict {
        impl_name: name.into(),
        impl_version: "test".into(),
        outcome,
    }
}

/// Honest Core next to a Core whose adapter "forgot" to map NULLDUMMY.
fn run(case: &Case) -> Vec<Verdict> {
    let honest = case.to_request(1);
    let mut buggy = honest.clone();
    buggy.flags.retain(|f| *f != Flag::Nulldummy);
    vec![core_verdict("core", &honest), core_verdict("buggy", &buggy)]
}

fn diverges(verdicts: &[Verdict]) -> bool {
    verdicts[0].outcome.accepted() != verdicts[1].outcome.accepted()
}

#[test]
fn injected_flag_bug_is_detected_minimized_bucketed_and_reported() {
    // 1. Detect: ordinary generated cases, no hints about the bug.
    let mix = Mix::new(Weights::default(), Vec::new());
    let mut rng = Rng::new(20_261_114);
    let mut findings = Vec::new();
    let mut executed = 0;
    while findings.len() < 12 && executed < 60_000 {
        let case = mix.generate(&mut rng);
        executed += 1;
        let verdicts = run(&case);
        if diverges(&verdicts) {
            findings.push(Finding {
                case,
                verdicts,
                source: format!("case-{executed}"),
            });
        }
    }
    assert!(
        findings.len() >= 12,
        "only {} divergences in {executed} cases: the generators do not reach the bug",
        findings.len()
    );
    for f in &findings {
        assert_eq!(vote_pattern(&f.verdicts), "core=FAIL buggy=OK");
        assert!(f.case.flags.contains(&Flag::Nulldummy));
    }

    // 2. Minimize and bucket.
    let buckets = bucketize(&findings, &mut run, 6, 4_000);
    assert_eq!(
        buckets.len(),
        1,
        "one root cause must give one bucket: {buckets:#?}"
    );
    let b = &buckets[0];
    assert_eq!(b.count, findings.len());
    assert_eq!(b.key, "core=FAIL buggy=OK [core:SCRIPT_FAIL]");
    assert!(
        diverges(&b.verdicts),
        "the representative must still diverge"
    );

    // 3. The representative is small and readable.
    let min = &b.representative;
    assert_eq!(
        min.flags,
        vec![Flag::Nulldummy],
        "only the relevant flag survives"
    );
    let tx = Tx::deserialize(&hex::decode(&min.tx_hex).unwrap()).unwrap();
    assert_eq!(tx.inputs.len(), 1);
    assert!(tx.outputs.is_empty());
    assert!(tx.inputs[0].witness.is_empty());
    let spk = hex::decode(&min.prevouts[0].script_pubkey_hex).unwrap();
    assert!(
        spk.contains(&0xae) || spk.contains(&0xaf),
        "CHECKMULTISIG must remain: {spk:02x?}"
    );
    let total = min.tx_hex.len() / 2 + spk.len();
    assert!(total <= 80, "minimized case is {total} bytes: {min:?}");
    assert!(
        b.stats.bytes_after * 2 < b.stats.bytes_before,
        "{:?}",
        b.stats
    );
    // Every minimized sample kept exactly the relevant opcode and flag. Samples whose spend
    // needs valid segwit signatures cannot be unwrapped (the minimizer does not re-sign), so
    // the output type may still differ between samples; the representative is the bare one.
    assert!(
        b.variants
            .keys()
            .all(|k| k.contains("NULLDUMMY") && k.contains("CHECKMULTISIG")),
        "{:?}",
        b.variants
    );
    assert!(
        b.variants
            .keys()
            .any(|k| k.starts_with("bare | flags: NULLDUMMY |"))
    );

    // 4. Report and export.
    let report = render(
        &buckets,
        "core,buggy",
        &["findings/private/minimized/x.json".into()],
    );
    for needle in [
        "1 bucket(s)",
        "core=FAIL buggy=OK",
        "CHECKMULTISIG",
        "flags: `NULLDUMMY`",
        "| core | test | rejects: SCRIPT_FAIL",
        "| buggy | test | accepts |",
        "diffuzz check --case findings/private/minimized/x.json --impls core,buggy",
    ] {
        assert!(
            report.contains(needle),
            "report lacks {needle:?}:\n{report}"
        );
    }
    // Core (the reference) rejects, so this is a tx_invalid-style vector.
    let vector = export_tx_vector(min, false).unwrap();
    assert!(vector.contains("\"NULLDUMMY\""), "{vector}");
    let parsed: serde_json::Value = serde_json::from_str(&vector).unwrap();
    assert_eq!(parsed[1].as_str().unwrap(), min.tx_hex);

    // 5. Determinism: the whole pipeline gives the same answer again.
    let again = bucketize(&findings, &mut run, 6, 4_000);
    assert_eq!(again, buckets);
    let _ = ErrorClass::ScriptFail;
}
