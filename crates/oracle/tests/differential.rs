//! End-to-end tests of the differential runner using fake adapters, including the
//! "adapter that lies" case required by the Phase 3 acceptance criteria.

#![allow(clippy::unwrap_used)] // test helpers

use std::path::PathBuf;
use std::time::Duration;

use diffuzz_oracle::adapter::{Adapter, AdapterConfig};
use diffuzz_oracle::diff::Class;
use diffuzz_oracle::findings::{FindingRecord, FindingsSink};
use diffuzz_oracle::known::Allowlist;
use diffuzz_oracle::runner::Differential;
use diffuzz_types::{Case, Flag, Outcome};

fn fake(name: &str, args: &[&str]) -> Adapter {
    let mut cfg = AdapterConfig::new(name, env!("CARGO_BIN_EXE_diffuzz-fake-adapter"));
    cfg.args = args.iter().map(|s| s.to_string()).collect();
    cfg.args.push(format!("name:{name}"));
    cfg.timeout = Duration::from_millis(1500);
    Adapter::spawn(cfg).unwrap()
}

fn case(tx_hex: &str) -> Case {
    Case {
        tx_hex: tx_hex.into(),
        input_index: 0,
        prevouts: vec![],
        flags: vec![Flag::P2sh],
        origin: Some("test".into()),
    }
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("diffuzz-diff-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn honest_adapters_agree() {
    let mut d = Differential::new(
        vec![fake("honest", &[]), fake("other", &[])],
        Allowlist::empty(),
        None,
    );
    let cases: Vec<Case> = (0..300)
        .map(|i| case(if i % 2 == 0 { "01" } else { "02" }))
        .collect();
    let results = d.run_batch(&cases);
    assert_eq!(results.len(), 300);
    for (i, r) in results.iter().enumerate() {
        let want = if i % 2 == 0 {
            Class::AgreeOk
        } else {
            Class::AgreeFail
        };
        assert_eq!(r.class, want, "case {i}");
        assert_eq!(r.verdicts.len(), 2);
        assert_eq!(r.verdicts[0].impl_name, "honest");
        assert_eq!(r.verdicts[1].impl_name, "other");
    }
    assert_eq!(d.metrics.cases, 300);
    assert_eq!(d.metrics.count(Class::AgreeOk), 150);
    assert_eq!(d.metrics.count(Class::AgreeFail), 150);
    assert_eq!(d.metrics.adapters[0].cases, 300);
    assert_eq!(d.adapter_names(), vec!["honest", "other"]);
}

#[test]
fn lying_adapter_is_detected_and_routed_to_private_findings() {
    let dir = tmp("liar");
    let sink = FindingsSink::new(&dir).unwrap();
    let mut d = Differential::new(
        vec![fake("honest", &[]), fake("liar", &["lie-on:beef"])],
        Allowlist::empty(),
        Some(sink),
    );
    d.set_seed(Some(1234));
    d.set_quiet(true);

    let results = d.run_batch(&[case("01"), case("01beef"), case("02"), case("02beef")]);
    assert_eq!(results[0].class, Class::AgreeOk);
    assert_eq!(results[1].class, Class::HardDiverge);
    assert_eq!(results[2].class, Class::AgreeFail);
    assert_eq!(results[3].class, Class::HardDiverge);
    assert_eq!(d.metrics.count(Class::HardDiverge), 2);

    // Both divergences are on disk, self-contained, with versions and the seed.
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 2);
    assert_eq!(d.sink().unwrap().written(), 2);
    let mut seen = Vec::new();
    for f in &files {
        assert!(
            f.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("hard_diverge-")
        );
        let rec: FindingRecord =
            serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        assert_eq!(rec.class, Class::HardDiverge);
        assert_eq!(rec.seed, Some(1234));
        assert_eq!(rec.verdicts.len(), 2);
        assert!(rec.verdicts.iter().all(|v| v.impl_version == "fake-1"));
        assert_ne!(
            rec.verdicts[0].outcome.accepted(),
            rec.verdicts[1].outcome.accepted()
        );
        seen.push(rec.case.tx_hex.clone());
    }
    seen.sort();
    assert_eq!(seen, vec!["01beef", "02beef"]);

    // Seeing the same divergence again does not write another file.
    d.run_batch(&[case("01beef")]);
    assert_eq!(d.sink().unwrap().written(), 2);
    assert_eq!(d.sink().unwrap().duplicates(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn allowlisted_divergence_is_known_and_not_written() {
    let dir = tmp("known");
    let entry = Allowlist::parse_entry(
        r#"
id = "liar-rejects-beef"
description = "The fake liar rejects valid cases containing beef."
impls_affected = ["liar"]
flags_condition = ["P2SH"]
example_case = "examples/liar.json"
reference_url = "https://example.org/liar"
reason = "Synthetic test entry."

[match]
accepts = ["honest"]
rejects = ["liar"]
reject_error_classes = ["EVAL_FALSE"]
"#,
    )
    .unwrap();
    let allow = Allowlist::from_entries(vec![entry]).unwrap();
    let mut d = Differential::new(
        vec![fake("honest", &[]), fake("liar", &["lie-on:beef"])],
        allow,
        Some(FindingsSink::new(&dir).unwrap()),
    );
    d.set_quiet(true);

    // "01beef": honest accepts, liar rejects -> matches the entry.
    // "02beef": honest rejects, liar accepts -> opposite direction, still a hard divergence.
    let results = d.run_batch(&[case("01beef"), case("02beef")]);
    assert_eq!(results[0].class, Class::Known);
    assert_eq!(results[0].known_id.as_deref(), Some("liar-rejects-beef"));
    assert_eq!(results[1].class, Class::HardDiverge);
    assert_eq!(d.metrics.known.get("liar-rejects-beef"), Some(&1));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn crash_and_timeout_are_separate_classes() {
    let dir = tmp("crash");
    let mut d = Differential::new(
        vec![
            fake("honest", &[]),
            fake("fragile", &["crash-on:dead", "hang-on:feed"]),
        ],
        Allowlist::empty(),
        Some(FindingsSink::new(&dir).unwrap()),
    );
    d.set_quiet(true);
    let results = d.run_batch(&[case("01dead"), case("01"), case("01feed"), case("02")]);
    assert_eq!(results[0].class, Class::Crash);
    assert!(matches!(
        results[0].verdicts[1].outcome,
        Outcome::Crash { .. }
    ));
    assert_eq!(results[1].class, Class::AgreeOk);
    assert_eq!(results[2].class, Class::Timeout);
    assert_eq!(results[3].class, Class::AgreeFail);
    assert_eq!(d.metrics.adapters[1].restarts, 2);

    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.iter().filter(|n| n.starts_with("crash-")).count(), 1);
    assert_eq!(
        names.iter().filter(|n| n.starts_with("timeout-")).count(),
        1
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn three_way_minority_is_a_divergence() {
    let mut d = Differential::new(
        vec![fake("a", &[]), fake("b", &[]), fake("c", &["lie-on:beef"])],
        Allowlist::empty(),
        None,
    );
    d.set_quiet(true);
    let results = d.run_batch(&[case("01beef"), case("01")]);
    assert_eq!(results[0].class, Class::HardDiverge);
    assert_eq!(results[1].class, Class::AgreeOk);
}
