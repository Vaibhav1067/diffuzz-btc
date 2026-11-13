//! Process-level tests for the adapter supervisor, driven by the scriptable fake adapter.

#![allow(clippy::unwrap_used)] // test helpers

use std::time::Duration;

use diffuzz_oracle::adapter::{Adapter, AdapterConfig};
use diffuzz_types::{Case, ErrorClass, Outcome};

fn fake(args: &[&str]) -> Adapter {
    let mut cfg = AdapterConfig::new("fake", env!("CARGO_BIN_EXE_diffuzz-fake-adapter"));
    cfg.args = args.iter().map(|s| s.to_string()).collect();
    cfg.timeout = Duration::from_millis(1500);
    Adapter::spawn(cfg).unwrap()
}

fn case(tx_hex: &str) -> Case {
    Case {
        tx_hex: tx_hex.into(),
        input_index: 0,
        prevouts: vec![],
        flags: vec![],
        origin: None,
    }
}

#[test]
fn answers_in_order() {
    let mut a = fake(&[]);
    let v = a.verify(&case("01aa"));
    assert_eq!(v.outcome, Outcome::Ok);
    assert_eq!(v.impl_name, "fake");
    assert_eq!(v.impl_version, "fake-1");
    let v = a.verify(&case("02aa"));
    assert!(matches!(
        v.outcome,
        Outcome::Fail {
            error_class: ErrorClass::EvalFalse,
            ..
        }
    ));

    let batch: Vec<Case> = (0..500)
        .map(|i| case(if i % 3 == 0 { "01" } else { "02" }))
        .collect();
    let verdicts = a.verify_batch(&batch);
    assert_eq!(verdicts.len(), 500);
    for (i, v) in verdicts.iter().enumerate() {
        assert_eq!(v.outcome.accepted(), Some(i % 3 == 0), "case {i}");
    }
    assert_eq!(a.stats().answered, 502);
    assert_eq!(a.stats().restarts, 0);
    assert_eq!(a.version(), "fake-1");
}

#[test]
fn crash_is_isolated_to_one_case_and_adapter_restarts() {
    let mut a = fake(&["crash-on:dead"]);
    let batch = vec![case("01"), case("01dead"), case("02"), case("01")];
    let v = a.verify_batch(&batch);
    assert_eq!(v[0].outcome, Outcome::Ok);
    match &v[1].outcome {
        Outcome::Crash { detail } => assert!(detail.contains("simulated crash"), "{detail}"),
        other => panic!("expected crash, got {other:?}"),
    }
    assert_eq!(v[2].outcome.accepted(), Some(false));
    assert_eq!(v[3].outcome, Outcome::Ok);
    assert_eq!(a.stats().crashes, 1);
    assert_eq!(a.stats().restarts, 1);
    assert_eq!(a.stats().answered, 3);
}

#[test]
fn timeout_is_reported_and_recovered() {
    let mut a = fake(&["hang-on:beef"]);
    let v = a.verify_batch(&[case("01beef"), case("01")]);
    assert_eq!(v[0].outcome, Outcome::Timeout);
    assert_eq!(v[1].outcome, Outcome::Ok);
    assert_eq!(a.stats().timeouts, 1);
    assert_eq!(a.stats().restarts, 1);
}

#[test]
fn garbage_and_wrong_id_are_crashes() {
    let mut a = fake(&["garbage-on:77", "wrong-id-on:88"]);
    let v = a.verify_batch(&[case("0177"), case("0188"), case("01")]);
    assert!(matches!(&v[0].outcome, Outcome::Crash { detail } if detail.contains("unparsable")));
    assert!(matches!(&v[1].outcome, Outcome::Crash { detail } if detail.contains("id mismatch")));
    assert_eq!(v[2].outcome, Outcome::Ok);
    assert_eq!(a.stats().crashes, 2);
}

#[test]
fn repeated_crashes_terminate() {
    let mut a = fake(&["crash-on:01"]);
    let v = a.verify_batch(&[case("01"), case("01"), case("01")]);
    assert_eq!(v.len(), 3);
    assert!(v.iter().all(|v| matches!(v.outcome, Outcome::Crash { .. })));
}
