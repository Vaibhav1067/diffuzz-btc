//! `diffuzz replay`: run upstream vector files through adapters and compare each adapter's
//! verdicts with the verdict the vector expects.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use diffuzz_corpus::{Loaded, SkipReason, VectorKind, VectorTest};
use diffuzz_oracle::diff::Class;
use diffuzz_oracle::runner::Differential;
use diffuzz_types::{Case, Outcome, Verdict};

/// Requests pipelined to an adapter at once.
const BATCH: usize = 256;

/// A vector whose expectation an implementation did not meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// Vector name (`file#index`).
    pub name: String,
    /// Upstream comment.
    pub comment: String,
    /// What the vector expects.
    pub expect_valid: bool,
    /// Upstream expected error name, if any.
    pub expected_error: Option<String>,
    /// One line per case: what the implementation said.
    pub got: Vec<String>,
}

/// One implementation's results for one vector file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImplReport {
    /// Implementation name.
    pub name: String,
    /// Implementation version string reported by the adapter.
    pub version: String,
    /// Vectors whose expectation was met.
    pub passed: usize,
    /// Vectors whose expectation was not met.
    pub mismatches: Vec<Mismatch>,
    /// Cases that crashed the adapter.
    pub crashes: usize,
    /// Cases that timed out.
    pub timeouts: usize,
}

/// Results for one vector file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileReport {
    /// File path as given.
    pub file: String,
    /// Runnable vectors.
    pub tests: usize,
    /// Cases executed per implementation.
    pub cases: usize,
    /// Comment-only entries.
    pub comments: usize,
    /// Skipped vectors by reason.
    pub skipped: BTreeMap<SkipReason, usize>,
    /// Per-implementation results.
    pub impls: Vec<ImplReport>,
    /// Cases per differential class (how the implementations compare with each other).
    pub classes: BTreeMap<Class, usize>,
    /// Matches per allowlist entry.
    pub known: BTreeMap<String, usize>,
}

impl FileReport {
    /// True if every implementation met every expectation and no case was a hard divergence,
    /// crash or timeout.
    pub fn clean(&self) -> bool {
        self.impls.iter().all(|i| i.mismatches.is_empty())
            && self.classes.keys().all(|c| !c.is_finding())
    }

    /// Total skipped vectors.
    pub fn skipped_total(&self) -> usize {
        self.skipped.values().sum()
    }
}

fn describe(v: &Verdict) -> String {
    match &v.outcome {
        Outcome::Ok => "OK".to_string(),
        Outcome::Fail {
            error_class,
            raw_error,
        } => format!("FAIL {error_class} ({raw_error})"),
        Outcome::Crash { detail } => format!("CRASH ({detail})"),
        Outcome::Timeout => "TIMEOUT".to_string(),
    }
}

/// Score one implementation's verdicts (one per case, in `tests` order) against expectations.
pub fn score(tests: &[VectorTest], verdicts: &[Verdict], name: &str) -> ImplReport {
    let mut report = ImplReport {
        name: name.to_string(),
        ..ImplReport::default()
    };
    let mut pos = 0;
    for t in tests {
        let vs = &verdicts[pos..pos + t.cases.len()];
        pos += t.cases.len();
        let mut accepted = Vec::with_capacity(vs.len());
        let mut broken = false;
        for v in vs {
            if !v.impl_version.is_empty() {
                report.version.clone_from(&v.impl_version);
            }
            match v.outcome.accepted() {
                Some(a) => accepted.push(a),
                None => {
                    broken = true;
                    match v.outcome {
                        Outcome::Timeout => report.timeouts += 1,
                        _ => report.crashes += 1,
                    }
                }
            }
        }
        // A crash or timeout never counts as meeting an expectation, even "invalid".
        if !broken && t.satisfied_by(&accepted) {
            report.passed += 1;
        } else {
            report.mismatches.push(Mismatch {
                name: t.name.clone(),
                comment: t.comment.clone(),
                expect_valid: t.expect_valid,
                expected_error: t.expected_error.clone(),
                got: vs.iter().map(describe).collect(),
            });
        }
    }
    report
}

/// Run every case of `loaded` through all adapters of `diff`, score each implementation
/// against the expected verdicts, and tally the differential classes.
pub fn run(file: &str, loaded: &Loaded, diff: &mut Differential) -> FileReport {
    let cases: Vec<Case> = loaded
        .tests
        .iter()
        .flat_map(|t| t.cases.iter().cloned())
        .collect();
    let names = diff.adapter_names();
    let mut report = FileReport {
        file: file.to_string(),
        tests: loaded.tests.len(),
        cases: cases.len(),
        comments: loaded.comments,
        skipped: loaded.skip_summary(),
        ..FileReport::default()
    };
    let mut per_impl: Vec<Vec<Verdict>> = vec![Vec::with_capacity(cases.len()); names.len()];
    for chunk in cases.chunks(BATCH) {
        for result in diff.run_batch(chunk) {
            *report.classes.entry(result.class).or_insert(0) += 1;
            if let Some(id) = result.known_id {
                *report.known.entry(id).or_insert(0) += 1;
            }
            for (i, v) in result.verdicts.into_iter().enumerate() {
                per_impl[i].push(v);
            }
        }
    }
    for (name, verdicts) in names.iter().zip(&per_impl) {
        report.impls.push(score(&loaded.tests, verdicts, name));
    }
    report
}

/// Load a vector file from disk, inferring its format from the file name.
pub fn load_file(path: &Path) -> Result<Loaded, String> {
    let shown = path.display();
    let kind = VectorKind::from_file_name(&path.to_string_lossy()).ok_or_else(|| {
        format!("{shown}: unknown vector file (expected script_tests/tx_valid/tx_invalid .json)")
    })?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?;
    diffuzz_corpus::load(kind, &text).map_err(|e| format!("{shown}: {e}"))
}

/// Human-readable summary of a file report. `max_listed` caps the mismatches printed per impl.
pub fn render(report: &FileReport, max_listed: usize) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "== {} ==", report.file);
    let _ = writeln!(
        s,
        "vectors: {} runnable ({} cases), {} skipped, {} comment entries",
        report.tests,
        report.cases,
        report.skipped_total(),
        report.comments
    );
    for (reason, n) in &report.skipped {
        let _ = writeln!(s, "  skipped {n}: {reason}");
    }
    for i in &report.impls {
        let _ = writeln!(
            s,
            "[{}] {}: total {}, passed {}, failed {}, crashes {}, timeouts {}",
            i.name,
            if i.version.is_empty() {
                "(no version)"
            } else {
                &i.version
            },
            report.tests,
            i.passed,
            i.mismatches.len(),
            i.crashes,
            i.timeouts
        );
        for m in i.mismatches.iter().take(max_listed) {
            let want = match (&m.expected_error, m.expect_valid) {
                (_, true) => "OK".to_string(),
                (Some(e), false) => format!("FAIL {e}"),
                (None, false) => "FAIL".to_string(),
            };
            let _ = writeln!(
                s,
                "  MISMATCH {} expected {want}; got {}",
                m.name,
                m.got.join(" | ")
            );
            if !m.comment.is_empty() {
                let _ = writeln!(s, "    comment: {}", m.comment);
            }
        }
        if i.mismatches.len() > max_listed {
            let _ = writeln!(s, "  ... and {} more", i.mismatches.len() - max_listed);
        }
    }
    if report.impls.len() > 1 {
        let classes: Vec<String> = report
            .classes
            .iter()
            .map(|(c, n)| format!("{c} {n}"))
            .collect();
        let _ = writeln!(
            s,
            "differential ({} cases): {}",
            report.cases,
            classes.join(", ")
        );
        for (id, n) in &report.known {
            let _ = writeln!(s, "  known divergence {id}: {n}");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::ErrorClass;

    fn test(name: &str, n_cases: usize, expect_valid: bool) -> VectorTest {
        let case = Case {
            tx_hex: "00".into(),
            input_index: 0,
            prevouts: vec![],
            flags: vec![],
            origin: None,
        };
        VectorTest {
            name: name.into(),
            comment: "c".into(),
            cases: vec![case; n_cases],
            expect_valid,
            expected_error: (!expect_valid).then(|| "EVAL_FALSE".to_string()),
        }
    }

    fn verdict(outcome: Outcome) -> Verdict {
        Verdict {
            impl_name: "x".into(),
            impl_version: "v1".into(),
            outcome,
        }
    }

    fn fail() -> Outcome {
        Outcome::Fail {
            error_class: ErrorClass::EvalFalse,
            raw_error: "r".into(),
        }
    }

    #[test]
    fn scoring() {
        let tests = vec![
            test("a", 2, true),
            test("b", 2, false),
            test("c", 1, true),
            test("d", 1, false),
        ];
        let verdicts = vec![
            verdict(Outcome::Ok),
            verdict(Outcome::Ok), // a: pass
            verdict(Outcome::Ok),
            verdict(fail()),           // b: pass (one input rejected)
            verdict(fail()),           // c: mismatch
            verdict(Outcome::Timeout), // d: timeout is not a pass
        ];
        let r = score(&tests, &verdicts, "x");
        assert_eq!(r.passed, 2);
        assert_eq!(r.version, "v1");
        assert_eq!(r.timeouts, 1);
        assert_eq!(r.mismatches.len(), 2);
        assert_eq!(r.mismatches[0].name, "c");
        assert_eq!(r.mismatches[0].got, vec!["FAIL EVAL_FALSE (r)"]);
        assert_eq!(r.mismatches[1].got, vec!["TIMEOUT"]);

        let report = FileReport {
            file: "f".into(),
            tests: 4,
            cases: 6,
            comments: 1,
            skipped: BTreeMap::from([(SkipReason::PolicyFlags, 3)]),
            impls: vec![r.clone(), r],
            classes: BTreeMap::from([(Class::AgreeOk, 4), (Class::AgreeFail, 2)]),
            known: BTreeMap::new(),
        };
        assert!(!report.clean());
        assert_eq!(report.skipped_total(), 3);
        let text = render(&report, 1);
        assert!(text.contains("total 4, passed 2, failed 2"), "{text}");
        assert!(
            text.contains("MISMATCH c expected OK; got FAIL EVAL_FALSE (r)"),
            "{text}"
        );
        assert!(text.contains("... and 1 more"), "{text}");
        assert!(
            text.contains("skipped 3: depends on policy flags"),
            "{text}"
        );
        assert!(
            text.contains("differential (6 cases): AGREE_OK 4, AGREE_FAIL 2"),
            "{text}"
        );

        let mut diverged = report.clone();
        diverged.impls.iter_mut().for_each(|i| i.mismatches.clear());
        assert!(diverged.clean());
        diverged.classes.insert(Class::HardDiverge, 1);
        assert!(!diverged.clean(), "a hard divergence must fail the run");
    }

    #[test]
    fn crash_in_invalid_vector_is_not_a_pass() {
        let tests = vec![test("b", 1, false)];
        let r = score(
            &tests,
            &[verdict(Outcome::Crash {
                detail: "boom".into(),
            })],
            "x",
        );
        assert_eq!(r.passed, 0);
        assert_eq!(r.crashes, 1);
    }

    #[test]
    fn load_file_errors() {
        assert!(
            load_file(Path::new("nope.json"))
                .unwrap_err()
                .contains("unknown vector file")
        );
        assert!(load_file(Path::new("does/not/exist/tx_valid.json")).is_err());
    }
}
