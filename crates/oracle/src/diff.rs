//! Classification of one case's verdicts across implementations.

use diffuzz_types::{Outcome, Verdict};
use serde::{Deserialize, Serialize};

/// Final classification of a case after allowlist matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Class {
    /// Every voting implementation accepted.
    AgreeOk,
    /// Every voting implementation rejected.
    AgreeFail,
    /// Implementations disagree, and the disagreement matches a documented benign entry.
    Known,
    /// Implementations disagree with no allowlist match. Triggers the disclosure rule.
    HardDiverge,
    /// At least one adapter crashed on the case.
    Crash,
    /// At least one adapter timed out on the case (and none crashed).
    Timeout,
    /// Fewer than two implementations gave a verdict (the others abstained), so there is
    /// nothing to compare.
    Undecided,
}

impl Class {
    /// Wire/report name, e.g. `"HARD_DIVERGE"`.
    pub fn name(self) -> &'static str {
        match self {
            Class::AgreeOk => "AGREE_OK",
            Class::AgreeFail => "AGREE_FAIL",
            Class::Known => "KNOWN",
            Class::HardDiverge => "HARD_DIVERGE",
            Class::Crash => "CRASH",
            Class::Timeout => "TIMEOUT",
            Class::Undecided => "UNDECIDED",
        }
    }

    /// True for classes that are written to the private findings directory.
    pub fn is_finding(self) -> bool {
        matches!(self, Class::HardDiverge | Class::Crash | Class::Timeout)
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Classification before the allowlist is consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawClass {
    /// Every voter accepted.
    AgreeOk,
    /// Every voter rejected.
    AgreeFail,
    /// Voters disagree.
    Diverge,
    /// An adapter crashed.
    Crash,
    /// An adapter timed out.
    Timeout,
    /// Fewer than two voters.
    Undecided,
}

/// An implementation's vote: `Some(accepted)` if it gave a verdict, `None` if it abstained
/// (unsupported flags or case shape), crashed or timed out.
pub fn vote(v: &Verdict) -> Option<bool> {
    match &v.outcome {
        Outcome::Ok => Some(true),
        Outcome::Fail { error_class, .. } if error_class.is_abstention() => None,
        Outcome::Fail { .. } => Some(false),
        Outcome::Crash { .. } | Outcome::Timeout => None,
    }
}

/// Classify the verdicts of all implementations for one case.
///
/// Crashes take precedence over timeouts, which take precedence over accept/reject comparison:
/// a crash is a finding in its own right and must never be hidden by an agreement among the
/// remaining implementations.
pub fn classify(verdicts: &[Verdict]) -> RawClass {
    if verdicts
        .iter()
        .any(|v| matches!(v.outcome, Outcome::Crash { .. }))
    {
        return RawClass::Crash;
    }
    if verdicts
        .iter()
        .any(|v| matches!(v.outcome, Outcome::Timeout))
    {
        return RawClass::Timeout;
    }
    let votes: Vec<bool> = verdicts.iter().filter_map(vote).collect();
    if votes.len() < 2 {
        return RawClass::Undecided;
    }
    match (votes.iter().all(|a| *a), votes.iter().all(|a| !*a)) {
        (true, _) => RawClass::AgreeOk,
        (_, true) => RawClass::AgreeFail,
        _ => RawClass::Diverge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::ErrorClass;

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
            raw_error: String::new(),
        }
    }

    #[test]
    fn agreement() {
        assert_eq!(
            classify(&[v("a", Outcome::Ok), v("b", Outcome::Ok)]),
            RawClass::AgreeOk
        );
        assert_eq!(
            classify(&[
                v("a", fail(ErrorClass::EvalFalse)),
                v("b", fail(ErrorClass::ScriptFail))
            ]),
            RawClass::AgreeFail,
            "different error classes are still agreement: only ok is compared"
        );
        assert_eq!(
            classify(&[
                v("a", Outcome::Ok),
                v("b", Outcome::Ok),
                v("c", Outcome::Ok)
            ]),
            RawClass::AgreeOk
        );
    }

    #[test]
    fn divergence() {
        assert_eq!(
            classify(&[v("a", Outcome::Ok), v("b", fail(ErrorClass::EvalFalse))]),
            RawClass::Diverge
        );
        assert_eq!(
            classify(&[
                v("a", fail(ErrorClass::EvalFalse)),
                v("b", fail(ErrorClass::EvalFalse)),
                v("c", Outcome::Ok)
            ]),
            RawClass::Diverge
        );
    }

    #[test]
    fn crash_and_timeout_take_precedence() {
        let crash = Outcome::Crash { detail: "x".into() };
        assert_eq!(
            classify(&[v("a", Outcome::Ok), v("b", crash.clone())]),
            RawClass::Crash
        );
        assert_eq!(
            classify(&[v("a", Outcome::Ok), v("b", Outcome::Timeout)]),
            RawClass::Timeout
        );
        assert_eq!(
            classify(&[v("a", Outcome::Timeout), v("b", crash)]),
            RawClass::Crash
        );
        // Even when the other two disagree, the crash is what gets reported.
        assert_eq!(
            classify(&[
                v("a", Outcome::Ok),
                v("b", fail(ErrorClass::EvalFalse)),
                v(
                    "c",
                    Outcome::Crash {
                        detail: String::new()
                    }
                )
            ]),
            RawClass::Crash
        );
    }

    #[test]
    fn abstentions_do_not_vote() {
        assert_eq!(
            classify(&[v("a", Outcome::Ok), v("b", fail(ErrorClass::InvalidFlags))]),
            RawClass::Undecided
        );
        assert_eq!(
            classify(&[
                v("a", Outcome::Ok),
                v("b", fail(ErrorClass::Unsupported)),
                v("c", Outcome::Ok)
            ]),
            RawClass::AgreeOk
        );
        assert_eq!(
            classify(&[
                v("a", Outcome::Ok),
                v("b", fail(ErrorClass::Unsupported)),
                v("c", fail(ErrorClass::EvalFalse))
            ]),
            RawClass::Diverge
        );
        assert_eq!(classify(&[]), RawClass::Undecided);
        assert_eq!(classify(&[v("a", Outcome::Ok)]), RawClass::Undecided);
        assert_eq!(vote(&v("a", fail(ErrorClass::Unsupported))), None);
        assert_eq!(vote(&v("a", fail(ErrorClass::Deserialize))), Some(false));
    }

    #[test]
    fn names_and_finding_classes() {
        assert_eq!(Class::HardDiverge.to_string(), "HARD_DIVERGE");
        assert_eq!(
            serde_json::to_string(&Class::AgreeOk).unwrap(),
            "\"AGREE_OK\""
        );
        for c in [Class::HardDiverge, Class::Crash, Class::Timeout] {
            assert!(c.is_finding());
        }
        for c in [
            Class::AgreeOk,
            Class::AgreeFail,
            Class::Known,
            Class::Undecided,
        ] {
            assert!(!c.is_finding());
        }
    }
}
