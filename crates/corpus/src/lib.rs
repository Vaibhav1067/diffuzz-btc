//! Loaders that turn upstream test vectors into [`Case`]s with an expected verdict.
//!
//! Supported files (formats as in Bitcoin Core's `src/test/data/`):
//!
//! * `script_tests.json`: one script pair per vector; see [`script_tests`].
//! * `tx_valid.json` / `tx_invalid.json`: whole transactions; see [`tx_tests`].
//! * `sighash.json`: legacy signature-hash vectors; see [`sighash`]. These are not script
//!   verification cases and are consumed by the sighash differential instead.
//!
//! The main oracle only runs consensus flags, so vectors that need policy flags are returned as
//! [`Skipped`] with a reason rather than silently dropped.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use diffuzz_types::Case;

pub mod asm;
pub mod script_tests;
pub mod sighash;
pub mod tx_tests;

/// A vector converted to cases, with the verdict the upstream test expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorTest {
    /// Stable identifier: `<file>#<array index>`.
    pub name: String,
    /// Upstream comment, if any.
    pub comment: String,
    /// One case per input that must be checked.
    pub cases: Vec<Case>,
    /// `true`: every case must be accepted. `false`: at least one case must be rejected.
    pub expect_valid: bool,
    /// Upstream's expected script error name (script_tests only), informational.
    pub expected_error: Option<String>,
}

impl VectorTest {
    /// Does a set of per-case accept/reject results satisfy this vector's expectation?
    pub fn satisfied_by(&self, accepted: &[bool]) -> bool {
        if self.expect_valid {
            accepted.iter().all(|a| *a)
        } else {
            accepted.iter().any(|a| !*a)
        }
    }
}

/// A vector that cannot be run by the consensus-only oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Stable identifier: `<file>#<array index>`.
    pub name: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// Why a vector was skipped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    /// The vector's verdict depends on policy/standardness flags.
    PolicyFlags,
    /// tx_invalid vector that fails `CheckTransaction` (marked `BADTX`), not script verification.
    BadTx,
    /// The flag set cannot be given to a consensus library (e.g. WITNESS without P2SH).
    UnsupportedFlagCombination,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SkipReason::PolicyFlags => "depends on policy flags",
            SkipReason::BadTx => "BADTX: fails context-free transaction checks, not script",
            SkipReason::UnsupportedFlagCombination => "flag combination not valid for consensus",
        })
    }
}

/// Result of loading one vector file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    /// Runnable vectors.
    pub tests: Vec<VectorTest>,
    /// Vectors skipped, with reasons.
    pub skipped: Vec<Skipped>,
    /// Comment-only entries in the file.
    pub comments: usize,
}

impl Loaded {
    /// Skip counts grouped by reason.
    pub fn skip_summary(&self) -> BTreeMap<SkipReason, usize> {
        let mut m = BTreeMap::new();
        for s in &self.skipped {
            *m.entry(s.reason.clone()).or_insert(0) += 1;
        }
        m
    }
}

/// A vector file that could not be parsed. This always indicates a bug in the loader or an
/// unexpected upstream format change, never a property of an implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    /// Which entry (`<file>#<index>`) or the file as a whole.
    pub location: String,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

impl std::error::Error for LoadError {}

pub(crate) fn err(location: &str, message: impl Into<String>) -> LoadError {
    LoadError {
        location: location.to_string(),
        message: message.into(),
    }
}

/// Which Core vector format a file uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorKind {
    /// `script_tests.json`
    ScriptTests,
    /// `tx_valid.json`
    TxValid,
    /// `tx_invalid.json`
    TxInvalid,
}

impl VectorKind {
    /// Guess the format from a file name.
    pub fn from_file_name(name: &str) -> Option<VectorKind> {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        match base {
            "script_tests.json" => Some(VectorKind::ScriptTests),
            "tx_valid.json" => Some(VectorKind::TxValid),
            "tx_invalid.json" => Some(VectorKind::TxInvalid),
            _ => None,
        }
    }
}

/// Load a vector file of the given kind from its JSON text.
pub fn load(kind: VectorKind, json: &str) -> Result<Loaded, LoadError> {
    match kind {
        VectorKind::ScriptTests => script_tests::load(json),
        VectorKind::TxValid => tx_tests::load(json, true),
        VectorKind::TxInvalid => tx_tests::load(json, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_from_name() {
        assert_eq!(
            VectorKind::from_file_name("vectors/core/script_tests.json"),
            Some(VectorKind::ScriptTests)
        );
        assert_eq!(
            VectorKind::from_file_name("a\\tx_valid.json"),
            Some(VectorKind::TxValid)
        );
        assert_eq!(
            VectorKind::from_file_name("tx_invalid.json"),
            Some(VectorKind::TxInvalid)
        );
        assert_eq!(VectorKind::from_file_name("sighash.json"), None);
    }

    #[test]
    fn expectation_semantics() {
        let mut t = VectorTest {
            name: "t".into(),
            comment: String::new(),
            cases: vec![],
            expect_valid: true,
            expected_error: None,
        };
        assert!(t.satisfied_by(&[true, true]));
        assert!(!t.satisfied_by(&[true, false]));
        t.expect_valid = false;
        assert!(t.satisfied_by(&[true, false]));
        assert!(!t.satisfied_by(&[true, true]));
    }
}
