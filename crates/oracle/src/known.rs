//! Allowlist of known, benign divergences (`known_divergences/*.toml`).
//!
//! An entry downgrades a divergence from `HARD_DIVERGE` to `KNOWN`. Because a too-broad entry
//! would hide real bugs, entries must cite a reference and must state the *direction* of the
//! disagreement, and matching is strict (see [`KnownDivergence::matches`]).
//!
//! ```toml
//! id = "btcd-example"
//! description = "What differs, in one or two sentences."
//! impls_affected = ["btcd"]
//! flags_condition = ["TAPROOT"]          # flags that must all be set; may be empty
//! example_case = "known_divergences/examples/btcd-example.json"
//! reference_url = "https://github.com/btcsuite/btcd/issues/0000"
//! reason = "Why this is benign."
//!
//! [match]
//! accepts = ["core"]                     # implementations that accept
//! rejects = ["btcd"]                     # implementations that reject
//! reject_error_classes = ["SCRIPT_NUM"]  # optional: any-of, for the rejecting affected impls
//! raw_error_contains = "number too big"  # optional
//! ```

use std::path::{Path, PathBuf};

use diffuzz_types::{Case, ErrorClass, Flag, Outcome, Verdict};
use serde::Deserialize;

use crate::diff::vote;

/// The strict part of an entry: which way the disagreement goes and how it presents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    /// Implementations that must have accepted.
    #[serde(default)]
    pub accepts: Vec<String>,
    /// Implementations that must have rejected.
    #[serde(default)]
    pub rejects: Vec<String>,
    /// If non-empty, every rejecting affected implementation must report one of these classes.
    #[serde(default)]
    pub reject_error_classes: Vec<ErrorClass>,
    /// If set, every rejecting affected implementation's raw error must contain this text.
    #[serde(default)]
    pub raw_error_contains: Option<String>,
}

/// One allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownDivergence {
    /// Unique identifier.
    pub id: String,
    /// What differs.
    pub description: String,
    /// Implementations whose behaviour is the documented deviation.
    pub impls_affected: Vec<String>,
    /// Flags that must all be set on the case for the entry to apply.
    #[serde(default)]
    pub flags_condition: Vec<Flag>,
    /// Path (relative to the repository root) of a minimal example case.
    pub example_case: String,
    /// Citation: upstream issue, PR, documentation or spec text.
    pub reference_url: String,
    /// Why the difference is benign.
    pub reason: String,
    /// Direction and presentation of the disagreement.
    #[serde(rename = "match")]
    pub matcher: Matcher,
}

impl KnownDivergence {
    /// Check the entry is complete: no empty required field, a real URL, a declared direction.
    pub fn validate(&self) -> Result<(), String> {
        let required = [
            ("id", &self.id),
            ("description", &self.description),
            ("example_case", &self.example_case),
            ("reference_url", &self.reference_url),
            ("reason", &self.reason),
        ];
        for (field, value) in required {
            if value.trim().is_empty() {
                return Err(format!("{}: field `{field}` must not be empty", self.id));
            }
        }
        if !(self.reference_url.starts_with("https://")
            || self.reference_url.starts_with("http://"))
        {
            return Err(format!("{}: reference_url must be an http(s) URL", self.id));
        }
        if self.impls_affected.is_empty() {
            return Err(format!("{}: impls_affected must not be empty", self.id));
        }
        if self.matcher.accepts.is_empty() || self.matcher.rejects.is_empty() {
            return Err(format!(
                "{}: [match] must name both `accepts` and `rejects` implementations",
                self.id
            ));
        }
        if self
            .matcher
            .accepts
            .iter()
            .any(|a| self.matcher.rejects.contains(a))
        {
            return Err(format!(
                "{}: an implementation is in both accepts and rejects",
                self.id
            ));
        }
        Ok(())
    }

    /// Does this entry explain the divergence seen for `case`?
    ///
    /// All of the following must hold:
    ///
    /// 1. every flag in `flags_condition` is set on the case;
    /// 2. every implementation listed in `accepts` voted accept and every one in `rejects`
    ///    voted reject (an implementation that is absent or abstained fails the match);
    /// 3. the implementations *not* in `impls_affected` are unanimous, so the affected ones
    ///    account for the whole disagreement;
    /// 4. the optional error-class and raw-error filters hold for every affected rejecter.
    pub fn matches(&self, case: &Case, verdicts: &[Verdict]) -> bool {
        if !self.flags_condition.iter().all(|f| case.flags.contains(f)) {
            return false;
        }
        let vote_of = |name: &String| {
            verdicts
                .iter()
                .find(|v| &v.impl_name == name)
                .and_then(vote)
        };
        if !self
            .matcher
            .accepts
            .iter()
            .all(|n| vote_of(n) == Some(true))
        {
            return false;
        }
        if !self
            .matcher
            .rejects
            .iter()
            .all(|n| vote_of(n) == Some(false))
        {
            return false;
        }
        let mut others = verdicts
            .iter()
            .filter(|v| !self.impls_affected.contains(&v.impl_name))
            .filter_map(vote);
        if let Some(first) = others.next()
            && others.any(|o| o != first)
        {
            return false;
        }
        for v in verdicts
            .iter()
            .filter(|v| self.impls_affected.contains(&v.impl_name))
        {
            if let Outcome::Fail {
                error_class,
                raw_error,
            } = &v.outcome
            {
                if !self.matcher.reject_error_classes.is_empty()
                    && !self.matcher.reject_error_classes.contains(error_class)
                {
                    return false;
                }
                if let Some(needle) = &self.matcher.raw_error_contains
                    && !raw_error.contains(needle.as_str())
                {
                    return false;
                }
            }
        }
        true
    }
}

/// The loaded allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    entries: Vec<KnownDivergence>,
}

impl Allowlist {
    /// An allowlist with no entries: every divergence is a hard divergence.
    pub fn empty() -> Allowlist {
        Allowlist::default()
    }

    /// Build from already-parsed entries, validating each and rejecting duplicate ids.
    pub fn from_entries(entries: Vec<KnownDivergence>) -> Result<Allowlist, String> {
        for (i, e) in entries.iter().enumerate() {
            e.validate()?;
            if entries[..i].iter().any(|o| o.id == e.id) {
                return Err(format!("duplicate known-divergence id {}", e.id));
            }
        }
        Ok(Allowlist { entries })
    }

    /// Parse one TOML document holding a single entry.
    pub fn parse_entry(text: &str) -> Result<KnownDivergence, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// Load every `*.toml` file in `dir` (sorted by name). A missing directory is an empty
    /// allowlist. `root` is the directory `example_case` paths are relative to; each example
    /// file must exist.
    pub fn load_dir(dir: &Path, root: &Path) -> Result<Allowlist, String> {
        let mut paths: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "toml"))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        paths.sort();
        let mut entries = Vec::new();
        for p in paths {
            let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            let entry = Self::parse_entry(&text).map_err(|e| format!("{}: {e}", p.display()))?;
            if !root.join(&entry.example_case).is_file() {
                return Err(format!(
                    "{}: example_case {} does not exist",
                    p.display(),
                    entry.example_case
                ));
            }
            entries.push(entry);
        }
        Self::from_entries(entries)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries, in load order.
    pub fn entries(&self) -> &[KnownDivergence] {
        &self.entries
    }

    /// The first entry that explains this divergence, if any.
    pub fn find(&self, case: &Case, verdicts: &[Verdict]) -> Option<&KnownDivergence> {
        self.entries.iter().find(|e| e.matches(case, verdicts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = r#"
id = "btcd-example"
description = "btcd rejects something Core accepts."
impls_affected = ["btcd"]
flags_condition = ["TAPROOT"]
example_case = "examples/btcd-example.json"
reference_url = "https://example.org/issue/1"
reason = "Documented upstream."

[match]
accepts = ["core"]
rejects = ["btcd"]
reject_error_classes = ["SCRIPT_NUM"]
raw_error_contains = "too big"
"#;

    fn case(flags: Vec<Flag>) -> Case {
        Case {
            tx_hex: "00".into(),
            input_index: 0,
            prevouts: vec![],
            flags,
            origin: None,
        }
    }

    fn ok(name: &str) -> Verdict {
        Verdict {
            impl_name: name.into(),
            impl_version: "1".into(),
            outcome: Outcome::Ok,
        }
    }

    fn fail(name: &str, class: ErrorClass, raw: &str) -> Verdict {
        Verdict {
            impl_name: name.into(),
            impl_version: "1".into(),
            outcome: Outcome::Fail {
                error_class: class,
                raw_error: raw.into(),
            },
        }
    }

    fn entry() -> KnownDivergence {
        Allowlist::parse_entry(ENTRY).unwrap()
    }

    #[test]
    fn parses_and_validates() {
        let e = entry();
        assert_eq!(e.id, "btcd-example");
        assert_eq!(e.flags_condition, vec![Flag::Taproot]);
        assert_eq!(e.matcher.reject_error_classes, vec![ErrorClass::ScriptNum]);
        e.validate().unwrap();
        assert_eq!(Allowlist::from_entries(vec![e.clone()]).unwrap().len(), 1);
        assert!(
            Allowlist::from_entries(vec![e.clone(), e])
                .unwrap_err()
                .contains("duplicate")
        );
    }

    #[test]
    fn validation_rejects_incomplete_entries() {
        let mut e = entry();
        e.reference_url = "see the mailing list".into();
        assert!(e.validate().unwrap_err().contains("reference_url"));
        let mut e = entry();
        e.reason = "  ".into();
        assert!(e.validate().unwrap_err().contains("reason"));
        let mut e = entry();
        e.matcher.accepts.clear();
        assert!(e.validate().unwrap_err().contains("accepts"));
        let mut e = entry();
        e.matcher.rejects = vec!["core".into()];
        assert!(e.validate().unwrap_err().contains("both"));
        let mut e = entry();
        e.impls_affected.clear();
        assert!(e.validate().is_err());
        // No citation at all is a parse error, as is an unknown field.
        assert!(Allowlist::parse_entry(&ENTRY.replace("reference_url", "ref")).is_err());
        assert!(Allowlist::parse_entry(&ENTRY.replace("[match]", "")).is_err());
    }

    #[test]
    fn strict_matching() {
        let e = entry();
        let good = [
            ok("core"),
            fail("btcd", ErrorClass::ScriptNum, "number too big"),
        ];
        assert!(e.matches(&case(vec![Flag::P2sh, Flag::Taproot]), &good));
        // Flag condition not met.
        assert!(!e.matches(&case(vec![Flag::P2sh]), &good));
        // Opposite direction.
        let reversed = [fail("core", ErrorClass::ScriptFail, ""), ok("btcd")];
        assert!(!e.matches(&case(vec![Flag::Taproot]), &reversed));
        // Wrong error class or text.
        let other_class = [
            ok("core"),
            fail("btcd", ErrorClass::EvalFalse, "number too big"),
        ];
        assert!(!e.matches(&case(vec![Flag::Taproot]), &other_class));
        let other_text = [
            ok("core"),
            fail("btcd", ErrorClass::ScriptNum, "something else"),
        ];
        assert!(!e.matches(&case(vec![Flag::Taproot]), &other_text));
        // An implementation named in the matcher is missing or abstained.
        assert!(!e.matches(&case(vec![Flag::Taproot]), &[ok("core")]));
        let abstained = [ok("core"), fail("btcd", ErrorClass::Unsupported, "too big")];
        assert!(!e.matches(&case(vec![Flag::Taproot]), &abstained));
    }

    #[test]
    fn unaffected_implementations_must_agree() {
        let e = entry();
        let c = case(vec![Flag::Taproot]);
        let third_agrees = [
            ok("core"),
            fail("btcd", ErrorClass::ScriptNum, "too big"),
            ok("libbitcoin"),
        ];
        assert!(e.matches(&c, &third_agrees));
        // A third implementation siding with btcd means the entry does not explain it.
        let third_dissents = [
            ok("core"),
            fail("btcd", ErrorClass::ScriptNum, "too big"),
            fail("libbitcoin", ErrorClass::EvalFalse, ""),
        ];
        assert!(!e.matches(&c, &third_dissents));
    }

    #[test]
    fn find_and_load_dir() {
        let list = Allowlist::from_entries(vec![entry()]).unwrap();
        let c = case(vec![Flag::Taproot]);
        let v = [ok("core"), fail("btcd", ErrorClass::ScriptNum, "too big")];
        assert_eq!(
            list.find(&c, &v).map(|e| e.id.as_str()),
            Some("btcd-example")
        );
        assert!(Allowlist::empty().find(&c, &v).is_none());
        assert!(Allowlist::empty().is_empty());

        let root = std::env::temp_dir().join(format!("diffuzz-known-{}", std::process::id()));
        let dir = root.join("known");
        std::fs::create_dir_all(root.join("examples")).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.toml"), ENTRY).unwrap();
        std::fs::write(dir.join("README.md"), "ignored").unwrap();
        // Example file missing.
        assert!(
            Allowlist::load_dir(&dir, &root)
                .unwrap_err()
                .contains("does not exist")
        );
        std::fs::write(root.join("examples/btcd-example.json"), "{}").unwrap();
        let loaded = Allowlist::load_dir(&dir, &root).unwrap();
        assert_eq!(loaded.entries().len(), 1);
        // Missing directory is simply empty.
        assert!(
            Allowlist::load_dir(&root.join("nope"), &root)
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
