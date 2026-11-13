//! The private findings sink.
//!
//! Hard divergences, crashes and timeouts are written as self-contained JSON files to a
//! directory that must not be tracked by git (rule 2: responsible disclosure). The sink refuses
//! to start if the directory is inside a git work tree and not ignored.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use diffuzz_types::tx::sha256d;
use diffuzz_types::{Case, Verdict, hex};
use serde::{Deserialize, Serialize};

use crate::diff::Class;

/// Everything needed to reproduce and triage one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    /// Classification (`HARD_DIVERGE`, `CRASH` or `TIMEOUT`).
    pub class: Class,
    /// Stable hash of the case (see [`case_hash`]).
    pub case_hash: String,
    /// The case itself.
    pub case: Case,
    /// Every implementation's verdict, including its version.
    pub verdicts: Vec<Verdict>,
    /// Generator seed of the run that produced the case, if any.
    pub seed: Option<u64>,
    /// Unix time the finding was recorded.
    pub timestamp_unix: u64,
}

/// Stable identifier of a case: the first 16 hex digits of the double-SHA256 of its transaction,
/// input index, prevouts and sorted flags. `origin` is deliberately excluded so the same case
/// reached twice has the same hash.
pub fn case_hash(case: &Case) -> String {
    let mut flags = case.flags.clone();
    diffuzz_types::normalize_flags(&mut flags);
    let mut data = String::new();
    data.push_str(&case.tx_hex);
    data.push('|');
    data.push_str(&case.input_index.to_string());
    for p in &case.prevouts {
        data.push('|');
        data.push_str(&p.script_pubkey_hex);
        data.push(':');
        data.push_str(&p.amount_sats.to_string());
    }
    for f in flags {
        data.push('|');
        data.push_str(f.name());
    }
    hex::encode(&sha256d(data.as_bytes())[..8])
}

/// Is `dir` safe to write findings to? `Ok(())` if it is outside any git work tree or is
/// ignored by git; an error if git would track files created in it.
pub fn check_untracked(dir: &Path) -> Result<(), String> {
    let probe = dir.join("probe.json");
    let out = Command::new("git")
        .arg("check-ignore")
        .arg("-q")
        .arg(&probe)
        .current_dir(dir)
        .output();
    match out {
        // 0: ignored. 128: not a git repository (or other fatal error). Both are safe.
        Ok(o) => match o.status.code() {
            Some(0) | Some(128) => Ok(()),
            Some(1) => Err(format!(
                "refusing to write findings to {}: the directory is inside a git work tree and \
                 not ignored (findings must stay private until disclosed)",
                dir.display()
            )),
            other => Err(format!("git check-ignore gave unexpected status {other:?}")),
        },
        // git not installed: nothing can be tracked by accident.
        Err(_) => Ok(()),
    }
}

/// Writes finding records to a private directory, one file per distinct case and class.
#[derive(Debug)]
pub struct FindingsSink {
    dir: PathBuf,
    written: u64,
    duplicates: u64,
}

impl FindingsSink {
    /// Create the directory if needed and verify it is not tracked by git.
    pub fn new(dir: impl Into<PathBuf>) -> Result<FindingsSink, String> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        check_untracked(&dir)?;
        Ok(FindingsSink {
            dir,
            written: 0,
            duplicates: 0,
        })
    }

    /// The directory findings are written to.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// New files written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Findings that were already on disk and therefore not rewritten.
    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }

    /// Record a finding. Returns the new file's path, or `None` if this case and class were
    /// already recorded (by this or an earlier run).
    pub fn record(
        &mut self,
        class: Class,
        case: &Case,
        verdicts: &[Verdict],
        seed: Option<u64>,
    ) -> std::io::Result<Option<PathBuf>> {
        let hash = case_hash(case);
        let path = self
            .dir
            .join(format!("{}-{hash}.json", class.name().to_ascii_lowercase()));
        if path.exists() {
            self.duplicates += 1;
            return Ok(None);
        }
        let record = FindingRecord {
            class,
            case_hash: hash,
            case: case.clone(),
            verdicts: verdicts.to_vec(),
            seed,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let json = serde_json::to_string_pretty(&record).map_err(std::io::Error::other)?;
        // Write then rename so a crash never leaves a truncated finding behind.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        self.written += 1;
        Ok(Some(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::{Flag, Outcome, Prevout};

    fn case() -> Case {
        Case {
            tx_hex: "0100".into(),
            input_index: 0,
            prevouts: vec![Prevout {
                script_pubkey_hex: "51".into(),
                amount_sats: 5,
            }],
            flags: vec![Flag::Witness, Flag::P2sh],
            origin: Some("a".into()),
        }
    }

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("diffuzz-findings-{name}-{}", std::process::id()))
    }

    #[test]
    fn hash_is_stable_and_ignores_origin_and_flag_order() {
        let a = case();
        let mut b = case();
        b.origin = None;
        b.flags.reverse();
        assert_eq!(case_hash(&a), case_hash(&b));
        assert_eq!(case_hash(&a).len(), 16);
        let mut c = case();
        c.prevouts[0].amount_sats = 6;
        assert_ne!(case_hash(&a), case_hash(&c));
        let mut d = case();
        d.input_index = 1;
        assert_ne!(case_hash(&a), case_hash(&d));
    }

    #[test]
    fn writes_once_and_round_trips() {
        let dir = tmp("write");
        let _ = std::fs::remove_dir_all(&dir);
        let mut sink = FindingsSink::new(&dir).unwrap();
        let verdicts = vec![Verdict {
            impl_name: "x".into(),
            impl_version: "1".into(),
            outcome: Outcome::Ok,
        }];
        let path = sink
            .record(Class::HardDiverge, &case(), &verdicts, Some(9))
            .unwrap()
            .unwrap();
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("hard_diverge-")
        );
        let rec: FindingRecord =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(rec.class, Class::HardDiverge);
        assert_eq!(rec.case, case());
        assert_eq!(rec.verdicts, verdicts);
        assert_eq!(rec.seed, Some(9));
        assert!(rec.timestamp_unix > 1_700_000_000);

        assert!(
            sink.record(Class::HardDiverge, &case(), &verdicts, None)
                .unwrap()
                .is_none()
        );
        assert_eq!((sink.written(), sink.duplicates()), (1, 1));
        // Same case, different class, is a separate file.
        assert!(
            sink.record(Class::Crash, &case(), &verdicts, None)
                .unwrap()
                .is_some()
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_a_tracked_directory() {
        // Build a throwaway git repository: a plain directory in it is trackable, an ignored
        // one is not. Skip silently if git is unavailable.
        let root = tmp("git");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tracked")).unwrap();
        std::fs::create_dir_all(root.join("private")).unwrap();
        let init = Command::new("git")
            .arg("init")
            .arg("-q")
            .current_dir(&root)
            .status();
        if !matches!(init, Ok(s) if s.success()) {
            return;
        }
        std::fs::write(root.join(".gitignore"), "/private/\n").unwrap();
        assert!(check_untracked(&root.join("private")).is_ok());
        let e = check_untracked(&root.join("tracked")).unwrap_err();
        assert!(e.contains("refusing"), "{e}");
        assert!(FindingsSink::new(root.join("tracked")).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
