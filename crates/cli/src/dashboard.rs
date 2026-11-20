//! `diffuzz dashboard`: a single self-contained HTML results page.
//!
//! Inputs are the machine-readable outputs of other commands: fuzz run summaries
//! (`fuzz --summary`, `run_overnight.sh`'s `summary.json`), a replay summary (`replay --json`)
//! and aux summaries (`aux --json`). They are read into the publishable types below, which
//! deliberately have no field for allowlist entry names, finding paths or case contents: the
//! page cannot leak what its payload cannot hold (rule 2). A run with unexplained divergences is
//! refused outright, since even its per-category counts point at an undisclosed bug. Unknown
//! JSON fields are ignored.
//!
//! The page itself is `assets/dashboard.html`; the payload is embedded as JSON and rendered by
//! the page's own script. No network access is needed to view it.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The HTML template. `__DIFFUZZ_DATA__` (as a JSON string literal) is replaced by the payload.
const TEMPLATE: &str = include_str!("../assets/dashboard.html");
const PLACEHOLDER: &str = "\"__DIFFUZZ_DATA__\"";

/// Per-implementation throughput of one fuzz run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImplRate {
    /// Implementation name.
    pub name: String,
    /// Pinned version string.
    pub version: String,
    /// Cases per second per process.
    pub cases_per_sec_per_process: f64,
    /// Median latency, microseconds.
    pub p50_us: u32,
    /// 99th percentile latency, microseconds.
    pub p99_us: u32,
    /// Process restarts.
    pub restarts: u64,
}

/// One fuzz run, publishable fields only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCard {
    /// Label given on the command line.
    #[serde(default)]
    pub label: String,
    /// Base seed.
    pub seed: u64,
    /// Unix start time.
    pub started_unix: u64,
    /// Duration, seconds.
    pub duration_secs: f64,
    /// Worker threads.
    pub workers: usize,
    /// Cases compared.
    pub cases: u64,
    /// Aggregate cases per second.
    pub cases_per_sec: f64,
    /// Cases per differential class (`AGREE_OK`, `KNOWN`, ...). Aggregate counts only.
    pub classes: BTreeMap<String, u64>,
    /// Per generator category: cases per class.
    #[serde(default)]
    pub by_category: BTreeMap<String, BTreeMap<String, u64>>,
    /// Cases per output type.
    #[serde(default)]
    pub wrappers: BTreeMap<String, u64>,
    /// Why the run stopped (`duration elapsed`, `6 segment(s); ...`).
    #[serde(default)]
    pub stop_reason: String,
    /// Per implementation throughput.
    #[serde(alias = "adapters", default)]
    pub impls: Vec<ImplRate>,
}

/// One implementation's corpus replay result, summed over vector files.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ReplayImpl {
    /// Implementation name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Vectors whose expectation was met.
    pub passed: usize,
    /// Vectors whose expectation was not met.
    pub failed: usize,
    /// Vectors with a documented abstention.
    pub abstained: usize,
    /// Crashes.
    pub crashes: usize,
    /// Timeouts.
    pub timeouts: usize,
}

/// Corpus replay summary (`replay --json`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ReplaySummary {
    /// Vector files replayed.
    pub files: Vec<String>,
    /// Runnable vectors.
    pub vectors: usize,
    /// Cases run per implementation.
    pub cases: usize,
    /// Skipped vectors.
    pub skipped: usize,
    /// Per implementation.
    pub impls: Vec<ReplayImpl>,
    /// Cases per differential class, all files.
    pub classes: BTreeMap<String, usize>,
}

/// One implementation's aux totals.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AuxImpl {
    /// Implementation name.
    pub name: String,
    /// Checks answered.
    pub answered: usize,
    /// Checks abstained.
    pub abstained: usize,
    /// Checks with a wrong expected digest.
    pub wrong: usize,
    /// Crashes and timeouts.
    pub failed: usize,
}

/// Aux summary (`aux --json`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AuxSummary {
    /// Label.
    #[serde(default)]
    pub label: String,
    /// Seed of generated checks (0 when none).
    pub seed: u64,
    /// Generated checks.
    pub generated: u64,
    /// Total checks.
    pub checks: usize,
    /// Per implementation.
    pub impls: Vec<AuxImpl>,
    /// Diverging checks.
    pub divergences: usize,
}

/// Everything the page shows.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Payload {
    /// Free-text description of the machine the runs ran on.
    pub machine: String,
    /// Unix time the page was generated.
    pub generated_unix: u64,
    /// Fuzz runs.
    pub runs: Vec<RunCard>,
    /// Corpus replay, if given.
    pub replay: Option<ReplaySummary>,
    /// Aux runs.
    pub aux: Vec<AuxSummary>,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parse `LABEL=PATH` (or a bare path, labelled by its file stem).
pub fn split_label(arg: &str) -> (String, &Path) {
    match arg.split_once('=') {
        Some((label, path)) if !label.is_empty() && !label.contains(['/', '\\']) => {
            (label.to_string(), Path::new(path))
        }
        _ => {
            // Split on either separator so labels are the same on every platform.
            let name = arg.rsplit(['/', '\\']).next().unwrap_or(arg);
            let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
            (stem.to_string(), Path::new(arg))
        }
    }
}

/// Load a fuzz run summary as a publishable run card.
pub fn load_run(arg: &str) -> Result<RunCard, String> {
    let (label, path) = split_label(arg);
    let mut card: RunCard = read_json(path)?;
    // Even a count says where an undisclosed bug is (rule 2): review it before publishing.
    if card.classes.get("HARD_DIVERGE").is_some_and(|n| *n > 0) {
        return Err(format!(
            "{}: run has unexplained divergences; review findings/private/ first",
            path.display()
        ));
    }
    card.label = label;
    Ok(card)
}

/// Load an aux summary.
pub fn load_aux(arg: &str) -> Result<AuxSummary, String> {
    let (label, path) = split_label(arg);
    let mut s: AuxSummary = read_json(path)?;
    s.label = label;
    Ok(s)
}

/// Load a replay summary.
pub fn load_replay(path: &Path) -> Result<ReplaySummary, String> {
    read_json(path)
}

/// Render the page. `</` is escaped inside the embedded JSON so no string in the payload can
/// close the script element.
pub fn render(payload: &Payload) -> Result<String, String> {
    let json = serde_json::to_string(payload)
        .map_err(|e| e.to_string())?
        .replace("</", "<\\/");
    if !TEMPLATE.contains(PLACEHOLDER) {
        return Err("dashboard template has no data placeholder".into());
    }
    Ok(TEMPLATE.replacen(PLACEHOLDER, &json, 1))
}

/// Replay summary from per-file replay reports.
pub fn replay_summary(files: &[crate::replay::FileReport]) -> ReplaySummary {
    let mut s = ReplaySummary::default();
    let mut impls: Vec<ReplayImpl> = Vec::new();
    for f in files {
        s.files.push(f.file.clone());
        s.vectors += f.tests;
        s.cases += f.cases;
        s.skipped += f.skipped_total();
        for (c, n) in &f.classes {
            *s.classes.entry(c.name().to_string()).or_insert(0) += n;
        }
        for i in &f.impls {
            let entry = match impls.iter_mut().find(|x| x.name == i.name) {
                Some(e) => e,
                None => {
                    impls.push(ReplayImpl {
                        name: i.name.clone(),
                        version: i.version.clone(),
                        ..ReplayImpl::default()
                    });
                    impls.last_mut().expect("just pushed")
                }
            };
            entry.passed += i.passed;
            entry.failed += i.mismatches.len();
            entry.abstained += i.abstained.len();
            entry.crashes += i.crashes;
            entry.timeouts += i.timeouts;
        }
    }
    s.impls = impls;
    s
}

/// Aux summary from an aux report.
pub fn aux_summary(report: &crate::auxcmd::AuxReport, seed: u64, generated: u64) -> AuxSummary {
    AuxSummary {
        label: String::new(),
        seed,
        generated,
        checks: report.checks,
        impls: report
            .impls
            .iter()
            .map(|t| AuxImpl {
                name: t.name.clone(),
                answered: t.answered,
                abstained: t.abstained,
                wrong: t.wrong.len(),
                failed: t.failed,
            })
            .collect(),
        divergences: report.divergences.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMMARY: &str = r#"{"seed":7,"started_unix":1,"duration_secs":2.0,"workers":1,
        "feedback":true,"cases":10,"cases_per_sec":5.0,
        "classes":{"AGREE_OK":6,"AGREE_FAIL":3,"KNOWN":1},
        "known":{"private-secret-entry-id":1},
        "error_classes":{},"by_category":{"gen/sig":{"AGREE_OK":6}},
        "wrappers":{"bare":10},
        "adapters":[{"name":"core","version":"v","cases":10,"cases_per_sec_per_process":5.0,
                     "p50_us":1,"p99_us":2,"restarts":0}],
        "signatures":1,"kept":1,"findings_written":0,"stop_reason":"done"}"#;

    #[test]
    fn private_allowlist_ids_never_reach_the_page() {
        let card: RunCard = serde_json::from_str(SUMMARY).unwrap();
        assert_eq!(card.classes["KNOWN"], 1);
        let html = render(&Payload {
            runs: vec![card],
            ..Payload::default()
        })
        .unwrap();
        assert!(!html.contains("private-secret-entry-id"));
        assert!(!html.contains(PLACEHOLDER));
        assert!(html.contains("\"AGREE_OK\":6"));
        // The page reads `impls`; summaries call the field `adapters`.
        assert!(html.contains("\"impls\":[{\"name\":\"core\""));
    }

    #[test]
    fn runs_with_hard_divergences_are_refused() {
        let dir = std::env::temp_dir().join(format!("diffuzz-dash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("run.json");
        std::fs::write(&path, SUMMARY.replace("\"KNOWN\":1", "\"HARD_DIVERGE\":1")).unwrap();
        let err = load_run(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("findings/private"), "{err}");
        std::fs::write(&path, SUMMARY).unwrap();
        assert!(load_run(path.to_str().unwrap()).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn labels_and_script_escaping() {
        assert_eq!(split_label("A=out/x.json").0, "A");
        assert_eq!(split_label("out/run/summary.json").0, "summary");
        assert_eq!(split_label("C:\\x\\y.json").0, "y");
        let html = render(&Payload {
            machine: "</script><b>".into(),
            ..Payload::default()
        })
        .unwrap();
        assert!(!html.contains("</script><b>"));
    }
}
