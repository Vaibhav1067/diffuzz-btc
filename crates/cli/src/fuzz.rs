//! `diffuzz fuzz`: generate cases, run them through the differential oracle on several worker
//! threads, and steer generation with a cheap feedback signal.
//!
//! The targets are not instrumented, so "coverage" is approximated: a case is *interesting* if
//! it reaches a new `(error classes, opcode set, output type)` tuple. Interesting cases are kept
//! and later mutated.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use diffuzz_gen::generators::{Generator, Mix, Weights, category};
use diffuzz_gen::rng::Rng;
use diffuzz_oracle::diff::Class;
use diffuzz_oracle::runner::{CaseResult, Differential};
use diffuzz_triage::features::{OpcodeSet, opcode_set, wrapper_type};
use diffuzz_types::{Case, Outcome};
use serde::Serialize;

/// Cases per batch sent to each adapter.
pub const BATCH: usize = 256;
/// Upper bound on the kept set, to bound memory on long runs.
const MAX_KEPT: usize = 20_000;

/// Everything `diffuzz fuzz` needs to know.
pub struct FuzzConfig {
    /// Base seed. Worker `w` uses an independent stream derived from it.
    pub seed: u64,
    /// Stop after this many cases (rounded up to a whole batch per worker).
    pub count: Option<u64>,
    /// Stop after this long.
    pub duration: Option<Duration>,
    /// Number of worker threads, each with its own set of adapter processes.
    pub workers: usize,
    /// Generator weights.
    pub weights: Weights,
    /// Seed cases for the mutator.
    pub seeds: Vec<Case>,
    /// Keep interesting cases and mutate them.
    pub feedback: bool,
    /// Stop the whole run at the first hard divergence (rule 2).
    pub stop_on_divergence: bool,
    /// Stop if more than this many finding files were written (protects the disk).
    pub max_findings: u64,
    /// Print progress this often.
    pub report_every: Duration,
}

/// The feedback tuple.
type Signature = (String, OpcodeSet, &'static str);

/// Per-adapter totals in the summary.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct AdapterSummary {
    /// Implementation name.
    pub name: String,
    /// Version string reported by the adapter.
    pub version: String,
    /// Cases answered, summed over workers.
    pub cases: u64,
    /// Cases per second per process while busy.
    pub cases_per_sec_per_process: f64,
    /// Median per-case latency in microseconds (worker 0, batch-averaged).
    pub p50_us: u32,
    /// 99th percentile per-case latency in microseconds (worker 0, batch-averaged).
    pub p99_us: u32,
    /// Process restarts, summed over workers.
    pub restarts: u64,
}

/// The machine-readable result of a fuzz run.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Summary {
    /// Base seed.
    pub seed: u64,
    /// Unix time the run started.
    pub started_unix: u64,
    /// Wall-clock duration in seconds.
    pub duration_secs: f64,
    /// Worker threads.
    pub workers: usize,
    /// Whether the feedback loop was on.
    pub feedback: bool,
    /// Cases fully compared across all implementations.
    pub cases: u64,
    /// `cases / duration_secs`.
    pub cases_per_sec: f64,
    /// Cases per differential class.
    pub classes: BTreeMap<String, u64>,
    /// Matches per allowlist entry.
    pub known: BTreeMap<String, u64>,
    /// Per implementation: how often each outcome / error class was reported.
    pub error_classes: BTreeMap<String, BTreeMap<String, u64>>,
    /// Per generator category: cases per differential class.
    pub by_category: BTreeMap<String, BTreeMap<String, u64>>,
    /// Cases per output type.
    pub wrappers: BTreeMap<String, u64>,
    /// Distinct feedback tuples reached.
    pub signatures: usize,
    /// Cases currently kept for mutation.
    pub kept: usize,
    /// New finding files written by this run.
    pub findings_written: u64,
    /// Why the run ended.
    pub stop_reason: String,
    /// Per-adapter figures.
    pub adapters: Vec<AdapterSummary>,
}

#[derive(Default)]
struct Shared {
    signatures: HashSet<Signature>,
    kept: Vec<Case>,
    classes: BTreeMap<Class, u64>,
    known: BTreeMap<String, u64>,
    error_classes: BTreeMap<String, BTreeMap<String, u64>>,
    by_category: BTreeMap<String, BTreeMap<Class, u64>>,
    wrappers: BTreeMap<&'static str, u64>,
    /// New finding files written, per worker (each worker has its own sink).
    findings: Vec<u64>,
    adapters: Vec<Vec<AdapterSummary>>,
    stop_reason: Option<String>,
}

fn outcome_label(o: &Outcome) -> String {
    match o {
        Outcome::Ok => "OK".to_string(),
        Outcome::Fail { error_class, .. } => error_class.name(),
        Outcome::Crash { .. } => "CRASH".to_string(),
        Outcome::Timeout => "TIMEOUT".to_string(),
    }
}

/// The feedback tuple for a case and its result.
pub fn signature(case: &Case, result: &CaseResult) -> Signature {
    let labels: Vec<String> = result
        .verdicts
        .iter()
        .map(|v| outcome_label(&v.outcome))
        .collect();
    (labels.join("|"), opcode_set(case), wrapper_type(case))
}

impl Shared {
    /// Fold one batch into the shared statistics; returns how many cases were new.
    fn absorb(
        &mut self,
        cases: &[Case],
        results: &[CaseResult],
        feedback: bool,
        rng: &mut Rng,
    ) -> usize {
        let mut fresh = 0;
        for (case, result) in cases.iter().zip(results) {
            *self.classes.entry(result.class).or_insert(0) += 1;
            if let Some(id) = &result.known_id {
                *self.known.entry(id.clone()).or_insert(0) += 1;
            }
            for v in &result.verdicts {
                *self
                    .error_classes
                    .entry(v.impl_name.clone())
                    .or_default()
                    .entry(outcome_label(&v.outcome))
                    .or_insert(0) += 1;
            }
            *self
                .by_category
                .entry(category(case).to_string())
                .or_default()
                .entry(result.class)
                .or_insert(0) += 1;
            let sig = signature(case, result);
            *self.wrappers.entry(sig.2).or_insert(0) += 1;
            if self.signatures.insert(sig) {
                fresh += 1;
                if feedback {
                    if self.kept.len() < MAX_KEPT {
                        self.kept.push(case.clone());
                    } else {
                        let at = rng.below(MAX_KEPT);
                        self.kept[at] = case.clone();
                    }
                }
            }
        }
        fresh
    }
}

fn adapter_summaries(diff: &Differential, versions: &[String]) -> Vec<AdapterSummary> {
    diff.metrics
        .adapters
        .iter()
        .zip(versions)
        .map(|(a, version)| AdapterSummary {
            name: a.name.clone(),
            version: version.clone(),
            cases: a.cases,
            cases_per_sec_per_process: a.cases_per_sec(),
            p50_us: a.percentile_us(0.50),
            p99_us: a.percentile_us(0.99),
            restarts: a.restarts,
        })
        .collect()
}

fn class_names(m: &BTreeMap<Class, u64>) -> BTreeMap<String, u64> {
    m.iter().map(|(c, n)| (c.name().to_string(), *n)).collect()
}

/// Run the fuzz loop. `make_oracle` builds one differential runner per worker.
pub fn run<F>(cfg: &FuzzConfig, make_oracle: F) -> Result<Summary, String>
where
    F: Fn() -> Result<Differential, String>,
{
    let workers = cfg.workers.max(1);
    let mut oracles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let mut d = make_oracle()?;
        d.set_seed(Some(cfg.seed));
        oracles.push(d);
    }

    let mix = Arc::new(Mix::new(cfg.weights, cfg.seeds.clone()));
    let shared = Arc::new(Mutex::new(Shared {
        adapters: vec![Vec::new(); workers],
        findings: vec![0; workers],
        ..Shared::default()
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let issued = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let deadline = cfg.duration.map(|d| started + d);

    std::thread::scope(|scope| {
        for (w, mut diff) in oracles.into_iter().enumerate() {
            let (mix, shared, stop, issued, done) = (
                mix.clone(),
                shared.clone(),
                stop.clone(),
                issued.clone(),
                done.clone(),
            );
            scope.spawn(move || {
                let mut rng = Rng::new(cfg.seed).fork(1_000_000 + w as u64);
                let mut versions = vec![String::new(); diff.adapter_names().len()];
                loop {
                    if stop.load(Ordering::Relaxed) || deadline.is_some_and(|d| Instant::now() >= d)
                    {
                        break;
                    }
                    if let Some(count) = cfg.count
                        && issued.fetch_add(BATCH as u64, Ordering::Relaxed) >= count
                    {
                        break;
                    }
                    // Take a few kept cases under the lock, then generate without it.
                    let parents: Vec<Case> = if cfg.feedback {
                        match shared.lock() {
                            Ok(s) if !s.kept.is_empty() => (0..BATCH / 3)
                                .map(|_| s.kept[rng.below(s.kept.len())].clone())
                                .collect(),
                            _ => Vec::new(),
                        }
                    } else {
                        Vec::new()
                    };
                    let mut batch = Vec::with_capacity(BATCH);
                    for parent in &parents {
                        batch.push(mix.mutator().mutate_case(&mut rng, parent));
                    }
                    while batch.len() < BATCH {
                        batch.push(mix.generate(&mut rng));
                    }

                    let results = diff.run_batch(&batch);
                    for r in &results {
                        for (i, v) in r.verdicts.iter().enumerate() {
                            if !v.impl_version.is_empty() {
                                versions[i].clone_from(&v.impl_version);
                            }
                        }
                    }
                    done.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    let written = diff.sink().map(|s| s.written()).unwrap_or(0);
                    let diverged = results.iter().any(|r| r.class == Class::HardDiverge);
                    if let Ok(mut s) = shared.lock() {
                        s.absorb(&batch, &results, cfg.feedback, &mut rng);
                        s.adapters[w] = adapter_summaries(&diff, &versions);
                        s.findings[w] = written;
                        let written: u64 = s.findings.iter().sum();
                        if diverged && cfg.stop_on_divergence && s.stop_reason.is_none() {
                            s.stop_reason = Some("hard divergence".to_string());
                            stop.store(true, Ordering::Relaxed);
                        }
                        if written > cfg.max_findings && s.stop_reason.is_none() {
                            s.stop_reason = Some("finding limit reached".to_string());
                            stop.store(true, Ordering::Relaxed);
                        }
                    }
                }
            });
        }

        // Progress reporter on the calling thread.
        let mut last = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(200));
            let finished = stop.load(Ordering::Relaxed)
                || deadline.is_some_and(|d| Instant::now() >= d)
                || cfg.count.is_some_and(|c| done.load(Ordering::Relaxed) >= c);
            if last.elapsed() >= cfg.report_every || finished {
                last = Instant::now();
                if let Ok(s) = shared.lock() {
                    eprint!(
                        "{}",
                        progress_line(&s, done.load(Ordering::Relaxed), started)
                    );
                }
            }
            if finished {
                break;
            }
        }
    });

    let duration = started.elapsed().as_secs_f64();
    let cases = done.load(Ordering::Relaxed);
    let s = shared.lock().map_err(|_| "worker panicked".to_string())?;
    let mut adapters: BTreeMap<String, AdapterSummary> = BTreeMap::new();
    let mut order = Vec::new();
    for (w, per_worker) in s.adapters.iter().enumerate() {
        for a in per_worker {
            if !adapters.contains_key(&a.name) {
                order.push(a.name.clone());
            }
            let e = adapters
                .entry(a.name.clone())
                .or_insert_with(|| AdapterSummary {
                    name: a.name.clone(),
                    ..AdapterSummary::default()
                });
            e.cases += a.cases;
            e.restarts += a.restarts;
            e.cases_per_sec_per_process += a.cases_per_sec_per_process / workers as f64;
            if !a.version.is_empty() {
                e.version.clone_from(&a.version);
            }
            if w == 0 {
                e.p50_us = a.p50_us;
                e.p99_us = a.p99_us;
            }
        }
    }
    let stop_reason = s.stop_reason.clone().unwrap_or_else(|| {
        if cfg.count.is_some_and(|c| cases >= c) {
            "count reached"
        } else {
            "duration elapsed"
        }
        .to_string()
    });
    Ok(Summary {
        seed: cfg.seed,
        started_unix,
        duration_secs: duration,
        workers,
        feedback: cfg.feedback,
        cases,
        cases_per_sec: if duration > 0.0 {
            cases as f64 / duration
        } else {
            0.0
        },
        classes: class_names(&s.classes),
        known: s.known.clone(),
        error_classes: s.error_classes.clone(),
        by_category: s
            .by_category
            .iter()
            .map(|(k, v)| (k.clone(), class_names(v)))
            .collect(),
        wrappers: s
            .wrappers
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
        signatures: s.signatures.len(),
        kept: s.kept.len(),
        findings_written: s.findings.iter().sum(),
        stop_reason,
        adapters: order
            .iter()
            .filter_map(|n| adapters.get(n).cloned())
            .collect(),
    })
}

fn progress_line(s: &Shared, cases: u64, started: Instant) -> String {
    let secs = started.elapsed().as_secs_f64();
    let classes: Vec<String> = s.classes.iter().map(|(c, n)| format!("{c}={n}")).collect();
    let mut line = format!(
        "[{secs:>7.1}s] cases {cases} ({:.0}/s) signatures {} kept {} | {}\n",
        if secs > 0.0 { cases as f64 / secs } else { 0.0 },
        s.signatures.len(),
        s.kept.len(),
        classes.join(" ")
    );
    if let Some(first) = s.adapters.first() {
        for a in first {
            line.push_str(&format!(
                "    {:<10} {:>8.0}/s per process  p50 {}us  p99 {}us  restarts {}\n",
                a.name, a.cases_per_sec_per_process, a.p50_us, a.p99_us, a.restarts
            ));
        }
    }
    line
}

/// Human-readable report of a summary: totals, per-category classes, per-implementation error
/// classes and output types.
pub fn render(s: &Summary) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "seed {}  workers {}  feedback {}  {:.1}s  {} cases  {:.0} cases/s  ({})",
        s.seed, s.workers, s.feedback, s.duration_secs, s.cases, s.cases_per_sec, s.stop_reason
    );
    let _ = writeln!(o, "classes:");
    for (c, n) in &s.classes {
        let _ = writeln!(o, "  {c:<14} {n:>10}  {:>5.1}%", pct(*n, s.cases));
    }
    for (id, n) in &s.known {
        let _ = writeln!(o, "  known divergence {id}: {n}");
    }
    let _ = writeln!(o, "by generator category:");
    for (cat, classes) in &s.by_category {
        let total: u64 = classes.values().sum();
        let parts: Vec<String> = classes
            .iter()
            .map(|(c, n)| format!("{c} {:.1}%", pct(*n, total)))
            .collect();
        let _ = writeln!(o, "  {cat:<14} {total:>10}  {}", parts.join(", "));
    }
    let _ = writeln!(o, "output types:");
    for (w, n) in &s.wrappers {
        let _ = writeln!(o, "  {w:<22} {n:>10}  {:>5.1}%", pct(*n, s.cases));
    }
    for (name, classes) in &s.error_classes {
        let total: u64 = classes.values().sum();
        let _ = writeln!(
            o,
            "outcomes reported by {name} ({} distinct):",
            classes.len()
        );
        let mut sorted: Vec<(&String, &u64)> = classes.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (class, n) in sorted {
            let _ = writeln!(o, "  {class:<38} {n:>10}  {:>5.1}%", pct(*n, total));
        }
    }
    let _ = writeln!(
        o,
        "feedback: {} distinct signatures, {} kept; findings written: {}",
        s.signatures, s.kept, s.findings_written
    );
    for a in &s.adapters {
        let _ = writeln!(
            o,
            "adapter {:<8} {}  {:.0} cases/s per process  p50 {}us  p99 {}us  restarts {}",
            a.name, a.version, a.cases_per_sec_per_process, a.p50_us, a.p99_us, a.restarts
        );
    }
    o
}

fn pct(n: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        n as f64 * 100.0 / total as f64
    }
}

/// Load every runnable case of the Core vector files found in `dir`, as mutation seeds.
/// Missing files are skipped; a missing directory yields no seeds.
pub fn corpus_seeds(dir: &Path) -> Vec<Case> {
    let mut seeds = Vec::new();
    for file in ["script_tests.json", "tx_valid.json", "tx_invalid.json"] {
        let path: PathBuf = dir.join(file);
        if let Ok(loaded) = crate::replay::load_file(&path) {
            seeds.extend(loaded.tests.into_iter().flat_map(|t| t.cases));
        }
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffuzz_types::{ErrorClass, Verdict};

    fn result(class: Class, outcomes: Vec<Outcome>) -> CaseResult {
        CaseResult {
            verdicts: outcomes
                .into_iter()
                .enumerate()
                .map(|(i, outcome)| Verdict {
                    impl_name: format!("impl{i}"),
                    impl_version: "1".into(),
                    outcome,
                })
                .collect(),
            class,
            known_id: None,
        }
    }

    fn case(origin: &str, tx_hex: &str) -> Case {
        Case {
            tx_hex: tx_hex.into(),
            input_index: 0,
            prevouts: vec![],
            flags: vec![],
            origin: Some(origin.into()),
        }
    }

    fn fail(c: ErrorClass) -> Outcome {
        Outcome::Fail {
            error_class: c,
            raw_error: String::new(),
        }
    }

    #[test]
    fn absorb_counts_and_keeps_only_new_signatures() {
        let mut s = Shared::default();
        let mut rng = Rng::new(1);
        let cases = vec![
            case("gen/sig/bare/p2pk", "00"),
            case("gen/sig/bare/p2pk", "01"),
        ];
        let ok = result(Class::AgreeOk, vec![Outcome::Ok, Outcome::Ok]);
        let bad = result(
            Class::AgreeFail,
            vec![fail(ErrorClass::ScriptFail), fail(ErrorClass::EvalFalse)],
        );
        // Both cases are undecodable, so they share opcode set and output type: the signature
        // differs only by outcome.
        assert_eq!(
            s.absorb(&cases, &[ok.clone(), ok.clone()], true, &mut rng),
            1
        );
        assert_eq!(s.kept.len(), 1);
        assert_eq!(s.absorb(&cases, &[ok, bad], true, &mut rng), 1);
        assert_eq!(s.kept.len(), 2);
        assert_eq!(s.classes[&Class::AgreeOk], 3);
        assert_eq!(s.classes[&Class::AgreeFail], 1);
        assert_eq!(s.by_category["gen/sig"][&Class::AgreeOk], 3);
        assert_eq!(s.error_classes["impl1"]["EVAL_FALSE"], 1);
        assert_eq!(s.error_classes["impl0"]["OK"], 3);
        assert_eq!(s.wrappers["undecodable"], 4);

        // Without feedback nothing is kept.
        let mut s = Shared::default();
        let r = result(Class::AgreeOk, vec![Outcome::Ok]);
        s.absorb(&cases[..1], &[r], false, &mut rng);
        assert!(s.kept.is_empty());
        assert_eq!(s.signatures.len(), 1);
    }

    #[test]
    fn kept_set_is_bounded() {
        let mut s = Shared::default();
        let mut rng = Rng::new(2);
        s.kept = vec![case("x", "00"); MAX_KEPT];
        let r = result(Class::Crash, vec![Outcome::Timeout]);
        s.absorb(&[case("y", "ff")], &[r], true, &mut rng);
        assert_eq!(s.kept.len(), MAX_KEPT);
        assert!(s.kept.iter().any(|c| c.tx_hex == "ff"));
    }

    #[test]
    fn summary_renders_and_serializes() {
        let mut s = Summary {
            seed: 5,
            cases: 200,
            cases_per_sec: 100.0,
            ..Summary::default()
        };
        s.classes.insert("AGREE_OK".into(), 150);
        s.classes.insert("AGREE_FAIL".into(), 50);
        s.by_category
            .entry("gen/sig".into())
            .or_default()
            .insert("AGREE_OK".into(), 150);
        s.error_classes
            .entry("btcd".into())
            .or_default()
            .insert("EVAL_FALSE".into(), 50);
        s.wrappers.insert("p2wsh".into(), 200);
        s.stop_reason = "count reached".into();
        let text = render(&s);
        assert!(text.contains("AGREE_OK"), "{text}");
        assert!(text.contains("75.0%"), "{text}");
        assert!(
            text.contains("outcomes reported by btcd (1 distinct)"),
            "{text}"
        );
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"cases\":200"));
        assert_eq!(pct(1, 0), 0.0);
    }

    #[test]
    fn corpus_seeds_from_missing_dir_is_empty() {
        assert!(corpus_seeds(Path::new("definitely/not/here")).is_empty());
    }
}
