//! The differential runner: fan a batch of cases out to every adapter concurrently, classify
//! each case, consult the allowlist, and route findings to the private sink.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use diffuzz_types::{Case, Verdict};

use crate::adapter::Adapter;
use crate::diff::{Class, RawClass, classify};
use crate::findings::FindingsSink;
use crate::known::Allowlist;

/// Outcome of one case across all implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseResult {
    /// One verdict per adapter, in adapter order.
    pub verdicts: Vec<Verdict>,
    /// Final classification.
    pub class: Class,
    /// Id of the allowlist entry that matched, for [`Class::Known`].
    pub known_id: Option<String>,
}

/// Latency samples kept per adapter for percentile estimates.
const MAX_SAMPLES: usize = 20_000;

/// Throughput and latency for one adapter.
#[derive(Debug, Clone, Default)]
pub struct AdapterMetrics {
    /// Implementation name.
    pub name: String,
    /// Cases sent.
    pub cases: u64,
    /// Wall time spent waiting for this adapter.
    pub busy: Duration,
    /// Process restarts.
    pub restarts: u64,
    /// Per-case latency samples in microseconds. Requests are pipelined, so each sample is a
    /// batch's wall time divided by its size, not an individually timed request.
    samples_us: Vec<u32>,
    next_sample: usize,
}

impl AdapterMetrics {
    fn add_batch(&mut self, n: usize, elapsed: Duration) {
        self.cases += n as u64;
        self.busy += elapsed;
        if n == 0 {
            return;
        }
        let per_case = (elapsed.as_micros() / n as u128).min(u128::from(u32::MAX)) as u32;
        if self.samples_us.len() < MAX_SAMPLES {
            self.samples_us.push(per_case);
        } else {
            self.samples_us[self.next_sample] = per_case;
            self.next_sample = (self.next_sample + 1) % MAX_SAMPLES;
        }
    }

    /// Cases per second while this adapter was busy.
    pub fn cases_per_sec(&self) -> f64 {
        let s = self.busy.as_secs_f64();
        if s > 0.0 { self.cases as f64 / s } else { 0.0 }
    }

    /// Latency percentile (0.0..=1.0) in microseconds over the retained samples.
    pub fn percentile_us(&self, p: f64) -> u32 {
        if self.samples_us.is_empty() {
            return 0;
        }
        let mut v = self.samples_us.clone();
        v.sort_unstable();
        let idx = ((v.len() - 1) as f64 * p.clamp(0.0, 1.0)).round() as usize;
        v[idx]
    }
}

/// Run-wide counters.
#[derive(Debug, Clone)]
pub struct Metrics {
    /// When the runner was created.
    pub started: Instant,
    /// Cases classified.
    pub cases: u64,
    /// Cases per final class.
    pub classes: BTreeMap<Class, u64>,
    /// Matches per allowlist entry id.
    pub known: BTreeMap<String, u64>,
    /// Per-adapter figures, in adapter order.
    pub adapters: Vec<AdapterMetrics>,
    last_report: Instant,
}

impl Metrics {
    fn new(names: &[String]) -> Metrics {
        let now = Instant::now();
        Metrics {
            started: now,
            cases: 0,
            classes: BTreeMap::new(),
            known: BTreeMap::new(),
            adapters: names
                .iter()
                .map(|n| AdapterMetrics {
                    name: n.clone(),
                    ..AdapterMetrics::default()
                })
                .collect(),
            last_report: now,
        }
    }

    /// Count of cases in `class`.
    pub fn count(&self, class: Class) -> u64 {
        self.classes.get(&class).copied().unwrap_or(0)
    }

    /// End-to-end cases per second since the runner was created (every case goes through all
    /// adapters, so this is the rate of fully compared cases).
    pub fn aggregate_cases_per_sec(&self) -> f64 {
        let s = self.started.elapsed().as_secs_f64();
        if s > 0.0 { self.cases as f64 / s } else { 0.0 }
    }

    /// Multi-line human-readable snapshot.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "[{:>7.1}s] cases {} ({:.0}/s end-to-end)",
            self.started.elapsed().as_secs_f64(),
            self.cases,
            self.aggregate_cases_per_sec()
        );
        for (class, n) in &self.classes {
            let _ = write!(s, " {class}={n}");
        }
        let _ = writeln!(s);
        for a in &self.adapters {
            let _ = writeln!(
                s,
                "    {:<10} {:>9.0}/s  p50 {}us  p90 {}us  p99 {}us  restarts {}",
                a.name,
                a.cases_per_sec(),
                a.percentile_us(0.50),
                a.percentile_us(0.90),
                a.percentile_us(0.99),
                a.restarts
            );
        }
        s
    }

    /// A snapshot if at least `interval` has passed since the last one, for periodic logging.
    pub fn maybe_render(&mut self, interval: Duration) -> Option<String> {
        if self.last_report.elapsed() < interval {
            return None;
        }
        self.last_report = Instant::now();
        Some(self.render())
    }
}

/// Runs cases through several long-lived adapters and classifies the results.
pub struct Differential {
    adapters: Vec<Adapter>,
    allowlist: Allowlist,
    sink: Option<FindingsSink>,
    seed: Option<u64>,
    /// Counters, public so callers can print or serialize them.
    pub metrics: Metrics,
    quiet: bool,
}

impl Differential {
    /// Create a runner. With `sink = None` findings are classified and counted but not written
    /// (used by tests and dry runs).
    pub fn new(adapters: Vec<Adapter>, allowlist: Allowlist, sink: Option<FindingsSink>) -> Self {
        let names: Vec<String> = adapters.iter().map(|a| a.name().to_string()).collect();
        Differential {
            adapters,
            allowlist,
            sink,
            seed: None,
            metrics: Metrics::new(&names),
            quiet: false,
        }
    }

    /// Record this generator seed in every finding written from now on.
    pub fn set_seed(&mut self, seed: Option<u64>) {
        self.seed = seed;
    }

    /// Suppress the loud stderr warning on findings (they are still written and counted).
    pub fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }

    /// Names of the adapters, in verdict order.
    pub fn adapter_names(&self) -> Vec<String> {
        self.adapters.iter().map(|a| a.name().to_string()).collect()
    }

    /// The findings sink, if any.
    pub fn sink(&self) -> Option<&FindingsSink> {
        self.sink.as_ref()
    }

    /// Classify one case's verdicts against the allowlist (no I/O).
    pub fn classify_case(&self, case: &Case, verdicts: &[Verdict]) -> (Class, Option<String>) {
        match classify(verdicts) {
            RawClass::AgreeOk => (Class::AgreeOk, None),
            RawClass::AgreeFail => (Class::AgreeFail, None),
            RawClass::Crash => (Class::Crash, None),
            RawClass::Timeout => (Class::Timeout, None),
            RawClass::Undecided => (Class::Undecided, None),
            // Policy flags differ between implementations by design (rule 5): a disagreement
            // under them is not a consensus finding, so there is nothing to compare.
            RawClass::Diverge if !case.is_consensus_only() => (Class::Undecided, None),
            RawClass::Diverge => match self.allowlist.find(case, verdicts) {
                Some(entry) => (Class::Known, Some(entry.id.clone())),
                None => (Class::HardDiverge, None),
            },
        }
    }

    /// Run a batch through every adapter concurrently and classify each case.
    pub fn run_batch(&mut self, cases: &[Case]) -> Vec<CaseResult> {
        // One thread per adapter; each pipelines the whole batch to its own process.
        let per_adapter: Vec<(Vec<Verdict>, Duration)> = std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .adapters
                .iter_mut()
                .map(|adapter| {
                    scope.spawn(move || {
                        let t = Instant::now();
                        let v = adapter.verify_batch(cases);
                        (v, t.elapsed())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|_| (Vec::new(), Duration::ZERO)))
                .collect()
        });

        for (i, (verdicts, elapsed)) in per_adapter.iter().enumerate() {
            self.metrics.adapters[i].add_batch(verdicts.len(), *elapsed);
            self.metrics.adapters[i].restarts = self.adapters[i].stats().restarts;
        }

        let mut results = Vec::with_capacity(cases.len());
        for (ci, case) in cases.iter().enumerate() {
            let verdicts: Vec<Verdict> = per_adapter
                .iter()
                .enumerate()
                .map(|(ai, (v, _))| {
                    v.get(ci).cloned().unwrap_or_else(|| Verdict {
                        impl_name: self.adapters[ai].name().to_string(),
                        impl_version: String::new(),
                        outcome: diffuzz_types::Outcome::Crash {
                            detail: "adapter thread panicked".to_string(),
                        },
                    })
                })
                .collect();
            let (class, known_id) = self.classify_case(case, &verdicts);
            self.metrics.cases += 1;
            *self.metrics.classes.entry(class).or_insert(0) += 1;
            if let Some(id) = &known_id {
                *self.metrics.known.entry(id.clone()).or_insert(0) += 1;
            }
            if class.is_finding() {
                self.record_finding(class, case, &verdicts);
            }
            results.push(CaseResult {
                verdicts,
                class,
                known_id,
            });
        }
        results
    }

    fn record_finding(&mut self, class: Class, case: &Case, verdicts: &[Verdict]) {
        let written = match self.sink.as_mut() {
            Some(sink) => sink.record(class, case, verdicts, self.seed),
            None => Ok(None),
        };
        if self.quiet {
            return;
        }
        match written {
            Ok(Some(path)) => {
                let bar = "!".repeat(72);
                eprintln!("{bar}");
                eprintln!("!! {class}: saved to {}", path.display());
                if class == Class::HardDiverge {
                    eprintln!(
                        "!! Implementations disagree under consensus flags with no allowlist"
                    );
                    eprintln!("!! match. Do NOT publish this file. Review it privately first.");
                }
                // Verdicts stay in the private file: terminal output may end up in a public log.
                eprintln!("{bar}");
            }
            Ok(None) => {}
            Err(e) => eprintln!("!! {class} could not be saved: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_flag_divergence_is_not_a_finding() {
        use diffuzz_types::{ErrorClass, Flag, Outcome};
        let d = Differential::new(vec![], Allowlist::empty(), None);
        let verdict = |name: &str, outcome| Verdict {
            impl_name: name.into(),
            impl_version: "1".into(),
            outcome,
        };
        let split = [
            verdict("btcd", Outcome::Ok),
            verdict(
                "nbitcoin",
                Outcome::Fail {
                    error_class: ErrorClass::ScriptFail,
                    raw_error: String::new(),
                },
            ),
        ];
        let mut case = Case {
            tx_hex: "00".into(),
            input_index: 0,
            prevouts: vec![],
            flags: vec![Flag::P2sh],
            origin: None,
        };
        assert_eq!(d.classify_case(&case, &split).0, Class::HardDiverge);
        case.flags.push(Flag::LowS);
        assert_eq!(d.classify_case(&case, &split).0, Class::Undecided);
    }

    #[test]
    fn adapter_metrics_math() {
        let mut m = AdapterMetrics::default();
        assert_eq!(m.cases_per_sec(), 0.0);
        assert_eq!(m.percentile_us(0.5), 0);
        m.add_batch(100, Duration::from_millis(10)); // 100us per case
        m.add_batch(100, Duration::from_millis(30)); // 300us per case
        m.add_batch(0, Duration::from_millis(5));
        assert_eq!(m.cases, 200);
        assert_eq!(m.percentile_us(0.0), 100);
        assert_eq!(m.percentile_us(1.0), 300);
        let rate = m.cases_per_sec();
        assert!((4400.0..4500.0).contains(&rate), "{rate}");
    }

    #[test]
    fn sample_buffer_is_bounded() {
        let mut m = AdapterMetrics::default();
        for _ in 0..(MAX_SAMPLES + 10) {
            m.add_batch(1, Duration::from_micros(7));
        }
        assert_eq!(m.samples_us.len(), MAX_SAMPLES);
        assert_eq!(m.next_sample, 10);
    }

    #[test]
    fn metrics_render_and_interval() {
        let mut m = Metrics::new(&["core".to_string(), "btcd".to_string()]);
        m.cases = 10;
        m.classes.insert(Class::AgreeOk, 7);
        m.classes.insert(Class::AgreeFail, 3);
        assert_eq!(m.count(Class::AgreeOk), 7);
        assert_eq!(m.count(Class::HardDiverge), 0);
        let text = m.render();
        assert!(text.contains("cases 10"), "{text}");
        assert!(text.contains("AGREE_OK=7"), "{text}");
        assert!(text.contains("core"), "{text}");
        assert!(m.maybe_render(Duration::from_secs(3600)).is_none());
        assert!(m.maybe_render(Duration::ZERO).is_some());
    }
}
