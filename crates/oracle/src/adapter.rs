//! Long-lived adapter subprocess management.
//!
//! An [`Adapter`] owns one child process speaking protocol v1. A background thread drains the
//! child's stdout into a channel, so the caller can wait for each response with a timeout and
//! can write a whole batch of requests without deadlocking on full pipes.
//!
//! Failure handling is deliberately conservative: any timeout, early exit, unparsable line or
//! id mismatch kills the process, is reported for exactly the request that was being waited on
//! ([`Outcome::Timeout`] or [`Outcome::Crash`]), and the process is restarted for the requests
//! after it.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use diffuzz_types::auxop::{AuxOp, AuxRequest, AuxResponse};
use diffuzz_types::{Case, Outcome, Response, Verdict};
use serde::Serialize;

/// How to launch an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterConfig {
    /// Short implementation name used in reports (`core`, `btcd`, ...).
    pub name: String,
    /// Executable to run.
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<String>,
    /// How long to wait for a single response before declaring a timeout.
    pub timeout: Duration,
}

impl AdapterConfig {
    /// A config with no arguments and a 10 second timeout.
    pub fn new(name: impl Into<String>, program: impl Into<PathBuf>) -> AdapterConfig {
        AdapterConfig {
            name: name.into(),
            program: program.into(),
            args: Vec::new(),
            timeout: Duration::from_secs(10),
        }
    }
}

/// Counters describing an adapter's life so far.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdapterStats {
    /// Requests answered with a well-formed response.
    pub answered: u64,
    /// Requests that ended in a crash.
    pub crashes: u64,
    /// Requests that ended in a timeout.
    pub timeouts: u64,
    /// Times the process was (re)started after the first launch.
    pub restarts: u64,
    /// Total time spent waiting on this adapter.
    pub busy: Duration,
}

struct Running {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    stderr_tail: Arc<Mutex<VecDeque<u8>>>,
}

/// A supervised adapter process.
pub struct Adapter {
    cfg: AdapterConfig,
    running: Option<Running>,
    next_id: u64,
    version: String,
    stats: AdapterStats,
    ever_started: bool,
}

const STDERR_TAIL: usize = 2048;

impl Adapter {
    /// Launch the adapter. Fails only if the process cannot be started at all.
    pub fn spawn(cfg: AdapterConfig) -> std::io::Result<Adapter> {
        let mut a = Adapter {
            cfg,
            running: None,
            next_id: 1,
            version: String::new(),
            stats: AdapterStats::default(),
            ever_started: false,
        };
        a.start()?;
        Ok(a)
    }

    /// The implementation name from the config.
    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    /// The implementation version last reported by the adapter ("" before the first answer).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Counters so far.
    pub fn stats(&self) -> &AdapterStats {
        &self.stats
    }

    fn start(&mut self) -> std::io::Result<()> {
        let mut child = Command::new(&self.cfg.program)
            .args(&self.cfg.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("no stderr"))?;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
        let tail2 = Arc::clone(&tail);
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut t) = tail2.lock() {
                    for b in &buf[..n] {
                        if t.len() == STDERR_TAIL {
                            t.pop_front();
                        }
                        t.push_back(*b);
                    }
                }
            }
        });

        if self.ever_started {
            self.stats.restarts += 1;
        }
        self.ever_started = true;
        self.running = Some(Running {
            child,
            stdin,
            lines: rx,
            stderr_tail: tail,
        });
        Ok(())
    }

    /// Kill the current process (if any) and describe how it ended.
    fn kill(&mut self) -> String {
        let Some(mut r) = self.running.take() else {
            return "adapter not running".to_string();
        };
        let _ = r.child.kill();
        let status = r
            .child
            .wait()
            .map(|s| s.to_string())
            .unwrap_or_else(|e| e.to_string());
        // Give the stderr thread a moment to drain what the dying process wrote.
        std::thread::sleep(Duration::from_millis(20));
        let tail = r
            .stderr_tail
            .lock()
            .map(|t| String::from_utf8_lossy(&t.iter().copied().collect::<Vec<u8>>()).into_owned())
            .unwrap_or_default();
        let tail = tail.trim();
        if tail.is_empty() {
            status
        } else {
            format!("{status}; stderr: {tail}")
        }
    }

    fn verdict(&self, outcome: Outcome) -> Verdict {
        Verdict {
            impl_name: self.cfg.name.clone(),
            impl_version: self.version.clone(),
            outcome,
        }
    }

    /// Verify one case.
    pub fn verify(&mut self, case: &Case) -> Verdict {
        self.verify_batch(std::slice::from_ref(case))
            .pop()
            .unwrap_or_else(|| {
                self.verdict(Outcome::Crash {
                    detail: "internal: empty batch result".into(),
                })
            })
    }

    /// Verify a batch of cases, pipelining requests. Verdicts are returned in input order.
    pub fn verify_batch(&mut self, cases: &[Case]) -> Vec<Verdict> {
        let results = self.exchange(
            cases.len(),
            |i, id| cases[i].to_request(id),
            |line| serde_json::from_str::<Response>(line).map(|r| (r.id, r)),
        );
        results
            .into_iter()
            .map(|r| match r {
                Ok(resp) => {
                    self.version.clone_from(&resp.impl_version);
                    Verdict::from_response(resp)
                }
                Err(outcome) => self.verdict(outcome),
            })
            .collect()
    }

    /// Run a batch of auxiliary operations (tx info, sighash), pipelining requests. Results are
    /// in input order; `Err` is a [`Outcome::Crash`] or [`Outcome::Timeout`].
    pub fn aux_batch(&mut self, ops: &[AuxOp]) -> Vec<Result<AuxResponse, Outcome>> {
        self.exchange(
            ops.len(),
            |i, id| AuxRequest {
                id,
                op: ops[i].clone(),
            },
            |line| serde_json::from_str::<AuxResponse>(line).map(|r| (r.id, r)),
        )
    }

    /// Send `n` requests and collect `n` results in order, restarting the process after any
    /// failure so later requests still get answered.
    fn exchange<Q, R>(
        &mut self,
        n: usize,
        make: impl Fn(usize, u64) -> Q,
        parse: impl Fn(&str) -> serde_json::Result<(u64, R)>,
    ) -> Vec<Result<R, Outcome>>
    where
        Q: Serialize,
    {
        let started = Instant::now();
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let before = out.len();
            self.run_pipeline(before, n, &make, &parse, &mut out);
            if out.len() == before {
                // Could not even start the adapter: fail the next request and keep going so a
                // permanently broken adapter still terminates.
                self.stats.crashes += 1;
                out.push(Err(Outcome::Crash {
                    detail: "adapter could not be started".to_string(),
                }));
            }
        }
        self.stats.busy += started.elapsed();
        out
    }

    /// Send requests `from..n` and collect responses until all are answered or one fails. On
    /// failure the failing request gets its Crash/Timeout result and the process is torn down;
    /// the caller resubmits the rest.
    fn run_pipeline<Q: Serialize, R>(
        &mut self,
        from: usize,
        n: usize,
        make: &impl Fn(usize, u64) -> Q,
        parse: &impl Fn(&str) -> serde_json::Result<(u64, R)>,
        out: &mut Vec<Result<R, Outcome>>,
    ) {
        if self.running.is_none() && self.start().is_err() {
            return;
        }
        let first_id = self.next_id;
        self.next_id += (n - from) as u64;

        // Write everything up front. A write error means the process died; the read loop below
        // will observe that on the first unanswered request.
        if let Some(r) = self.running.as_mut() {
            let mut buf = Vec::new();
            for (k, i) in (from..n).enumerate() {
                if serde_json::to_writer(&mut buf, &make(i, first_id + k as u64)).is_ok() {
                    buf.push(b'\n');
                }
            }
            let _ = r.stdin.write_all(&buf).and_then(|()| r.stdin.flush());
        }

        for k in 0..(n - from) {
            let id = first_id + k as u64;
            let received = match self.running.as_ref() {
                Some(r) => r.lines.recv_timeout(self.cfg.timeout),
                None => Err(RecvTimeoutError::Disconnected),
            };
            let failure = match received {
                Ok(line) => match parse(&line) {
                    Ok((got, resp)) if got == id => {
                        self.stats.answered += 1;
                        out.push(Ok(resp));
                        continue;
                    }
                    Ok((got, _)) => Outcome::Crash {
                        detail: format!("id mismatch: sent {id}, got {got}"),
                    },
                    Err(e) => Outcome::Crash {
                        detail: format!("unparsable response ({e}): {}", truncate(&line, 200)),
                    },
                },
                Err(RecvTimeoutError::Timeout) => Outcome::Timeout,
                Err(RecvTimeoutError::Disconnected) => Outcome::Crash {
                    detail: String::new(),
                },
            };
            let how = self.kill();
            let outcome = match failure {
                Outcome::Timeout => {
                    self.stats.timeouts += 1;
                    Outcome::Timeout
                }
                Outcome::Crash { detail } => {
                    self.stats.crashes += 1;
                    let detail = if detail.is_empty() {
                        how
                    } else {
                        format!("{detail}; exit: {how}")
                    };
                    Outcome::Crash { detail }
                }
                other => other,
            };
            out.push(Err(outcome));
            return;
        }
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        if let Some(mut r) = self.running.take() {
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_char_boundary() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 3), "abc...");
        assert_eq!(truncate("aé", 2), "a...");
    }

    #[test]
    fn spawn_failure_is_an_error() {
        let cfg = AdapterConfig::new("nope", "definitely-not-a-real-program-xyz");
        assert!(Adapter::spawn(cfg).is_err());
    }

    #[test]
    fn config_defaults() {
        let cfg = AdapterConfig::new("core", "x");
        assert_eq!(cfg.name, "core");
        assert_eq!(cfg.timeout, Duration::from_secs(10));
        assert!(cfg.args.is_empty());
    }
}
