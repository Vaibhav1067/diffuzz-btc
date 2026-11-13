//! Adapter process management and differential comparison.
//!
//! * [`adapter`]: supervise one adapter subprocess (spawn, pipeline, timeout, restart).
//! * [`resolve`]: find adapter executables by implementation name.
//! * [`diff`]: classify one case's verdicts (agree, diverge, crash, timeout).
//! * [`known`]: the allowlist of documented benign divergences.
//! * [`findings`]: the private, git-ignored findings sink.
//! * [`runner`]: fan cases out to all adapters concurrently and tie the above together.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod diff;
pub mod findings;
pub mod known;
pub mod resolve;
pub mod runner;
