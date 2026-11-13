//! Adapter process management and differential comparison.
//!
//! * [`adapter`]: supervise one adapter subprocess (spawn, pipeline, timeout, restart).
//! * [`resolve`]: find adapter executables by implementation name.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod resolve;
