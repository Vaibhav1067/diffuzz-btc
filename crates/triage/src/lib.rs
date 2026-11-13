//! Divergence bucketing, deduplication and reports.
//!
//! * [`features`]: structural features of a case (output type, opcode set).
//! * [`bucket`]: group findings by root-cause signature and minimize representatives.
//! * [`report`]: Markdown report writer and export to Core's test-vector format.

#![forbid(unsafe_code)]

pub mod bucket;
pub mod features;
pub mod report;
