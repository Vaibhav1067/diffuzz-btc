//! `diffuzz aux`: the secondary-surface differential (transaction decoding and signature
//! hashes).
//!
//! Checks come from upstream vectors: Core's `sighash.json` (legacy digests with expected
//! values), the BIP341 wallet vectors (key-path digests with expected values), and a `txinfo`
//! decode of every distinct transaction in those files plus `tx_valid.json` / `tx_invalid.json`.
//! Each check runs on every implementation. An implementation that answers `unsupported`
//! abstains. Anything else is compared with the expected value (if the vector has one) and with
//! every other answering implementation. Cross-implementation disagreements, crashes and
//! timeouts are written to the private findings directory (rule 2).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use diffuzz_corpus::{VectorKind, bip341, sighash};
use diffuzz_oracle::adapter::Adapter;
use diffuzz_types::auxop::{AuxOp, AuxResponse, SighashKind};
use diffuzz_types::tx::sha256d;
use diffuzz_types::{Outcome, hex};
use serde::Serialize;

/// Requests pipelined to an adapter at once.
const BATCH: usize = 256;

/// One operation to run everywhere, with the upstream expectation if there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxCheck {
    /// Where it came from (`file#index`).
    pub name: String,
    /// The operation.
    pub op: AuxOp,
    /// Expected digest (raw byte order), for sighash vectors.
    pub expected_digest: Option<String>,
}

/// Reverse a hex string's bytes (Core prints uint256 values byte-reversed).
fn reverse_hex(h: &str) -> String {
    let mut b = hex::decode(h).unwrap_or_default();
    b.reverse();
    hex::encode(&b)
}

/// Build all checks from Core's vector directory and the BIP341 wallet vectors (either may be
/// missing; at least one check must result).
pub fn build_checks(core_dir: &Path, bip341_file: &Path) -> Result<Vec<AuxCheck>, String> {
    let read =
        |p: &PathBuf| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let mut checks = Vec::new();
    let mut txs = BTreeSet::new();

    let p = core_dir.join("sighash.json");
    if p.is_file() {
        for v in sighash::load(&read(&p)?).map_err(|e| e.to_string())? {
            let tx_hex = hex::encode(&v.tx);
            txs.insert(tx_hex.clone());
            checks.push(AuxCheck {
                name: v.name,
                op: AuxOp::Sighash {
                    kind: SighashKind::Legacy,
                    tx_hex,
                    input_index: v.input_index,
                    script_hex: hex::encode(&v.script),
                    // The vectors store the 32-bit value as signed; the hash uses its bits.
                    hash_type: v.hash_type as u32,
                    amount_sats: 0,
                    prevouts: vec![],
                    annex_hex: None,
                    leaf_hash_hex: None,
                    codesep_pos: u32::MAX,
                },
                expected_digest: Some(reverse_hex(&v.expected_hex)),
            });
        }
    }
    if bip341_file.is_file() {
        for v in bip341::load(&read(&bip341_file.to_path_buf())?).map_err(|e| e.to_string())? {
            txs.insert(v.tx_hex.clone());
            checks.push(AuxCheck {
                name: v.name,
                op: AuxOp::Sighash {
                    kind: SighashKind::Bip341,
                    tx_hex: v.tx_hex,
                    input_index: v.input_index,
                    script_hex: String::new(),
                    hash_type: u32::from(v.hash_type),
                    amount_sats: 0,
                    prevouts: v.prevouts,
                    annex_hex: None,
                    leaf_hash_hex: None,
                    codesep_pos: u32::MAX,
                },
                expected_digest: Some(v.expected_hex),
            });
        }
    }
    for (file, kind) in [
        ("tx_valid.json", VectorKind::TxValid),
        ("tx_invalid.json", VectorKind::TxInvalid),
    ] {
        let p = core_dir.join(file);
        if p.is_file() {
            let loaded = diffuzz_corpus::load(kind, &read(&p)?).map_err(|e| e.to_string())?;
            for t in loaded.tests {
                txs.extend(t.cases.into_iter().map(|c| c.tx_hex));
            }
        }
    }
    for (i, tx_hex) in txs.into_iter().enumerate() {
        checks.push(AuxCheck {
            name: format!("txinfo#{i}"),
            op: AuxOp::Txinfo { tx_hex },
            expected_digest: None,
        });
    }
    if checks.is_empty() {
        return Err(format!(
            "no vectors found in {} or {}",
            core_dir.display(),
            bip341_file.display()
        ));
    }
    Ok(checks)
}

/// How one implementation did on one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImplStatus {
    /// Answered and met the expectation (or there was none).
    Answered,
    /// Answered `unsupported`.
    Abstained,
    /// Answered, but the digest is missing or differs from the expected one.
    WrongDigest,
    /// Crashed or timed out.
    Failed(String),
}

/// The comparable content of an answer: success plus every reported field.
fn fields(r: &AuxResponse) -> [(&'static str, Option<String>); 6] {
    [
        ("ok", Some(r.ok.to_string())),
        ("txid", r.txid.clone()),
        ("wtxid", r.wtxid.clone()),
        ("weight", r.weight.map(|w| w.to_string())),
        ("hex", r.hex.clone()),
        ("digest", r.digest.clone()),
    ]
}

/// Classify one check's results: per-implementation status, plus the names of the fields on
/// which two answering implementations disagree (`ok` included). A field one implementation
/// does not report is not compared.
pub fn classify(
    check: &AuxCheck,
    results: &[Result<AuxResponse, Outcome>],
) -> (Vec<ImplStatus>, Vec<&'static str>) {
    let mut statuses = Vec::new();
    let mut answered = Vec::new();
    for r in results {
        statuses.push(match r {
            Err(Outcome::Timeout) => ImplStatus::Failed("TIMEOUT".into()),
            Err(o) => ImplStatus::Failed(format!("CRASH: {o:?}")),
            Ok(a) if a.unsupported => ImplStatus::Abstained,
            Ok(a) => {
                answered.push(a);
                match &check.expected_digest {
                    Some(want) if !a.ok || a.digest.as_deref() != Some(want.as_str()) => {
                        ImplStatus::WrongDigest
                    }
                    _ => ImplStatus::Answered,
                }
            }
        });
    }
    let all: Vec<_> = answered.iter().map(|a| fields(a)).collect();
    let mut diverging = Vec::new();
    for (k, (name, _)) in fields(&AuxResponse::default()).into_iter().enumerate() {
        let values: BTreeSet<&String> = all.iter().filter_map(|f| f[k].1.as_ref()).collect();
        if values.len() > 1 {
            diverging.push(name);
        }
    }
    (statuses, diverging)
}

/// Per-implementation totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImplTotals {
    /// Implementation name.
    pub name: String,
    /// Checks answered (and matching any expectation).
    pub answered: usize,
    /// Checks abstained.
    pub abstained: usize,
    /// Checks with an expected digest that was not produced.
    pub wrong: Vec<String>,
    /// Crashes and timeouts.
    pub failed: usize,
}

/// Results of a whole `aux` run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuxReport {
    /// Checks run.
    pub checks: usize,
    /// Per implementation.
    pub impls: Vec<ImplTotals>,
    /// Diverging checks: name and the fields that differ.
    pub divergences: Vec<(String, Vec<&'static str>)>,
    /// Finding files written.
    pub written: Vec<PathBuf>,
}

impl AuxReport {
    /// No wrong digest, no divergence, no crash or timeout.
    pub fn clean(&self) -> bool {
        self.divergences.is_empty()
            && self
                .impls
                .iter()
                .all(|i| i.wrong.is_empty() && i.failed == 0)
    }
}

#[derive(Serialize)]
struct AuxFinding<'a> {
    class: &'static str,
    name: &'a str,
    request: &'a AuxOp,
    expected_digest: &'a Option<String>,
    diverging_fields: &'a [&'static str],
    responses: Vec<(String, String, serde_json::Value)>,
}

/// Run every check on every adapter and record findings under `findings_dir`.
pub fn run(
    checks: &[AuxCheck],
    adapters: &mut [Adapter],
    findings_dir: &Path,
) -> Result<AuxReport, String> {
    diffuzz_oracle::findings::check_untracked(findings_dir)?;
    let mut report = AuxReport {
        checks: checks.len(),
        impls: adapters
            .iter()
            .map(|a| ImplTotals {
                name: a.name().to_string(),
                ..ImplTotals::default()
            })
            .collect(),
        ..AuxReport::default()
    };
    for chunk in checks.chunks(BATCH) {
        let ops: Vec<AuxOp> = chunk.iter().map(|c| c.op.clone()).collect();
        let per_impl: Vec<Vec<Result<AuxResponse, Outcome>>> =
            adapters.iter_mut().map(|a| a.aux_batch(&ops)).collect();
        for (i, check) in chunk.iter().enumerate() {
            let results: Vec<Result<AuxResponse, Outcome>> =
                per_impl.iter().map(|r| r[i].clone()).collect();
            let (statuses, diverging) = classify(check, &results);
            let mut failed = false;
            for (t, s) in report.impls.iter_mut().zip(&statuses) {
                match s {
                    ImplStatus::Answered => t.answered += 1,
                    ImplStatus::Abstained => t.abstained += 1,
                    ImplStatus::WrongDigest => t.wrong.push(check.name.clone()),
                    ImplStatus::Failed(_) => {
                        t.failed += 1;
                        failed = true;
                    }
                }
            }
            if diverging.is_empty() && !failed {
                continue;
            }
            if !diverging.is_empty() {
                report
                    .divergences
                    .push((check.name.clone(), diverging.clone()));
            }
            let finding = AuxFinding {
                class: if diverging.is_empty() {
                    "AUX_CRASH"
                } else {
                    "AUX_DIVERGE"
                },
                name: &check.name,
                request: &check.op,
                expected_digest: &check.expected_digest,
                diverging_fields: &diverging,
                responses: adapters
                    .iter()
                    .zip(&results)
                    .map(|(a, r)| {
                        let v = match r {
                            Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                            Err(o) => serde_json::Value::String(format!("{o:?}")),
                        };
                        (a.name().to_string(), a.version().to_string(), v)
                    })
                    .collect(),
            };
            let json = serde_json::to_string_pretty(&finding).map_err(|e| e.to_string())?;
            let id = hex::encode(
                &sha256d(
                    serde_json::to_string(&check.op)
                        .map_err(|e| e.to_string())?
                        .as_bytes(),
                )[..8],
            );
            let path = findings_dir.join(format!("{}-{id}.json", finding.class.to_lowercase()));
            std::fs::write(&path, json).map_err(|e| format!("{}: {e}", path.display()))?;
            report.written.push(path);
        }
    }
    Ok(report)
}

/// Human-readable summary. Lists check names and field names only, never case contents.
pub fn render(report: &AuxReport, max_listed: usize) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "aux checks: {}", report.checks);
    for t in &report.impls {
        let _ = writeln!(
            s,
            "  {:<14} answered {:>6}  abstained {:>6}  wrong digest {:>4}  crash/timeout {}",
            t.name,
            t.answered,
            t.abstained,
            t.wrong.len(),
            t.failed
        );
        for w in t.wrong.iter().take(max_listed) {
            let _ = writeln!(s, "      wrong: {w}");
        }
    }
    let mut by_field: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, f) in &report.divergences {
        for x in f {
            *by_field.entry(x).or_insert(0) += 1;
        }
    }
    let _ = writeln!(
        s,
        "  divergences: {} {:?}; {} finding file(s) written (private)",
        report.divergences.len(),
        by_field,
        report.written.len()
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(expected: Option<&str>) -> AuxCheck {
        AuxCheck {
            name: "t".into(),
            op: AuxOp::Txinfo {
                tx_hex: "00".into(),
            },
            expected_digest: expected.map(str::to_owned),
        }
    }

    fn ok(digest: Option<&str>, txid: Option<&str>) -> Result<AuxResponse, Outcome> {
        Ok(AuxResponse {
            ok: true,
            digest: digest.map(str::to_owned),
            txid: txid.map(str::to_owned),
            ..AuxResponse::default()
        })
    }

    #[test]
    fn reverses() {
        assert_eq!(reverse_hex("0102ff"), "ff0201");
    }

    #[test]
    fn classifies() {
        let unsupported = Ok(AuxResponse::unsupported(0, "no"));
        let (st, div) = classify(&check(Some("aa")), &[ok(Some("aa"), None), unsupported]);
        assert_eq!(st, vec![ImplStatus::Answered, ImplStatus::Abstained]);
        assert!(div.is_empty());

        let (st, div) = classify(
            &check(Some("aa")),
            &[ok(Some("aa"), None), ok(Some("bb"), None)],
        );
        assert_eq!(st[1], ImplStatus::WrongDigest);
        assert_eq!(div, vec!["digest"]);

        // A field only one side reports is not compared; ok/!ok is.
        let (_, div) = classify(&check(None), &[ok(None, Some("t")), ok(None, None)]);
        assert!(div.is_empty());
        let failed = Ok(AuxResponse::failed(0, "x"));
        let (_, div) = classify(&check(None), &[ok(None, None), failed]);
        assert_eq!(div, vec!["ok"]);

        let (st, _) = classify(&check(None), &[Err(Outcome::Timeout)]);
        assert!(matches!(st[0], ImplStatus::Failed(_)));
    }
}
