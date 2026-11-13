//! `diffuzz` command-line entry point.

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use diffuzz_gen::generators::{Mix, Weights, category};
use diffuzz_oracle::adapter::Adapter;
use diffuzz_oracle::findings::{FindingRecord, FindingsSink};
use diffuzz_oracle::known::Allowlist;
use diffuzz_oracle::resolve::resolve;
use diffuzz_oracle::runner::Differential;
use diffuzz_types::Case;

mod fuzz;
mod replay;

#[derive(Parser)]
#[command(
    name = "diffuzz",
    version,
    about = "Differential fuzzer for Bitcoin consensus"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run upstream vector files through adapters and compare with the expected verdicts.
    Replay(ReplayArgs),
    /// Generate cases deterministically and write them as JSON lines.
    Gen(GenArgs),
    /// Generate cases and run them through the differential oracle.
    Fuzz(FuzzArgs),
    /// Run one saved case (or finding) through the adapters and print every verdict.
    Check(CheckArgs),
    /// Merge the summary files of several fuzz segments into one.
    Summarize(SummarizeArgs),
    /// Shrink a diverging case while every implementation keeps its verdict.
    Minimize(MinimizeArgs),
    /// Bucket saved findings by root cause, minimize representatives and write a report.
    Report(ReportArgs),
    /// Print a case in Bitcoin Core's tx_valid.json / tx_invalid.json vector format.
    ExportCoreVector(CheckArgs),
}

/// Options shared by every command that runs the differential oracle.
#[derive(Args, Clone)]
struct OracleArgs {
    /// Implementations to run, comma separated (e.g. `core,btcd`).
    #[arg(long = "impls", alias = "impl", required = true, value_delimiter = ',')]
    impls: Vec<String>,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// Directory of known-divergence TOML entries.
    #[arg(long, default_value = "known_divergences")]
    known_dir: PathBuf,
    /// Private directory for hard divergences, crashes and timeouts. Must be git-ignored.
    #[arg(long, default_value = "findings/private")]
    findings_dir: PathBuf,
}

/// Options shared by commands that generate cases.
#[derive(Args, Clone)]
struct GenOpts {
    /// Seed for the deterministic generators.
    #[arg(long)]
    seed: u64,
    /// Generator weights file.
    #[arg(long, default_value = "weights.toml")]
    weights: PathBuf,
    /// Directory with Core's vector files, used as mutation seeds.
    #[arg(long, default_value = "vectors/core")]
    corpus: PathBuf,
}

#[derive(Args)]
struct ReplayArgs {
    /// Vector files (script_tests.json, tx_valid.json, tx_invalid.json).
    #[arg(long, required = true, num_args = 1..)]
    vectors: Vec<PathBuf>,
    /// Maximum mismatches listed per implementation and file.
    #[arg(long, default_value_t = 50)]
    max_listed: usize,
    #[command(flatten)]
    oracle: OracleArgs,
}

#[derive(Args)]
struct GenArgs {
    #[command(flatten)]
    opts: GenOpts,
    /// Number of cases.
    #[arg(long)]
    count: u64,
    /// Output directory; receives `cases.jsonl` and `manifest.json`.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct FuzzArgs {
    #[command(flatten)]
    opts: GenOpts,
    #[command(flatten)]
    oracle: OracleArgs,
    /// Stop after this many cases.
    #[arg(long)]
    count: Option<u64>,
    /// Stop after this long, e.g. `90s`, `30m`, `1h`.
    #[arg(long, value_parser = parse_duration)]
    duration: Option<Duration>,
    /// Worker threads; each runs its own adapter processes.
    #[arg(long, default_value_t = 1)]
    workers: usize,
    /// Disable the keep-and-mutate feedback loop.
    #[arg(long)]
    no_feedback: bool,
    /// Keep running after a hard divergence instead of stopping.
    #[arg(long)]
    keep_going: bool,
    /// Stop once this many finding files were written.
    #[arg(long, default_value_t = 500)]
    max_findings: u64,
    /// Write the machine-readable summary to this file.
    #[arg(long)]
    summary: Option<PathBuf>,
    /// Seconds between progress lines.
    #[arg(long, default_value_t = 10)]
    report_secs: u64,
    /// Consensus flags to force onto every case, comma separated (e.g. `DERSIG`).
    #[arg(long, value_delimiter = ',', value_parser = parse_flag)]
    require_flags: Vec<diffuzz_types::Flag>,
}

#[derive(Args)]
struct MinimizeArgs {
    /// A JSON file holding a case or a finding.
    #[arg(long)]
    case: PathBuf,
    /// Where to write the minimized case.
    #[arg(long)]
    out: PathBuf,
    /// Maximum oracle evaluations.
    #[arg(long, default_value_t = 5_000)]
    max_attempts: u64,
    #[command(flatten)]
    oracle: OracleArgs,
}

#[derive(Args)]
struct ReportArgs {
    /// Directory with finding files (searched one level deep).
    #[arg(long = "in", default_value = "findings/private")]
    input: PathBuf,
    /// Report file. Must be in a git-ignored location while findings are undisclosed.
    #[arg(long, default_value = "findings/private/report.md")]
    out: PathBuf,
    /// Findings to minimize per bucket.
    #[arg(long, default_value_t = 5)]
    per_bucket: usize,
    /// Maximum oracle evaluations per minimized finding.
    #[arg(long, default_value_t = 3_000)]
    max_attempts: u64,
    #[command(flatten)]
    oracle: OracleArgs,
}

#[derive(Args)]
struct SummarizeArgs {
    /// Segment summary files written by `fuzz --summary`.
    #[arg(long = "in", required = true, num_args = 1..)]
    inputs: Vec<PathBuf>,
    /// Where to write the merged summary.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct CheckArgs {
    /// A JSON file holding a case, or a finding written to the private findings directory.
    #[arg(long)]
    case: PathBuf,
    #[command(flatten)]
    oracle: OracleArgs,
}

fn parse_flag(s: &str) -> Result<diffuzz_types::Flag, String> {
    match diffuzz_types::Flag::from_name(s) {
        Some(f) if f.is_consensus() => Ok(f),
        Some(_) => Err(format!(
            "{s} is a policy flag; the oracle is consensus-only"
        )),
        None => Err(format!("unknown flag {s:?}")),
    }
}

/// Parse `90`, `90s`, `30m` or `2h` into a duration.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let (digits, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => s.split_at(i),
        None => (s, "s"),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration {s:?}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("invalid duration unit in {s:?} (use s, m or h)")),
    };
    Ok(Duration::from_secs(secs))
}

/// Start the adapters and build the differential runner.
fn build_oracle(args: &OracleArgs) -> Result<Differential, String> {
    let mut adapters = Vec::new();
    for name in &args.impls {
        let mut cfg = resolve(name)?;
        cfg.timeout = Duration::from_millis(args.timeout_ms);
        let program = cfg.program.display().to_string();
        adapters.push(Adapter::spawn(cfg).map_err(|e| format!("cannot start {program}: {e}"))?);
    }
    let allowlist = Allowlist::load_dir(&args.known_dir, Path::new("."))?;
    let sink = FindingsSink::new(&args.findings_dir)?;
    Ok(Differential::new(adapters, allowlist, Some(sink)))
}

/// Like [`build_oracle`] but without a findings sink and without warnings: for commands that
/// probe many candidate cases (minimizer, report), which must not be recorded as new findings.
fn build_probe(args: &OracleArgs) -> Result<Differential, String> {
    let mut adapters = Vec::new();
    for name in &args.impls {
        let mut cfg = resolve(name)?;
        cfg.timeout = Duration::from_millis(args.timeout_ms);
        let program = cfg.program.display().to_string();
        adapters.push(Adapter::spawn(cfg).map_err(|e| format!("cannot start {program}: {e}"))?);
    }
    let mut diff = Differential::new(adapters, Allowlist::empty(), None);
    diff.set_quiet(true);
    Ok(diff)
}

/// Read a case from a file holding either a bare case or a finding record.
fn read_case(path: &Path) -> Result<(Case, Option<FindingRecord>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    match serde_json::from_str::<FindingRecord>(&text) {
        Ok(record) => Ok((record.case.clone(), Some(record))),
        Err(_) => serde_json::from_str(&text)
            .map(|c| (c, None))
            .map_err(|e| format!("{}: neither a finding nor a case: {e}", path.display())),
    }
}

fn run_one(diff: &mut Differential, case: &Case) -> Vec<diffuzz_types::Verdict> {
    diff.run_batch(std::slice::from_ref(case))
        .pop()
        .map(|r| r.verdicts)
        .unwrap_or_default()
}

fn cmd_minimize(args: &MinimizeArgs) -> Result<bool, String> {
    use diffuzz_triage::bucket::vote_pattern;
    let (case, _) = read_case(&args.case)?;
    let mut diff = build_probe(&args.oracle)?;
    let pattern = vote_pattern(&run_one(&mut diff, &case));
    println!("preserving: {pattern}");
    let (min, stats) = diffuzz_minimize::minimize(
        &case,
        &mut |c| vote_pattern(&run_one(&mut diff, c)) == pattern,
        args.max_attempts,
    );
    let text = serde_json::to_string_pretty(&min).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, text).map_err(|e| format!("{}: {e}", args.out.display()))?;
    println!(
        "{} -> {} bytes in {} oracle calls ({} accepted, {} rounds); wrote {}",
        stats.bytes_before,
        stats.bytes_after,
        stats.attempts,
        stats.accepted,
        stats.rounds,
        args.out.display()
    );
    print!("{}", diffuzz_triage::report::describe_case(&min));
    Ok(true)
}

fn cmd_report(args: &ReportArgs) -> Result<bool, String> {
    use diffuzz_triage::bucket::{Finding, bucketize};
    // The report quotes undisclosed cases, so it must not land in a tracked path.
    let out_dir = args
        .out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    diffuzz_oracle::findings::check_untracked(out_dir)?;

    let mut files = Vec::new();
    let mut dirs = vec![args.input.clone()];
    if let Ok(rd) = std::fs::read_dir(&args.input) {
        dirs.extend(
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_dir()),
        );
    }
    for dir in dirs {
        // Skip our own output and the private allowlist examples.
        if dir
            .file_name()
            .is_some_and(|n| n == "minimized" || n == "known")
        {
            continue;
        }
        if let Ok(rd) = std::fs::read_dir(&dir) {
            files.extend(
                rd.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "json")),
            );
        }
    }
    files.sort();
    let mut findings = Vec::new();
    for path in &files {
        if let Ok((_, Some(record))) = read_case(path) {
            findings.push(Finding {
                case: record.case,
                verdicts: record.verdicts,
                source: path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            });
        }
    }
    println!(
        "{} finding file(s) under {}",
        findings.len(),
        args.input.display()
    );

    let mut diff = build_probe(&args.oracle)?;
    let buckets = bucketize(
        &findings,
        &mut |c| run_one(&mut diff, c),
        args.per_bucket,
        args.max_attempts,
    );
    let min_dir = out_dir.join("minimized");
    std::fs::create_dir_all(&min_dir).map_err(|e| format!("{}: {e}", min_dir.display()))?;
    let mut paths = Vec::new();
    for (i, b) in buckets.iter().enumerate() {
        let path = min_dir.join(format!("bucket-{:02}.json", i + 1));
        let text = serde_json::to_string_pretty(&b.representative).map_err(|e| e.to_string())?;
        std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        paths.push(path.display().to_string().replace('\\', "/"));
    }
    let text = diffuzz_triage::report::render(&buckets, &args.oracle.impls.join(","), &paths);
    std::fs::write(&args.out, text).map_err(|e| format!("{}: {e}", args.out.display()))?;
    for (i, b) in buckets.iter().enumerate() {
        println!("bucket {:>2}: {:>6} finding(s)  {}", i + 1, b.count, b.key);
    }
    println!("report written to {}", args.out.display());
    Ok(true)
}

fn cmd_export(args: &CheckArgs) -> Result<bool, String> {
    let (case, _) = read_case(&args.case)?;
    let mut diff = build_probe(&args.oracle)?;
    let verdicts = run_one(&mut diff, &case);
    // The first implementation listed is the reference for "valid" or "invalid".
    let reference = verdicts.first().ok_or("no implementation answered")?;
    let valid = reference
        .outcome
        .accepted()
        .ok_or_else(|| format!("{} gave no verdict for this case", reference.impl_name))?;
    let vector =
        diffuzz_triage::report::export_tx_vector(&case, valid).ok_or("case cannot be decoded")?;
    eprintln!(
        "{} {} this case: format is tx_{}.json",
        reference.impl_name,
        if valid { "accepts" } else { "rejects" },
        if valid { "valid" } else { "invalid" }
    );
    if valid {
        eprintln!(
            "note: Core's tx_valid test also applies policy flags; run Core's test suite on it."
        );
    }
    println!("{vector}");
    Ok(true)
}

fn load_weights(path: &Path) -> Result<Weights, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Weights::from_toml(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Weights::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn cmd_replay(args: &ReplayArgs) -> Result<bool, String> {
    let mut diff = build_oracle(&args.oracle)?;
    let mut clean = true;
    for path in &args.vectors {
        let loaded = replay::load_file(path)?;
        let report = replay::run(&path.display().to_string(), &loaded, &mut diff);
        print!("{}", replay::render(&report, args.max_listed));
        clean &= report.clean();
    }
    print!("{}", diff.metrics.render());
    println!(
        "{}",
        if clean {
            "RESULT: clean"
        } else {
            "RESULT: MISMATCHES OR FINDINGS"
        }
    );
    Ok(clean)
}

fn cmd_gen(args: &GenArgs) -> Result<bool, String> {
    let mix = Mix::new(
        load_weights(&args.opts.weights)?,
        fuzz::corpus_seeds(&args.opts.corpus),
    );
    std::fs::create_dir_all(&args.out).map_err(|e| format!("{}: {e}", args.out.display()))?;
    let path = args.out.join("cases.jsonl");
    let file = std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = std::io::BufWriter::new(file);
    let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for n in 0..args.count {
        let case = mix.case(args.opts.seed, n);
        *counts.entry(category(&case).to_string()).or_insert(0) += 1;
        serde_json::to_writer(&mut out, &case).map_err(|e| e.to_string())?;
        out.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())?;
    let manifest = serde_json::json!({
        "seed": args.opts.seed,
        "count": args.count,
        "generator_version": env!("CARGO_PKG_VERSION"),
        "mutation_seeds": mix.mutator().seed_count(),
        "categories": counts,
        "regenerate": "case n is Mix::case(seed, n); it does not depend on other cases",
    });
    let manifest_path = args.out.join("manifest.json");
    let text = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    std::fs::write(&manifest_path, text)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    println!(
        "seed {}: wrote {} cases to {}",
        args.opts.seed,
        args.count,
        path.display()
    );
    for (cat, n) in &counts {
        println!("  {cat:<14} {n}");
    }
    Ok(true)
}

fn cmd_fuzz(args: &FuzzArgs) -> Result<bool, String> {
    if args.count.is_none() && args.duration.is_none() {
        return Err("give --count or --duration".to_string());
    }
    let cfg = fuzz::FuzzConfig {
        seed: args.opts.seed,
        count: args.count,
        duration: args.duration,
        workers: args.workers,
        weights: load_weights(&args.opts.weights)?,
        seeds: fuzz::corpus_seeds(&args.opts.corpus),
        feedback: !args.no_feedback,
        stop_on_divergence: !args.keep_going,
        max_findings: args.max_findings,
        report_every: Duration::from_secs(args.report_secs.max(1)),
        required_flags: args.require_flags.clone(),
    };
    eprintln!(
        "fuzz: seed {} workers {} impls {} mutation seeds {}",
        cfg.seed,
        cfg.workers,
        args.oracle.impls.join(","),
        cfg.seeds.len()
    );
    let summary = fuzz::run(&cfg, || build_oracle(&args.oracle))?;
    print!("{}", fuzz::render(&summary));
    if let Some(path) = &args.summary {
        let text = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("summary written to {}", path.display());
    }
    let findings = ["HARD_DIVERGE", "CRASH", "TIMEOUT"]
        .iter()
        .map(|c| summary.classes.get(*c).copied().unwrap_or(0))
        .sum::<u64>();
    if findings > 0 {
        println!(
            "RESULT: {findings} finding(s). Review {} privately before sharing anything.",
            args.oracle.findings_dir.display()
        );
    } else {
        println!("RESULT: no divergence, crash or timeout");
    }
    Ok(findings == 0)
}

fn cmd_check(args: &CheckArgs) -> Result<bool, String> {
    let text =
        std::fs::read_to_string(&args.case).map_err(|e| format!("{}: {e}", args.case.display()))?;
    // Accept either a bare case or a finding record wrapping one.
    let case: Case = match serde_json::from_str::<FindingRecord>(&text) {
        Ok(record) => record.case,
        Err(_) => serde_json::from_str(&text)
            .map_err(|e| format!("{}: neither a finding nor a case: {e}", args.case.display()))?,
    };
    let mut diff = build_oracle(&args.oracle)?;
    diff.set_quiet(true);
    let result = diff
        .run_batch(std::slice::from_ref(&case))
        .pop()
        .ok_or("no result")?;
    println!(
        "flags: {}",
        case.flags
            .iter()
            .map(|f| f.name())
            .collect::<Vec<_>>()
            .join(",")
    );
    for v in &result.verdicts {
        println!("{:<10} {:<40} {:?}", v.impl_name, v.impl_version, v.outcome);
    }
    println!("class: {}", result.class);
    if let Some(id) = &result.known_id {
        println!("known divergence: {id}");
    }
    Ok(!result.class.is_finding())
}

fn cmd_summarize(args: &SummarizeArgs) -> Result<bool, String> {
    let mut parts = Vec::new();
    for path in &args.inputs {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let part: fuzz::Summary =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        parts.push(part);
    }
    let merged = fuzz::merge(&parts);
    let text = serde_json::to_string_pretty(&merged).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, text).map_err(|e| format!("{}: {e}", args.out.display()))?;
    print!("{}", fuzz::render(&merged));
    println!(
        "merged {} segment(s) into {}",
        parts.len(),
        args.out.display()
    );
    Ok(true)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Replay(args) => cmd_replay(args),
        Command::Gen(args) => cmd_gen(args),
        Command::Fuzz(args) => cmd_fuzz(args),
        Command::Check(args) => cmd_check(args),
        Command::Summarize(args) => cmd_summarize(args),
        Command::Minimize(args) => cmd_minimize(args),
        Command::Report(args) => cmd_report(args),
        Command::ExportCoreVector(args) => cmd_export(args),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
        assert!(parse_duration("1d").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("").is_err());
        assert_eq!(parse_flag("DERSIG"), Ok(diffuzz_types::Flag::Dersig));
        assert!(parse_flag("LOW_S").unwrap_err().contains("policy"));
        assert!(parse_flag("nope").is_err());
    }

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
