//! `diffuzz` command-line entry point.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use diffuzz_oracle::adapter::Adapter;
use diffuzz_oracle::findings::FindingsSink;
use diffuzz_oracle::known::Allowlist;
use diffuzz_oracle::resolve::resolve;
use diffuzz_oracle::runner::Differential;

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
}

#[derive(Args)]
struct ReplayArgs {
    /// Vector files (script_tests.json, tx_valid.json, tx_invalid.json).
    #[arg(long, required = true, num_args = 1..)]
    vectors: Vec<PathBuf>,
    /// Implementations to run, comma separated (e.g. `core` or `core,btcd`).
    #[arg(long = "impls", alias = "impl", required = true, value_delimiter = ',')]
    impls: Vec<String>,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// Maximum mismatches listed per implementation and file.
    #[arg(long, default_value_t = 50)]
    max_listed: usize,
    #[command(flatten)]
    oracle: OracleArgs,
}

/// Options shared by every command that runs the differential oracle.
#[derive(Args)]
struct OracleArgs {
    /// Directory of known-divergence TOML entries.
    #[arg(long, default_value = "known_divergences")]
    known_dir: PathBuf,
    /// Private directory for hard divergences, crashes and timeouts. Must be git-ignored.
    #[arg(long, default_value = "findings/private")]
    findings_dir: PathBuf,
}

/// Start the adapters and build the differential runner.
fn build_oracle(
    impls: &[String],
    timeout_ms: u64,
    args: &OracleArgs,
) -> Result<Differential, String> {
    let mut adapters = Vec::new();
    for name in impls {
        let mut cfg = resolve(name)?;
        cfg.timeout = Duration::from_millis(timeout_ms);
        let program = cfg.program.display().to_string();
        adapters.push(Adapter::spawn(cfg).map_err(|e| format!("cannot start {program}: {e}"))?);
    }
    let allowlist = Allowlist::load_dir(&args.known_dir, std::path::Path::new("."))?;
    let sink = FindingsSink::new(&args.findings_dir)?;
    Ok(Differential::new(adapters, allowlist, Some(sink)))
}

fn cmd_replay(args: &ReplayArgs) -> Result<bool, String> {
    let mut diff = build_oracle(&args.impls, args.timeout_ms, &args.oracle)?;
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Replay(args) => cmd_replay(args),
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
