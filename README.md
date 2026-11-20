# diffuzz-btc

A differential fuzzer for Bitcoin consensus. It feeds identical (transaction, spent outputs,
input index, consensus flags) cases to independent implementations of the script interpreter
and reports any disagreement on accept or reject. A second harness does the same for
transaction decoding and signature hashes.

| Surface | Implementations |
|---|---|
| Script verification: legacy, P2SH, segwit v0, taproot key and script path | Bitcoin Core 26.0 (`libbitcoinconsensus`), current Bitcoin Core master (`libbitcoinkernel`, Docker), btcd `txscript/v2` v2.0.1, NBitcoin 10.0.21, libbitcoin-system v4.0.10537 |
| Transaction decoding, legacy / BIP143 / BIP341 signature hashes | rust-bitcoin 0.32.102, btcd, NBitcoin, libbitcoin (Core abstains: its library exposes neither) |

Results so far (one Windows machine, November 2026): about 218 million generated script cases
across nine runs with no unexplained divergence, every adapter reproducing Bitcoin Core's own
test vectors, and over 900,000 sighash and decoding checks. Methodology, numbers and
limitations are in [docs/WRITEUP.md](docs/WRITEUP.md).

## Quick start

Requirements: Rust (pinned in `rust-toolchain.toml`), Go (version in `adapters/btcd-go/go.mod`),
the .NET SDK for the NBitcoin adapter, and Docker for the libbitcoin adapter (optional).

```
cargo build --release
scripts/build_adapters.sh --release
docker build -f docker/libbitcoin.Dockerfile -t diffuzz-libbitcoin .        # optional
docker build -f docker/core-kernel.Dockerfile -t diffuzz-core-kernel .     # optional, current Core
export DIFFUZZ_ADAPTER_LIBBITCOIN=adapters/libbitcoin-cpp/diffuzz-adapter-libbitcoin.sh
export DIFFUZZ_ADAPTER_CORE_KERNEL=adapters/core-kernel-rs/diffuzz-adapter-core-kernel.sh
```

Prove every adapter against Core's vectors first:

```
target/release/diffuzz replay --impls core,btcd,nbitcoin,libbitcoin \
  --vectors vectors/core/script_tests.json vectors/core/tx_valid.json vectors/core/tx_invalid.json
```

Then fuzz:

```
target/release/diffuzz fuzz --seed 1 --duration 10m --workers 8 \
  --impls core,btcd,nbitcoin,libbitcoin --summary out/run.json
target/release/diffuzz aux --impls rust-bitcoin,btcd,nbitcoin,libbitcoin,core \
  --seed 1 --count 100000 --json out/aux.json
target/release/diffuzz dashboard --run out/run.json --aux out/aux.json --out out/dashboard.html
```

`scripts/run_overnight.sh <hours> [workers] [seed]` runs long, segmented campaigns.

## Commands

| Command | What it does |
|---|---|
| `replay` | Runs Core's vector files through the adapters and checks each expected verdict |
| `fuzz` | Generates seeded cases and runs the differential, with behavioural feedback |
| `aux` | Sighash and decoding differential over upstream vectors plus generated checks |
| `check` | Runs one saved case through the adapters and prints every verdict |
| `minimize` | Shrinks a diverging case while every implementation keeps its verdict |
| `report` | Buckets saved findings by root cause and writes a report |
| `gen` | Writes generated cases as JSON lines |
| `dashboard` | Writes a self-contained HTML results page from run summaries |
| `summarize`, `export-core-vector` | Merge segment summaries; print a case in Core's vector format |

## Layout

```
crates/types     cases, flags, verdicts, wire protocol, tx/script/taproot helpers
crates/corpus    loaders for Core's and BIP341's vectors
crates/gen       seeded structure-aware generators, mutator, re-signing, sighash code
crates/oracle    adapter processes, comparison, allowlist, private findings sink
crates/minimize  delta-debugging minimizer
crates/triage    bucketing, case features, report writer
crates/cli       the diffuzz binary and the dashboard template
adapters/        core-rs, core-kernel-rs, btcd-go, nbitcoin-cs, libbitcoin-cpp, rust-bitcoin
fuzz/            cargo-fuzz targets (nightly)
vectors/         pinned upstream vectors, see vectors/SOURCES.md
docs/            architecture, flag mapping, generators, aux protocol, corpus results, write-up
upstream/        upstream fixes kept as a record (not submitted; see its README)
```

## How findings are handled

Only consensus flags are compared, and only accept or reject. A disagreement that matches no
documented allowlist entry stops the run and is written to `findings/private/`, which is
git-ignored and checked at startup. Anything that may be consensus-relevant is reported to the
affected project privately before anything about it is published.

## Documentation

- [docs/WRITEUP.md](docs/WRITEUP.md): methodology, results, limitations, reproduction
- [docs/architecture.md](docs/architecture.md), [docs/flag-mapping.md](docs/flag-mapping.md),
  [docs/generators.md](docs/generators.md), [docs/aux-protocol.md](docs/aux-protocol.md),
  [docs/corpus-results.md](docs/corpus-results.md)
- [DESIGN.md](DESIGN.md): the dashboard's design system

There is no licence file yet.
