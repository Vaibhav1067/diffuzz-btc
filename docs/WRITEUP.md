# diffuzz-btc: write-up

A differential fuzzer for Bitcoin consensus. It feeds identical (transaction, spent outputs,
input index, consensus flags) cases to independent implementations of the script interpreter
and reports any disagreement on accept/reject. A secondary harness does the same for
transaction decoding and signature hashes.

This document covers what was built, how it was tested, what it found, and its limitations.
Design details are in `architecture.md`, `flag-mapping.md`, `generators.md` and
`aux-protocol.md`.

## 1. What is compared

| Surface | Implementations | Harness |
|---|---|---|
| Script verification (legacy, P2SH, segwit v0, taproot key and script path) | Bitcoin Core 26.0 (`libbitcoinconsensus`), current Bitcoin Core master 70d9ec7f3d4 (`libbitcoinkernel`), btcd `txscript/v2` v2.0.1, NBitcoin 10.0.21, libbitcoin-system v4.0.10537 | `diffuzz replay`, `diffuzz fuzz` |
| Transaction decoding, legacy / BIP143 / BIP341 signature hashes | rust-bitcoin 0.32.102, btcd, NBitcoin (Core abstains: its library exposes neither) | `diffuzz aux` |
| Our own transaction parser and sighash code vs rust-bitcoin, in-process | `crates/types`, `crates/gen` vs rust-bitcoin | cargo-fuzz targets in `fuzz/` |

Each implementation runs as a long-lived subprocess speaking line-delimited JSON. Only the
`ok` field is compared. Error classes are normalized for bucketing but never voted on, because
implementations legitimately report the same failure differently.

Only the seven consensus flags are used (`P2SH`, `DERSIG`, `NULLDUMMY`, `CLTV`, `CSV`,
`WITNESS`, `TAPROOT`). Policy flags differ between implementations by design and would bury
real signal.

Of the four interpreters, btcd and libbitcoin are independent designs; NBitcoin follows the
structure of Core's interpreter closely. libbitcoin runs in a digest-pinned Docker container
built from source (`docker/libbitcoin.Dockerfile`), without network access. Current Core runs
the same way (`docker/core-kernel.Dockerfile`) as a fifth voter beside Core 26.0.

## 2. Methodology

**Ground truth first.** Before an adapter's answers are trusted, it must reproduce the
expected verdict of every runnable vector in Core's `script_tests.json`, `tx_valid.json` and
`tx_invalid.json` (Core v32.1). Core, btcd and NBitcoin pass all 963 runnable vectors (1029
cases); libbitcoin passes 956 and abstains on 7 that carry witness data with `WITNESS` off, a
state that cannot occur on chain (libbitcoin rejects it, Core ignores the witness). 488 vectors are skipped because their verdict depends on policy flags or on
context-free transaction checks that are not script verification (`corpus-results.md`). The
aux adapters must reproduce all 500 digests of Core's `sighash.json` and the 7 key-path digests
of the BIP341 wallet vectors; they do.

**Structure-aware generation.** Random bytes rarely get past a script's first opcode and never
produce a valid signature. Five seeded generators (`generators.md`) build nearly valid spends
with real ECDSA and Schnorr signatures from deterministic test keys, then perturb them in one or
two deliberate ways: a script grammar that tracks stack types, signature templates under every
wrapper, P2SH and segwit wrappers, fourteen taproot templates (annex, `OP_SUCCESSx`,
`OP_CHECKSIGADD`, unknown leaf versions, the sigops budget, control-block corruption), and a
mutator seeded with Core's vectors. A test calls Core in-process and asserts that each template
is accepted in its valid form, so the success paths are reached.

**Re-signing.** Half of all mutants get fresh signatures from the test keys over the mutated
transaction (`crates/gen/src/resign.rs`), so mutations of signed data still reach success
paths. A test requires every broken valid spend to verify in Core again after re-signing; on
20,000 mutations of generated cases it raised Core's accept rate from 18.9% to 29.2%.

**Feedback.** The targets are not instrumented. `diffuzz fuzz` keeps cases with a new
signature: (each implementation's outcome, set of non-push opcodes, output type). This rewards
new error classes and opcode combinations, not branch coverage.

**Reproducibility.** All generation is seeded and logged; case `n` of seed `s` can be
regenerated alone. Every divergence is saved as one self-contained JSON case, and every adapter
reports its pinned implementation version.

**Triage.** A divergence that matches no allowlist entry stops the run and is written to
`findings/private/`, which is git-ignored and checked to be ignored at startup. The minimizer
shrinks it by delta debugging while every implementation keeps its verdict. The report writer
buckets findings by verdict signature. Allowlist entries need a description, a citation, an
example case and a reason, and must state the direction of the disagreement.

## 3. Results

Measured on 2026-11-16 to 2026-11-19 on one Windows 11 x86_64 machine with 16 logical cores,
release builds, 12 workers, each worker running its own process per implementation.

### Script verification

| Run | Implementations | Seed | Duration | Cases | Cases/s (aggregate) | AGREE_OK | AGREE_FAIL | KNOWN | HARD_DIVERGE |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | core, btcd | 20261117 | 600 s | 14,396,160 | 23,990 | 5,558,160 | 8,830,614 | 7,386 | 0 |
| B | core, btcd, nbitcoin | 20261120 | 900 s | 14,327,040 | 15,917 | 5,503,862 | 8,789,787 | 33,391 | 0 |
| C | core, btcd, nbitcoin | 20261122 | 3,590 s | 47,467,776 | 13,222 | 18,241,809 | 29,114,418 | 111,549 | 0 |
| D | core, btcd, nbitcoin, libbitcoin | 20261123 | 600 s | 5,577,472 | 9,291 | 2,150,405 | 3,413,947 | 13,120 | 0 |
| E | core, btcd, nbitcoin, libbitcoin | 20261124 | 7,176 s | 68,086,272 | 9,488 | 26,251,953 | 41,675,524 | 158,795 | 0 |
| F | core, btcd, nbitcoin, libbitcoin | 20261125 | 300 s | 2,721,536 | 9,066 | 1,049,588 | 1,665,493 | 6,455 | 0 |
| G | core, btcd, nbitcoin, libbitcoin | 20261127 | 300 s | 3,346,688 | 11,146 | 1,291,915 | 2,046,955 | 7,818 | 0 |
| H | core, core-kernel, btcd, nbitcoin, libbitcoin | 20261128 | 300 s | 2,560,000 | 8,525 | 987,743 | 1,566,208 | 6,049 | 0 |

Run C is `scripts/run_overnight.sh` (six 10-minute segments, re-signing enabled); a Docker
build of libbitcoin overlapped its last segments, so its rate is a lower bound. In run D
libbitcoin, at 1,259 cases/s per process (p50 798 µs, including the container pipe), is the
bottleneck. Run E is twelve 10-minute segments with all four interpreters: per process
Core 3,475/s (p50 258 µs), btcd 2,633/s, NBitcoin 1,879/s and libbitcoin 1,208/s (p50 827 µs),
no process restarts, 1.6 million distinct behavioural signatures.
Run F is the first after the generators began targeting `SIGHASH_SINGLE` without a matching
output on purpose (about 1% of cases, see `generators.md`).
Runs A–F used the skeleton of 1 to 3 inputs and 0 to 3 outputs (up to commit f14253e).
Later commits draw different cases from the same seed; check out that commit to reproduce
these numbers. Run G is the first with the wider skeleton (up to 12 inputs, P2TR among spent
outputs); run H adds current Core, so five interpreters vote on every case.

Per-process rates in run A: Core 13,427/s (p50 72 µs), btcd 5,795/s (p50 151 µs). The
aggregate exceeds the 20k cases/s target in `CLAUDE.md` without a binary protocol, so the JSON
protocol was kept. In run B NBitcoin is the slowest process (3,330/s, p50 284 µs; Core 6,471/s and btcd 4,224/s
while sharing the machine with it).

Corpus replay (all four): 1029 cases, 863 agree-accept, 166 agree-reject, no divergence. Current
Core (`core-kernel`) passes all 963 runnable vectors as well, identically to Core 26.0.

In total, about 150 million generated script cases ran through the differential in these runs,
plus earlier development runs.

### Transaction decoding and signature hashes

| Run | Checks | Divergences after adapter fixes | Crashes / timeouts |
|---|---:|---:|---:|
| Upstream vectors | 1,140 | 0 | 0 |
| Generated, seeds 1, 2, 3 (100k each) | 300,000 | 0 | 0 |
| Generated, seed 20261116 | 500,000 | 0 | 0 |
| Upstream vectors plus 100k generated, libbitcoin as fifth implementation, seed 20261120 | 101,140 | 0 | 0 |

Generated checks include annexes, script-path leaves, undefined hash types,
`SIGHASH_SINGLE` without a matching output, out-of-range input indexes, unparsable scriptCodes
and byte-mutated transactions.

### What was found

Every divergence is triaged privately before anything about it is published (the project's
disclosure rule). This section lists only what has been cleared for publication.

1. **Adapter preconditions (fixed).** Places where a library's API means something other than
   the wire protocol: btcd's `CalcSignatureHash` refuses unparsable scriptCode; btcd's
   `NewTxSigHashes` skips the taproot midstate when no prevout is P2TR; btcd's
   `CalcWitnessSigHash` rewrites a P2WPKH program into a P2PKH scriptCode; NBitcoin's
   `GetSignatureHash` throws on unparsable scriptCode; NBitcoin's `Money` cannot hold an output
   value of `long.MinValue`. Each adapter now abstains on exactly that input, documented in
   `aux-protocol.md`.
2. **Documented library behaviour.** rust-bitcoin serializes zero-input transactions in BIP141
   form by design, so it decodes a witness flag followed by zero inputs, which Core rejects.
   rust-bitcoin 0.32.102 (and master at 271f662a) checks the BIP341 input index only for
   `ANYONECANPAY`; consensus never asks for a sighash of a nonexistent input. Both are handled
   in the rust-bitcoin adapter with citations. A fix for the input-index check, with a test that
   fails without it, is in `upstream/rust-bitcoin-taproot-input-index/`. It was not
   submitted: rust-bitcoin does not accept first-time patches written with an LLM (its
   `CONTRIBUTING.md`), and this one was.
3. **Modelling differences.** libbitcoin rejects witness data on a non-witness spend even with
   segwit inactive; Core ignores it. Unreachable on chain; the adapter abstains.

`KNOWN` in the tables counts cases matched by allowlist entries. Entries are narrow
(direction, flag and case-feature conditions), so any other divergence still stops a run.

## 4. Limitations

- **Not coverage-guided against the implementations.** Feedback is a behavioural signature,
  not branch coverage. Core's C++ is not instrumented, even in the cargo-fuzz targets.
- **Current Core is a development snapshot.** `libbitcoinconsensus` was removed after 26.x, so
  the main Core adapter is 26.0. Current Core runs through `libbitcoinkernel` (`core-kernel`),
  pinned to master at 70d9ec7f3d4 (2026-07), not to a release, and only in Docker. It joined
  in run H, so the long runs A–F compared Core 26.0 only.
- **No block-level checks.** Only per-input script verification: no `CheckTransaction`,
  sigop counting across a block, weight limits, coinbase rules or contextual checks.
- **Independence is partial.** btcd and libbitcoin are independent designs; NBitcoin is a
  close port of Core's structure, so shared misreadings of Core are less likely to show up
  between Core and NBitcoin.
- **Generator gaps** (`generators.md`): at most twelve inputs and six outputs; taproot
  siblings are random hashes rather than real leaves (indistinguishable to a verifier, except
  a sibling equal to its node, which is never generated); the mutator re-signs only signatures
  made with the generator's own test keys, and only half of its mutants.
- **One machine, short runs.** The longest run here is two hours. These rates are for this
  machine only.
- **Allowlist is trust-based.** An entry hides every case matching its conditions. Entries
  are kept narrow, but a second bug with the same shape would be hidden behind the first.
- **Results are not all public.** Divergences still under review are not described here.

## 5. Reproduction

```
cargo build --release
scripts/build_adapters.sh --release          # btcd (Go), NBitcoin (.NET), Rust adapters

# Correctness proof
target/release/diffuzz replay --impls core,btcd,nbitcoin \
  --vectors vectors/core/script_tests.json vectors/core/tx_valid.json vectors/core/tx_invalid.json

# libbitcoin (Docker)
docker build -f docker/libbitcoin.Dockerfile -t diffuzz-libbitcoin .
export DIFFUZZ_ADAPTER_LIBBITCOIN=adapters/libbitcoin-cpp/diffuzz-adapter-libbitcoin.sh   # .cmd on Windows

# Script differential (run A)
target/release/diffuzz fuzz --seed 20261117 --duration 10m --workers 12 --impls core,btcd \
  --summary out/a.json

# Sighash and decoding differential
target/release/diffuzz aux --impls rust-bitcoin,btcd,nbitcoin,core --seed 1 --count 100000

# Results page: one offline HTML file from the summaries above (CI uploads one per push)
target/release/diffuzz replay --json out/replay.json --impls core,btcd,nbitcoin,libbitcoin --vectors ...
target/release/diffuzz aux --json out/aux.json --impls rust-bitcoin,btcd,nbitcoin,core --seed 1 --count 100000
target/release/diffuzz dashboard --run A=out/a.json --replay out/replay.json --aux out/aux.json   --machine "<this machine>" --out out/dashboard.html

# In-process cargo-fuzz targets (nightly)
cd fuzz && cargo +nightly fuzz run sighash_diff -- -max_total_time=600
```

Run B used allowlist entries that are not in the repository; without them it stops at the
first divergence, which is the intended behaviour. On Windows inside a OneDrive folder, build
the Go adapter with `scripts/build_adapters.sh` (it builds from a temporary copy).

Pinned versions: Rust 1.100.0, Core 26.0 via `bitcoinconsensus` 0.106.0+26.0, btcd
`txscript/v2` v2.0.1, NBitcoin 10.0.21, libbitcoin-system v4.0.10537, rust-bitcoin 0.32.102, vectors from Core v32.1
(`f0de87f0`) and bips `b34d9f75` (`vectors/SOURCES.md`).
