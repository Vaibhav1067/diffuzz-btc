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
| Script verification (legacy, P2SH, segwit v0, taproot key and script path) | Bitcoin Core 26.0 (`libbitcoinconsensus`), btcd `txscript/v2` v2.0.1, NBitcoin 10.0.21 | `diffuzz replay`, `diffuzz fuzz` |
| Transaction decoding, legacy / BIP143 / BIP341 signature hashes | rust-bitcoin 0.32.102, btcd, NBitcoin (Core abstains: its library exposes neither) | `diffuzz aux` |
| Our own transaction parser and sighash code vs rust-bitcoin, in-process | `crates/types`, `crates/gen` vs rust-bitcoin | cargo-fuzz targets in `fuzz/` |

Each implementation runs as a long-lived subprocess speaking line-delimited JSON. Only the
`ok` field is compared. Error classes are normalized for bucketing but never voted on, because
implementations legitimately report the same failure differently.

Only the seven consensus flags are used (`P2SH`, `DERSIG`, `NULLDUMMY`, `CLTV`, `CSV`,
`WITNESS`, `TAPROOT`). Policy flags differ between implementations by design and would bury
real signal.

libbitcoin-system, the planned third interpreter, was not built. NBitcoin was used instead
(reasons in `flag-mapping.md`). NBitcoin follows the structure of Core's interpreter closely, so
it is less independent than btcd's from-scratch design.

## 2. Methodology

**Ground truth first.** Before an adapter's answers are trusted, it must reproduce the
expected verdict of every runnable vector in Core's `script_tests.json`, `tx_valid.json` and
`tx_invalid.json` (Core v32.1). All three interpreters pass all 963 runnable vectors (1029
cases); 488 vectors are skipped because their verdict depends on policy flags or on
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

Measured on 2026-11-16 to 2026-11-18 on one Windows 11 x86_64 machine with 16 logical cores,
release builds, 12 workers, each worker running its own process per implementation.

### Script verification

| Run | Implementations | Seed | Duration | Cases | Cases/s (aggregate) | AGREE_OK | AGREE_FAIL | KNOWN | HARD_DIVERGE |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | core, btcd | 20261117 | 600 s | 14,396,160 | 23,990 | 5,558,160 | 8,830,614 | 7,386 | 0 |
| B | core, btcd, nbitcoin | 20261120 | 900 s | 14,327,040 | 15,917 | 5,503,862 | 8,789,787 | 33,391 | 0 |

Per-process rates in run A: Core 13,427/s (p50 72 µs), btcd 5,795/s (p50 151 µs). The
aggregate exceeds the 20k cases/s target in `CLAUDE.md` without a binary protocol, so the JSON
protocol was kept. In run B NBitcoin is the slowest process (3,330/s, p50 284 µs; Core 6,471/s and btcd 4,224/s
while sharing the machine with it).

Corpus replay (all three): 1029 cases, 863 agree-accept, 166 agree-reject, no divergence.

### Transaction decoding and signature hashes

| Run | Checks | Divergences after adapter fixes | Crashes / timeouts |
|---|---:|---:|---:|
| Upstream vectors | 1,140 | 0 | 0 |
| Generated, seeds 1, 2, 3 (100k each) | 300,000 | 0 | 0 |
| Generated, seed 20261116 | 500,000 | 0 | 0 |

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
   in the rust-bitcoin adapter with citations.

`KNOWN` in the tables counts cases matched by allowlist entries. Entries are narrow
(direction, flag and case-feature conditions), so any other divergence still stops a run.

## 4. Limitations

- **Not coverage-guided against the implementations.** Feedback is a behavioural signature,
  not branch coverage. Core's C++ is not instrumented, even in the cargo-fuzz targets.
- **Core 26.0, not current Core.** `libbitcoinconsensus` was removed after 26.x; the adapter
  uses the last release that has it. Consensus code changes since then are not covered.
- **No block-level checks.** Only per-input script verification: no `CheckTransaction`,
  sigop counting across a block, weight limits, coinbase rules or contextual checks.
- **Two truly independent interpreters.** btcd is a reimplementation; NBitcoin is a close port
  of Core's structure. libbitcoin was not built.
- **Generator gaps** (`generators.md`): at most three inputs and outputs, no multi-leaf taproot
  trees with more than one known leaf, the mutator does not re-sign.
- **One machine, short runs.** The longest runs here are 10 to 15 minutes, plus earlier
  overnight segments. These rates are for this machine only.
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

# Script differential (run A)
target/release/diffuzz fuzz --seed 20261117 --duration 10m --workers 12 --impls core,btcd \
  --summary out/a.json

# Sighash and decoding differential
target/release/diffuzz aux --impls rust-bitcoin,btcd,nbitcoin,core --seed 1 --count 100000

# In-process cargo-fuzz targets (nightly)
cd fuzz && cargo +nightly fuzz run sighash_diff -- -max_total_time=600
```

Run B used allowlist entries that are not in the repository; without them it stops at the
first divergence, which is the intended behaviour. On Windows inside a OneDrive folder, build
the Go adapter with `scripts/build_adapters.sh` (it builds from a temporary copy).

Pinned versions: Rust 1.100.0, Core 26.0 via `bitcoinconsensus` 0.106.0+26.0, btcd
`txscript/v2` v2.0.1, NBitcoin 10.0.21, rust-bitcoin 0.32.102, vectors from Core v32.1
(`f0de87f0`) and bips `b34d9f75` (`vectors/SOURCES.md`).
