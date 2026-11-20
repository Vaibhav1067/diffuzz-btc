# Architecture

`diffuzz-btc` feeds identical cases to several independent Bitcoin implementations and reports
any disagreement on accept/reject. This document summarizes the design; `CLAUDE.md` is the
authoritative spec.

## What a case is

A case is everything needed to verify one transaction input:

- the serialized spending transaction,
- the index of the input under test,
- **all** outputs the transaction spends (script + amount, aligned with the inputs; taproot
  sighashes commit to every one of them),
- a set of consensus verification flags.

A case is a single self-contained JSON object, so any divergence can be replayed from one file
plus pinned adapter versions.

## Components

```
            +-----------+     +---------+
 vectors -> |  corpus   | --> |         |        +--------------------+
            +-----------+     |         | -----> | adapter: core-rs   |  Bitcoin Core consensus
            +-----------+     | oracle  |        +--------------------+
 seed ----> |    gen    | --> |         | -----> | adapter: btcd-go   |  btcd txscript
            +-----------+     |         |        +--------------------+
                              |         | -----> | adapter: libbitcoin|  libbitcoin-system v4 (Docker)
                              |         |        +--------------------+
                              |         | -----> | adapter: core-kern.|  current Core, libbitcoinkernel (Docker)
                              +----+----+        +--------------------+
                                   |
                     divergences   v
                              +---------+     +----------+     +--------+
                              | triage  | <-- | minimize |     | report |
                              +---------+     +----------+     +--------+
```

| Path | Role |
|---|---|
| `crates/types` | `Case`, `Flag`, `Prevout`, `Verdict`, `ErrorClass`, wire-protocol structs |
| `crates/corpus` | Loaders for Core's JSON vectors and the BIP-341 vectors |
| `crates/gen` | Seeded, structure-aware generators and mutators |
| `crates/oracle` | Adapter process manager, differential comparison, allowlist matching |
| `crates/minimize` | Delta-debugging minimizer that preserves the divergence signature |
| `crates/triage` | Bucketing, deduplication, report writer |
| `crates/cli` | The `diffuzz` binary |
| `adapters/*` | One subprocess per implementation, written in its native language |
| `fuzz/` | cargo-fuzz targets (separate workspace) |
| `vectors/` | Seed vectors at pinned upstream commits, see `vectors/SOURCES.md` |
| `known_divergences/` | Allowlist of benign, cited differences |
| `findings/private/` | Gitignored. Unreviewed divergences land here first |

## Adapters and the wire protocol

Each implementation runs as a long-lived subprocess. The orchestrator writes one JSON request per
line to its stdin and reads one JSON response per line from its stdout.

Request:

```json
{"id": 42, "tx_hex": "0200...", "input_index": 0,
 "prevouts": [{"script_pubkey_hex": "76a9...88ac", "amount_sats": 100000}],
 "flags": ["P2SH", "DERSIG", "NULLDUMMY", "CLTV", "CSV", "WITNESS", "TAPROOT"]}
```

Response:

```json
{"id": 42, "ok": false, "error_class": "SIG_NULLFAIL", "raw_error": "...",
 "impl": "btcd", "impl_version": "v0.24.x"}
```

- `ok` is the only field the oracle compares. `error_class` is a normalized category for
  statistics and bucketing; `raw_error` is for humans.
- Malformed input must not crash an adapter: it answers `ok:false, error_class:"DESERIALIZE"`.
- A crash or timeout is its own outcome (`CRASH` / `TIMEOUT`), never folded into accept/reject.
- Flag names are an abstract enum; each adapter maps them to its implementation's flags. The
  table lives in `docs/flag-mapping.md`.
- A length-prefixed binary protocol (v2) is added only if measurement shows JSON is the
  bottleneck.

## Comparison semantics

1. Every enabled adapter gets the same case with the same flags.
2. If all agree on `ok`: `AGREE_OK` or `AGREE_FAIL`.
3. Otherwise it is a divergence. If it matches an entry in `known_divergences/` it is `KNOWN`.
4. Anything else is a `HARD_DIVERGE`: written to `findings/private/`, never to a tracked path,
   and work on that class stops until it has been reviewed (responsible disclosure).
5. An adapter crash or timeout is classified `CRASH` / `TIMEOUT`, takes precedence over the
   accept/reject comparison, and is also written to `findings/private/`.
6. An adapter may abstain (`INVALID_FLAGS`, `UNSUPPORTED`) when it cannot evaluate a case
   faithfully. Abstentions do not vote; with fewer than two votes the case is `UNDECIDED`.

The findings writer refuses to start if its directory is inside a git work tree and not ignored.

Only consensus flags are used in the main oracle. Policy/standardness flags (STRICTENC, LOW_S,
MINIMALIF, CLEANSTACK, DISCOURAGE_*, ...) differ between implementations by design and would
drown real signal. A disagreement on a case that carries any policy flag is classified
`UNDECIDED`, never as a finding; there is no policy mode.

## Why these oracles

- **Bitcoin Core** is the reference. It is reached through bindings to its consensus code: 26.0
  through `libbitcoinconsensus` (`core`) and current master through `libbitcoinkernel`
  (`core-kernel`, Docker).
- **btcd `txscript`** is an independent Go reimplementation of the interpreter.
- **libbitcoin-system** is an independent C++ implementation, run in a Docker container.
- **NBitcoin** is a C# implementation that closely follows Core's interpreter structure.
- **rust-bitcoin** has no script interpreter, so it is *not* a script oracle. It takes part only
  in the serialization and sighash differentials.

## Determinism and reproducibility

- All generation takes an explicit seed, logged with every run.
- Rust toolchain, upstream vector commits, and every adapter's implementation version are pinned.
- The Core vectors double as the regression test: every adapter must reproduce their expected
  verdicts before its output is trusted in a differential run.
