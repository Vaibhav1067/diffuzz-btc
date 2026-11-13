# diffuzz-btc

Cross-implementation differential fuzzer for Bitcoin consensus (Script, Taproot, tx/sighash).

## Project goal

Build `diffuzz-btc`, a differential fuzzing framework that feeds identical (transaction, prevouts, input index, consensus flags) cases to multiple independent Bitcoin implementations and reports any disagreement on accept/reject.

Primary surface: the Script interpreter (legacy, P2SH, segwit v0, taproot/tapscript). Secondary surface: transaction/block deserialization round-trips and sighash computation.

Success = a reproducible harness, a large executed-case count, a clean triage pipeline, upstream PRs (test vectors/fixes), and an honest write-up. Finding a real consensus bug is a bonus, not a requirement.

## Hard rules (never violate)

1. **Git/GitHub identity.** NEVER add Claude, an AI, or any bot as a collaborator, co-author, or contributor on any repository. NEVER add `Co-Authored-By:` trailers or "Generated with Claude" lines to commit messages, PR descriptions, or files. All commits are authored solely by the repo's configured git user. Do not change `git config user.name/user.email`. Never invite or add anyone to a repo.
   **Pushing:** standing instruction from the owner (2026-11-13): push to `origin` (https://github.com/Vaibhav1067/diffuzz-btc) often, after each tested commit or small group of commits. Plain `git push` only: never force-push, never push anything covered by rule 2, and never open issues or PRs unless asked in that message.
2. **Responsible disclosure.** If a divergence looks like a real consensus-relevant bug (one implementation accepts what another rejects under consensus flags, and it is not on the known-benign list), STOP. Do not commit it to public paths, do not open an issue or PR, do not paste it into any public place. Write it only to `findings/private/` (gitignored), summarize it to me, and wait for instructions.
3. **No real funds, no mainnet keys.** Use only deterministic test keys derived from fixed seeds. Never connect to mainnet peers from this project. Regtest/signet only, and only if a phase needs it.
4. **Verify, don't assume.** APIs, crate versions, flag names, and library availability change. Before using any dependency, check its actual docs/source (`cargo doc`, `go doc`, the repo README). If something I (or this file) claim does not match reality, tell me and adapt.
5. **Only consensus flags.** Differential comparisons must use consensus-only verification flags. Policy/standardness flags (e.g. STRICTENC, LOW_S, MINIMALIF, CLEANSTACK, DISCOURAGE_*) must NOT be used in the main oracle, because policy differences between implementations are expected and uninteresting. A separate, clearly labeled "policy mode" may exist but is off by default.
6. **Reproducibility.** Every divergence must be reproducible from a single self-contained JSON case file plus pinned adapter versions. No flaky findings.
7. **Small, tested steps.** After each logical unit: build, run tests, run clippy/fmt (Rust) and `go vet`/`gofmt` (Go), then commit with a clear message. Never leave the tree broken.
8. **Ask when blocked.** If a design choice has real tradeoffs or a dependency is unavailable, ask me one concise question rather than guessing silently.

## Important design facts (already verified by the author, re-verify anyway)

* `rust-bitcoin` does NOT contain a script interpreter. It provides serialization, sighash, and (via the `bitcoinconsensus` feature) bindings to Core's consensus library. So rust-bitcoin is used for tx/block (de)serialization and sighash differentials, NOT as an independent script-execution oracle.
* Independent script interpreters available as oracles: Bitcoin Core (via libbitcoinconsensus or libbitcoinkernel bindings; check which are available for the pinned version, as libbitcoinconsensus has been deprecated/removed in newer Core releases), btcd `txscript` (Go), libbitcoin-system (C++), and optionally rust-miniscript's interpreter for miniscript-shaped cases.
* Bitcoin Core's repo contains canonical JSON test vectors (`src/test/data/`: `script_tests.json`, `tx_valid.json`, `tx_invalid.json`, `sighash.json`) and BIP-341 wallet test vectors live in the BIPs repo. These are the seed corpus and the sanity check for every adapter.

## Architecture

Rust workspace for the orchestrator; each implementation is wrapped in a long-lived adapter subprocess speaking a tiny line-delimited JSON protocol over stdin/stdout. Adapters are written in the implementation's native language.

```
diffuzz-btc/
  CLAUDE.md
  Cargo.toml                 # workspace
  rust-toolchain.toml        # pinned stable
  crates/
    types/                   # Case, Flags, Prevout, Verdict, protocol structs, serde
    corpus/                  # loaders for Core JSON vectors + BIP341 vectors
    gen/                     # structure-aware generators and mutators
    oracle/                  # adapter process manager, comparison, normalization, allowlist
    minimize/                # delta-debugging case minimizer
    triage/                  # dedupe/bucket divergences, report writer
    cli/                     # `diffuzz` binary (run, replay, fuzz, minimize, report)
  adapters/
    core-rs/                 # Rust adapter around Core consensus lib bindings
    btcd-go/                 # Go adapter around btcd txscript
    libbitcoin-cpp/          # C++ adapter (later phase)
  fuzz/                      # cargo-fuzz targets (libFuzzer) using `arbitrary`
  vectors/                   # seed vectors fetched by script (record source + commit hash)
  known_divergences/         # allowlist of benign, documented differences (TOML)
  findings/
    public/                  # sanitized, disclosed findings only
    private/                 # GITIGNORED. Anything suspicious goes here first
  docs/                      # architecture, methodology, flag-mapping table, write-up
  scripts/                   # fetch_vectors.sh, build_adapters.sh, run_overnight.sh
  docker/                    # reproducible build images pinning each implementation
  .github/workflows/ci.yml
```

## Wire protocol (v1, line-delimited JSON)

Request (one JSON object per line):

```json
{"id": 42,
 "tx_hex": "0200...",
 "input_index": 0,
 "prevouts": [{"script_pubkey_hex": "76a9...88ac", "amount_sats": 100000}],
 "flags": ["P2SH", "DERSIG", "NULLDUMMY", "CLTV", "CSV", "WITNESS", "TAPROOT"]}
```

Response:

```json
{"id": 42, "ok": false, "error_class": "SIG_NULLFAIL", "raw_error": "implementation specific text", "impl": "btcd", "impl_version": "v0.24.x"}
```

* `ok` is the ONLY field compared in the main oracle. `error_class` is a normalized, informational category; `raw_error` is for humans.
* Taproot verification needs ALL spent outputs of the transaction (not just the one being spent), which is why `prevouts` is a full array aligned with tx inputs.
* Adapters must handle malformed input without crashing: return `ok:false, error_class:"DESERIALIZE"`. An adapter crash or timeout is itself recorded as a finding class (`CRASH`/`TIMEOUT`), kept separate from accept/reject divergences.
* Flag names are an abstract enum in `types`; each adapter owns the mapping to its implementation's flags. The mapping table lives in `docs/flag-mapping.md` and must be kept accurate.
* If JSON throughput becomes the bottleneck (target: at least 20k cases/sec aggregate with batching), add a length-prefixed binary protocol v2. Do not optimize before measuring.

## Comparison semantics

* Run each case through all enabled adapters with identical flags.
* A divergence = not all adapters agree on `ok`.
* A hard divergence = disagreement under consensus flags with no allowlist match. These go to `findings/private/` automatically and trigger rule 2.
* Allowlist entries (`known_divergences/*.toml`) require: description, affected implementations, minimal example case, link/reference, and the reason it is benign (e.g. library not supporting a deployment flag, known upstream issue). No entry without a citation.

## Coding standards

* Rust: stable, `#![forbid(unsafe_code)]` everywhere except adapter FFI boundaries (document each unsafe block). `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test` must pass.
* Go: `gofmt`, `go vet`, `go test ./...`.
* Determinism: all random generation takes an explicit seed; log the seed with every run. Same seed + same versions = same cases.
* Every public function in `types`, `oracle`, `gen` has a doc comment and at least one test.
* Error handling: no `unwrap()` in non-test code outside obviously-infallible spots.
* CI (GitHub Actions): fmt, clippy, tests, adapter build, and a 60-second smoke fuzz run.

## Definition of done for the whole project

* At least 2 independent script-interpreter oracles (Core + btcd) running in the main comparison; third (libbitcoin) is a stretch.
* All Core vectors in `script_tests.json`, `tx_valid.json`, `tx_invalid.json` pass through every adapter with the expected verdict, with remaining mismatches either fixed or allowlisted with citations.
* Structure-aware generators covering legacy, P2SH, P2WPKH/P2WSH, and taproot (key path + script path) including annex, `OP_SUCCESSx`, `OP_CHECKSIGADD`, unknown leaf versions, and the tapscript sigops budget.
* Minimizer reduces any divergence to a small readable case.
* A published benchmark: total cases executed, cases/sec, divergence counts by class, coverage notes.
* `docs/WRITEUP.md` with methodology, results, limitations (honest), and reproduction instructions.
