# Corpus results

Every adapter must reproduce the expected verdict of Bitcoin Core's own test vectors before its
answers are trusted in a differential run. This is the harness's correctness proof and its
regression test: re-run it after any adapter, loader or generator change.

```
scripts/build_adapters.sh --release
cargo run --release -p diffuzz-cli -- replay \
  --vectors vectors/core/script_tests.json vectors/core/tx_valid.json vectors/core/tx_invalid.json \
  --impls core,btcd,nbitcoin
```

Vectors: Bitcoin Core v32.1 (`f0de87f0`), see `vectors/SOURCES.md`.
Last run: 2026-11-13, Windows 11 x86_64 (also run on every push by CI on Linux).

## Results

| File | Entries | Comments | Runnable vectors | Cases | Skipped |
|---|---:|---:|---:|---:|---:|
| `script_tests.json` | 1292 | 55 | 772 | 772 | 465 |
| `tx_valid.json` | 250 | 129 | 121 | 176 | 0 |
| `tx_invalid.json` | 201 | 108 | 70 | 81 | 23 |
| **Total** | 1743 | 292 | **963** | **1029** | 488 |

A transaction vector yields one case per input; a valid vector needs every input accepted, an
invalid one needs at least one input rejected.

| Implementation | Version | Passed | Failed | Abstained | Crashes | Timeouts |
|---|---|---:|---:|---:|---:|---:|
| `core` | libbitcoinconsensus 26.0 (`bitcoinconsensus` 0.106.0+26.0) | 963 / 963 | 0 | 0 | 0 | 0 |
| `btcd` | txscript/v2 v2.0.1 | 963 / 963 | 0 | 0 | 0 | 0 |
| `nbitcoin` | NBitcoin 10.0.21 | 963 / 963 | 0 | 0 | 0 | 0 |
| `libbitcoin` | libbitcoin-system v4.0.10537 (added 2026-11-18) | 956 / 963 | 0 | 7 | 0 | 0 |
| `core-kernel` | Core master 70d9ec7f3d4, libbitcoinkernel (added 2026-11-19) | 963 / 963 | 0 | 0 | 0 | 0 |

libbitcoin's 7 abstentions are inputs with witness data and `WITNESS` off, a state that cannot
occur on chain (`flag-mapping.md`). An abstaining vector is neither passed nor failed. With all
four interpreters, the 1029 cases are 863 agree-accept and 166 agree-reject, with no divergence.

No mismatches, so nothing needed to be classified as an adapter bug, an unsupported feature or
an implementation difference, and `known_divergences/` is empty.

## Differential result

The same replay compares the three implementations with each other (`ok` only):

| File | Cases | AGREE_OK | AGREE_FAIL | KNOWN | HARD_DIVERGE | CRASH | TIMEOUT |
|---|---:|---:|---:|---:|---:|---:|---:|
| `script_tests.json` | 772 | 677 | 95 | 0 | 0 | 0 | 0 |
| `tx_valid.json` | 176 | 176 | 0 | 0 | 0 | 0 | 0 |
| `tx_invalid.json` | 81 | 10 | 71 | 0 | 0 | 0 | 0 |
| **Total** | **1029** | 863 | 166 | 0 | 0 | 0 | 0 |

(`tx_invalid.json` has AGREE_OK cases because only one input of an invalid transaction has to
fail.) Throughput on this tiny run is not a benchmark; see `WRITEUP.md` for rates.

## What was skipped, and why

The main oracle runs consensus flags only (CLAUDE.md rule 5), and the Core adapter cannot
express policy flags at all.

| Reason | `script_tests` | `tx_valid` | `tx_invalid` |
|---|---:|---:|---:|
| Verdict depends on policy flags | 465 | 0 | 14 |
| `BADTX`: fails context-free transaction checks, not script verification | 0 | 0 | 9 |

How flags are derived for the vectors that do run:

- **`script_tests.json`**: a vector names the exact flags to use. Consensus-only vectors run
  unchanged (249). Vectors that include policy flags but expect `OK` run with the policy flags
  removed (523): every script flag only adds restrictions, so valid under a flag set implies
  valid under any subset. Vectors that include policy flags and expect an error are skipped,
  because the error may come from the policy flag.
- **`tx_valid.json`**: the vector lists flags to *exclude*. We verify with all seven consensus
  flags minus the excluded ones, which is implied by Core's own check that removing flags never
  invalidates a valid transaction.
- **`tx_invalid.json`**: the vector lists the flags under which it must fail; it runs only if
  all of them are consensus flags.
- WITNESS is dropped whenever P2SH is absent, mirroring `TrimFlags` in Core's `tx_tests.cpp`.

The five tapscript vectors in `script_tests.json` (placeholders `#SCRIPT#`, `#CONTROLBLOCK#`,
`#TAPROOTOUTPUT#`) are expanded the way Core's test does and are included above.

## Limits of this result

- 465 of 1237 script vectors are not exercised, all because they need policy flags. Most of
  them test policy behaviour, but some consensus-relevant failure paths are only reachable in
  the vectors through a policy-flagged entry.
- The Core adapter is Core 26.0 while the vectors are from v32.1 (see `docs/flag-mapping.md`).
- `sighash.json` and the BIP-341 wallet vectors are not script-verification cases; they are
  used by the sighash differential in a later phase.
