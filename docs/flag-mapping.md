# Flag mapping and adapter notes

Each adapter owns the mapping from the abstract `Flag` enum (`crates/types`) to its
implementation's flags. This table must be updated whenever an adapter changes. Most false
"findings" in differential fuzzers are adapter mistakes, so read it critically.

## Pinned implementations

| Adapter | Implementation | Version pin | Where pinned |
|---|---|---|---|
| `core` | Bitcoin Core `libbitcoinconsensus` | Core **26.0**, via crate `bitcoinconsensus = "=0.106.0"` (`0.106.0+26.0`) | `adapters/core-rs/Cargo.toml`, `Cargo.lock` |
| `btcd` | btcd `txscript` | `github.com/btcsuite/btcd/txscript/v2` **v2.0.1**, `wire/v2` v2.0.2 | `adapters/btcd-go/go.mod`, `go.sum` |

## Consensus flags (used by the main oracle)

| Abstract flag | BIP | Core (`libbitcoinconsensus`) | btcd (`txscript`) |
|---|---|---|---|
| `P2SH` | 16 | `VERIFY_P2SH` (1 << 0) | `ScriptBip16` |
| `DERSIG` | 66 | `VERIFY_DERSIG` (1 << 2) | `ScriptVerifyDERSignatures` |
| `NULLDUMMY` | 147 | `VERIFY_NULLDUMMY` (1 << 4) | `ScriptStrictMultiSig` |
| `CLTV` | 65 | `VERIFY_CHECKLOCKTIMEVERIFY` (1 << 9) | `ScriptVerifyCheckLockTimeVerify` |
| `CSV` | 112 | `VERIFY_CHECKSEQUENCEVERIFY` (1 << 10) | `ScriptVerifyCheckSequenceVerify` |
| `WITNESS` | 141/143 | `VERIFY_WITNESS` (1 << 11) | `ScriptVerifyWitness` |
| `TAPROOT` | 341/342 | `VERIFY_TAPROOT` (1 << 17) | `ScriptVerifyTaproot` |

The btcd names were taken from btcd's own vector harness (`parseScriptFlags` in
`txscript/reference_test.go`), which maps Core's vector flag names the same way.

## Policy flags (never used by the main oracle)

| Abstract flag | Core | btcd |
|---|---|---|
| `STRICTENC` | not exposed | `ScriptVerifyStrictEncoding` |
| `LOW_S` | not exposed | `ScriptVerifyLowS` |
| `SIGPUSHONLY` | not exposed | `ScriptVerifySigPushOnly` |
| `MINIMALDATA` | not exposed | `ScriptVerifyMinimalData` |
| `DISCOURAGE_UPGRADABLE_NOPS` | not exposed | `ScriptDiscourageUpgradableNops` |
| `CLEANSTACK` | not exposed | `ScriptVerifyCleanStack` |
| `MINIMALIF` | not exposed | `ScriptVerifyMinimalIf` |
| `NULLFAIL` | not exposed | `ScriptVerifyNullFail` |
| `WITNESS_PUBKEYTYPE` | not exposed | `ScriptVerifyWitnessPubKeyType` |
| `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` | not exposed | `ScriptVerifyDiscourageUpgradeableWitnessProgram` |
| `CONST_SCRIPTCODE` | not exposed | `ScriptVerifyConstScriptCode` |
| `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` | not exposed | `ScriptVerifyDiscourageUpgradeableTaprootVersion` |
| `DISCOURAGE_OP_SUCCESS` | not exposed | `ScriptVerifyDiscourageOpSuccess` |
| `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` | not exposed | `ScriptVerifyDiscourageUpgradeablePubkeyType` |

`libbitcoinconsensus` rejects any flag outside its consensus set with `ERR_INVALID_FLAGS`, so
the Core adapter answers `INVALID_FLAGS` for policy flags. A policy-mode comparison against Core
would need a custom C++ harness over Core's sources; that is not built.

## Core adapter (`adapters/core-rs`)

**Binding choice.** Two bindings were evaluated on 2026-11-13:

- `bitcoinconsensus` 0.106.0+26.0 (rust-bitcoin project): bundles the consensus sources of Core
  26.0 and builds them with `cc`. Exposes `verify_with_flags` including the
  `bitcoinconsensus_verify_script_with_spent_outputs` entry point, so **taproot is supported**
  (all spent outputs are passed). No external dependencies.
- `bitcoinkernel` 0.3.2: bindings to `libbitcoinkernel` from a newer Core. Needs a CMake build of
  Core plus Boost headers, and its script-verification API reports the same coarse result.

`bitcoinconsensus` was chosen: it supports every consensus flag including taproot, builds
hermetically on Linux and Windows, and is an exact, immutable source snapshot.

**Consequences worth knowing.**

- The interpreter under test is Core **26.0**, the last release that shipped
  `libbitcoinconsensus`. The seed vectors are from Core v32.1. No consensus rule changed in
  script verification between them, and all runnable v32.1 vectors pass (see
  `docs/corpus-results.md`), but the version gap is real and is stated wherever results are
  reported.
- The library reports only *that* a script failed, not Core's `ScriptError`. The Core adapter's
  `error_class` is therefore `SCRIPT_FAIL` for every script rejection. Error-class statistics
  come from btcd.
- Core's interpreter asserts that P2SH is set whenever WITNESS is set. The adapter answers
  `INVALID_FLAGS` for WITNESS-without-P2SH instead of letting the process abort.
- Windows/MSVC needs two build defines for the bundled libsecp256k1 (static linkage and the
  ellswift module, which Core 26.0's `pubkey.cpp` references). They are set in
  `.cargo/config.toml`, scoped to the MSVC target, and touch no consensus code.

**Error mapping.**

| `libbitcoinconsensus` result | `error_class` |
|---|---|
| `ERR_SCRIPT` (script evaluated to failure) | `SCRIPT_FAIL` |
| `ERR_TX_INDEX` | `TX_INDEX` |
| `ERR_TX_DESERIALIZE`, `ERR_TX_SIZE_MISMATCH`, `ERR_SPENT_OUTPUTS_MISMATCH` | `DESERIALIZE` |
| `ERR_INVALID_FLAGS` | `INVALID_FLAGS` |
| anything else | `UNKNOWN` |

## btcd adapter (`adapters/btcd-go`)

- The transaction is decoded with `wire.MsgTx.Deserialize`; trailing bytes are rejected as
  `DESERIALIZE` (Core's library rejects a length mismatch the same way).
- All spent outputs are supplied through `txscript.NewMultiPrevOutFetcher`, and sighash
  midstates through `txscript.NewTxSigHashes`, so taproot is supported.
- **Limitation.** btcd looks spent outputs up by outpoint, while the protocol (and Core) pass
  them by input position. A transaction with two inputs spending the *same* outpoint but with
  *different* declared prevouts cannot be represented; the adapter answers `UNSUPPORTED`, which
  the oracle treats as an abstention. Such a transaction is invalid in any case (duplicate
  inputs).
- A panic inside btcd is recovered and reported as `error_class: "CRASH"` with the stack trace.

btcd error codes map to error classes one-to-one where Core has an equivalent `ScriptError`
(see `errorClasses` in `adapters/btcd-go/main.go`). The lossy groupings are:

| btcd error codes | `error_class` |
|---|---|
| all fifteen `ErrSig*` DER-shape errors | `SIG_DER` |
| `ErrEmptyStack`, `ErrEvalFalse` | `EVAL_FALSE` |
| `ErrReservedOpcode`, `ErrMalformedPush` | `BAD_OPCODE` |
| `ErrTaprootMerkleProofInvalid`, `ErrTaprootOutputKeyParityMismatch` | `WITNESS_PROGRAM_MISMATCH` |
| `ErrControlBlockTooSmall`, `ErrControlBlockTooLarge`, `ErrControlBlockInvalidLength` | `TAPROOT_WRONG_CONTROL_SIZE` |
| `ErrNonConstScriptCode`, `ErrCodeSeparator` | `OP_CODESEPARATOR` |
| unmapped codes (`ErrScriptUnfinished`, `ErrInvalidProgramCounter`, ...) | `UNKNOWN` |

## Shared request validation

Both adapters reject, before or instead of running a script:

| Condition | `error_class` |
|---|---|
| request is not valid JSON / wrong field types | `DESERIALIZE` |
| `tx_hex` or a prevout script is not hex, or the tx does not decode | `DESERIALIZE` |
| number of prevouts differs from the number of inputs | `DESERIALIZE` |
| `input_index` out of range | `TX_INDEX` |
| a prevout amount above `i64::MAX` | `DESERIALIZE` |

`INVALID_FLAGS` and `UNSUPPORTED` are abstentions: the adapter is saying "I cannot evaluate
this", not "the implementation rejects this". The oracle never counts them as a divergence.
