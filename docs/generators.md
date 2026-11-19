# Generators

Random bytes almost never get past the first opcode of a script, and never produce a valid
signature. The generators in `crates/gen` are therefore structure-aware: they build
transactions, scripts and witnesses that are *nearly* valid and differ from a valid spend in one
or two deliberate ways. Signatures are real: deterministic test keys sign with secp256k1 over
sighashes computed by this project's own implementation of the legacy, BIP143 and BIP341
algorithms.

## Determinism

- `Rng` is an in-tree xoshiro256** seeded through SplitMix64, with its output pinned by a test.
  No external RNG crate can change generated cases between versions.
- `Mix::case(seed, n)` forks an independent stream per case, so case `n` can be regenerated
  without replaying cases `0..n`.
- Test keys are `SHA256("diffuzz-btc test key" || index || counter)`. They are public by
  construction and must never receive funds.
- ECDSA uses RFC 6979; BIP340 signing uses zero auxiliary randomness.
- `diffuzz gen --seed S --count N --out DIR` is fully reproducible. `diffuzz fuzz` is
  reproducible with one worker and feedback off; with several workers the order in which
  workers contribute kept cases depends on timing. Every finding is saved as a self-contained
  case file, so reproducing a finding never depends on replaying a run.

## The five generators

Weights live in `weights.toml` (defaults: script 30, sig 25, wrapper 10, taproot 25, mutate 10).

### `script` (`generators/script.rs`)

A grammar that tracks a model of the stack (depth and "number or bytes" per element), so
opcodes usually find the operands they need. Each step picks from: number pushes (boundary
values, negative zero, non-minimal and 5-byte encodings), data pushes (sizes around 75/76,
255/256 and 520, sometimes with a non-minimal push opcode), unary and binary arithmetic, stack
manipulation, `PICK`/`ROLL`, `EQUAL` and the `VERIFY` family, hashes, NOPs, alt-stack moves,
`CLTV`/`CSV`, nested `IF`/`NOTIF`/`ELSE`/`ENDIF` (branches are re-balanced to equal depth; 4%
are left unterminated), and a small share of disabled, reserved and undefined opcodes.
Witness scripts must end with exactly one true element, so 70% of scripts are finished by
clearing the stack and pushing `1`.

22% of cases are named **limit cases**, each built to sit on a boundary:

| Name | What it probes |
|---|---|
| `ops-201` / `ops-202` | 201 non-push opcode limit (absent in tapscript) |
| `size-10000` / `size-10001` | script size limit (absent in tapscript) |
| `stack-1000` / `stack-1001` | combined stack limit |
| `push-520` / `push-521` | element size limit |
| `num-4byte-ok`, `num-5byte-input`, `num-overflow-chain` | 4-byte operand rule: a 5-byte result is fine, a 5-byte operand is not |
| `negative-zero`, `nonminimal-number` | number and boolean decoding |
| `if-deep` | conditional nesting up to 150 |
| `unexecuted` | what still fails inside a branch that never runs (disabled opcodes, `VERIF`, oversized pushes) |
| `locktime` | `CLTV`/`CSV` operands against the transaction's lock time, sequence and version, including type-flag and disable-flag boundaries |

### `sig` (`generators/sig.rs`)

Eleven templates (`P2PK`, `P2PK` with `CHECKSIGVERIFY`, `P2PKH`, `CHECKMULTISIG`,
`CHECKMULTISIGVERIFY`, `CHECKSIG NOT`, two `OP_CODESEPARATOR` placements, a signature embedded
in its own script to exercise `FindAndDelete`, `P2WPKH`, `P2SH-P2WPKH`) across bare, P2SH,
P2WSH and P2SH-P2WSH. The free choices, each usually benign so that most cases are one step
from valid:

- hash type: `ALL` 45% of the time, otherwise `NONE`, `SINGLE`, their `ANYONECANPAY` forms and
  undefined bytes (`0x00`, `0x04`, `0x1f`, `0x21`, `0x41`, `0x7f`, `0x80`, `0xff`), all signed
  correctly since consensus hashes whatever byte is present. When the byte selects `SINGLE`
  (low five bits `3`), 40% of cases remove the output matching the input under test
  (`spend::orphan_single`, origin suffix `/single-no-output`): legacy then signs the number one,
  BIP143 a zero `hashOutputs`, and both verify in Core; the `taproot` generator does the same for
  `SINGLE` Schnorr signatures, which BIP341 makes invalid. About 1% of the mixed stream;
- DER encoding: strict, or one of seven variants that only a lax parser accepts;
- high-S;
- public key: compressed, uncompressed, hybrid, and six invalid forms;
- damage: none, bit flip, wrong key, wrong message, empty, truncated, mislabelled hash type;
- multisig: `m` and `n` including 0-of-n, 20 and 21 keys, `m > n`, non-empty dummy, reversed
  signature order, one signature too few or too many.

### `wrapper` (`generators/wrapper.rs`)

Sixteen templates for the output type itself: every witness version with program lengths 1 to
41 (including pay-to-anchor and P2SH-nested programs), P2WSH hash mismatch and empty witness,
wrong P2WPKH witness count, scriptSig malleation of native and nested witness spends, witness
data on non-witness outputs, P2SH hash mismatch, non-push-only scriptSig, redeem scripts of
519 to 600 bytes, P2SH inside P2SH, witness scripts of 9,999 to 10,001 bytes, witness items of
519 to 521 bytes and witness stacks of 998 to 1,001 items.

### `taproot` (`generators/taproot.rs`)

Fourteen templates: key-path spends (all hash types, annex, tweaked with and without a script
root), merkle path depth 0 to 129, known and unknown leaf versions (including `0x50`, which
collides with the annex tag), five kinds of control-block corruption, `CHECKSIG` variants,
k-of-n `CHECKSIGADD`, public key lengths 0 to 65, `OP_SUCCESSx` with decodable and undecodable
surroundings, consensus `MINIMALIF`, the signature-operations budget, `CHECKMULTISIG` in
tapscript, `OP_CODESEPARATOR` positions, annex in script-path spends, and initial stack limits.
15% of cases use the template's all-valid settings.

### `mutate` (`generators/mutate.rs`)

Takes a seed case (the 1,029 corpus cases, or cases kept by the fuzz loop) and applies one to
three of: bit flip, byte insertion or deletion, opcode substitution, instruction deletion,
splicing instructions from another case, boundary-value replacement of a pushed number or of
the version, lock time, sequence, amount or output value, witness item duplication, removal or
emptying, and toggling a consensus flag. Scripts are edited at instruction granularity. When a
P2SH redeem script or P2WSH witness script is mutated, the hash commitment is recomputed 75% of
the time, so the mutated script is actually executed instead of failing the hash check.

## Re-signing mutants

`crates/gen/src/resign.rs`. Half of all mutants are passed through `resign`, which recomputes
the sighash over the mutated transaction and replaces every signature made by a test key: bare
and P2SH legacy scripts (with `FindAndDelete`), P2WPKH and P2WSH (also nested), and tapscript
leaves with leaf version 0xc0 (witness items pair with keys top of stack first). Such mutants
are tagged `gen/mutate/resigned/...`.

`crates/gen/tests/resign_core.rs` proves it: valid spends are broken by changing the lock
time, re-signed, and must all verify in Core again (every pre-taproot template under every
wrapper, and the tapscript `checksig`, `checksigadd` and `annex` templates). On 20,000 single
mutations of generated signature cases, re-signing raised Core's accept rate from 18.9% to
29.2% (2026-11-18).

## Proof that success paths are reached

`crates/gen/tests/core_accepts.rs` calls Bitcoin Core in-process and asserts, for 12 to 25
seeds per combination:

- every signature template is accepted under every pre-taproot wrapper when built with valid
  choices (528 cases), with the two principled exceptions asserted the other way round;
- every hash-type byte verifies; every lax DER encoding verifies without DERSIG and fails with
  it; high-S, uncompressed and hybrid keys verify; damaged signatures do not;
- multisig rules (NULLDUMMY, order, 0-of-n, 20 and 21 keys) behave as specified;
- all fourteen taproot templates verify in their valid form;
- each limit pair passes on one side and fails on the other, including the tapscript
  exemptions;
- in a 4,000-case mixed stream, every category has at least 8% accepted and 8% rejected cases.

The BIP143 example and all seven key-path sighashes of the BIP341 wallet vectors are checked
directly in `sighash.rs`.

## Feedback and tuning

The targets are not instrumented. `diffuzz fuzz` approximates coverage with a signature:

    (outcome or error class reported by each implementation, set of non-push opcodes, output type)

A case with a new signature is kept (up to 20,000, then random replacement) and a third of each
batch is mutations of kept cases. This rewards reaching new error classes and new opcode
combinations; it knows nothing about branches inside the implementations.

To tune, run a short fuzz and read the report it prints:

- **by generator category**: a category that is almost all `AGREE_FAIL` is too destructive;
- **outcomes reported by btcd**: the distribution of error classes. A healthy mix has `OK`
  well below 100% and no single failure class dominating;
- **output types**: adjust `weights.toml` if an output type is starved.

Distribution measured on the default weights is recorded with the fuzzing results in
`docs/WRITEUP.md`.

## Known gaps

- No generator for taproot script trees with more than one *known* leaf (siblings are random
  hashes), and none for P2SH-wrapped taproot, which is not a taproot spend.
- Re-signing (below) covers only signatures made by test keys, and skips taproot key-path
  spends and scripts containing `OP_CODESEPARATOR`. Mutants of Core's vectors are never
  re-signed.
- Transactions have at most twelve inputs (usually one to six) and six outputs. Other inputs
  spend simple outputs (`OP_1`, P2PKH, P2WPKH, P2TR), never another generated spend.
