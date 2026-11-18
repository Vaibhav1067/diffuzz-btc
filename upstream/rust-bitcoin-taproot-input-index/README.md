# rust-bitcoin: BIP341 sighash accepts a nonexistent input index

Status: **prepared, not submitted.** Opening an issue or PR needs the owner's go-ahead
(CLAUDE.md rule 1). Not consensus-relevant, so rule 2 does not apply.

## Problem

`SighashCache::taproot_encode_signing_data_to` validates `input_index` only in the
`ANYONECANPAY` branch (`tx_in(input_index)`). Without `ANYONECANPAY` it serializes
`input_index as u32` and returns a digest for an input that does not exist, while the legacy
and segwit v0 functions return `InputsIndexError`. Present in 0.32.102 and on master at
`c8ee144a` (2026-11-16). No existing issue found (searched 2026-11-14; closest: #1966,
#1965).

Found by diffuzz-btc's sighash differential: btcd and NBitcoin reject such a request,
rust-bitcoin returned a digest.

## Fix

`fix.patch` (against master `c8ee144af8f2a14dfe4627b018f096ca3ccc1ebe`): call
`tx_in(input_index)` right after the prevouts check, for every sighash type. The extended
`sighash_errors` test checks `Default`, `All`, `None` and `Single` with index 10 on a
one-input transaction.

Verified locally: `cargo test -p bitcoin --lib sighash` passes with the patch (23 tests); with
only the test applied, `sighash_errors` fails.

## Suggested PR text

> **sighash: check the input index for every taproot sighash type**
>
> `taproot_encode_signing_data_to` only checked `input_index` when `ANYONECANPAY` was set, so
> for the other sighash types it produced a digest for a nonexistent input instead of
> `InputsIndexError` (the legacy and segwit v0 functions already return the error). Check it
> up front and extend `sighash_errors` to cover `Default`, `All`, `None` and `Single`.
