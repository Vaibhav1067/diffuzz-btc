# Secondary surface: tx decoding and sighash (`diffuzz aux`)

Wire format: `crates/types/src/auxop.rs`. A protocol line with an `"op"` field is an auxiliary
request; adapters answer `{"ok": false, "unsupported": true}` for anything they cannot do, and an
unsupported answer is an abstention, never a verdict. Digests and ids are hex of the raw 32
bytes in SHA-256 output order (not Core's byte-reversed display order).

| op | fields compared |
|----|-----------------|
| `txinfo` | `ok`, `txid`, `wtxid`, `weight`, `hex` (re-serialization) |
| `sighash` (`legacy`, `bip143`, `bip341`) | `ok`, `digest` |

A field one implementation does not report (NBitcoin reports no `weight`) is not compared.

## Implementations

| impl | txinfo | legacy | bip143 | bip341 | notes |
|------|--------|--------|--------|--------|-------|
| `rust-bitcoin` (0.32.102) | yes | yes | canonical hash types only | yes | the library leaves `OP_CODESEPARATOR` removal to the caller; the adapter strips them as Core's `SerializeScriptCode` does. `p2wsh_signature_hash` hashes the normalized hash type, so non-canonical values abstain. Zero-input transactions abstain on `txinfo` (BIP141 serialization by design). The adapter bounds-checks `input_index`, which the library skips for non-ANYONECANPAY BIP341. |
| `btcd` (txscript v2.0.1) | yes | parsable scripts only | yes | key path without annex; script path (base leaf) | `CalcSignatureHash` refuses unparsable scriptCode, where Core hashes the bytes. btcd keys prevouts by outpoint, so duplicate outpoints abstain. `NewTxSigHashes` skips the taproot midstate when no prevout is P2TR, so such BIP341 requests abstain. `CalcWitnessSigHash` turns a scriptCode that is exactly a P2WPKH program into the P2PKH-style scriptCode, so BIP143 requests with such a scriptCode abstain. |
| `nbitcoin` | yes (no weight) | parsable scripts only | parsable scripts only | yes | `GetSignatureHash` parses the scriptCode into ops and throws on truncated pushes, where Core hashes the bytes. `Money` cannot hold an output value of `long.MinValue`, so such transactions abstain on `txinfo` (Core decodes them and rejects them later as `bad-txns-vout-negative`). |
| `core` (libbitcoinconsensus 26.0) | no | no | no | no | the library exposes only script verification; always abstains. |

For a BIP341 script-path request, send both `script_hex` (the leaf script, leaf version 0xc0)
and its `leaf_hash_hex`: btcd derives the leaf hash from the script, NBitcoin and rust-bitcoin
take the given hash.

## Checks run by `diffuzz aux`

* Core `sighash.json`: legacy digests with the expected value (500 vectors).
* BIP341 `wallet-test-vectors.json`: key-path digests with the expected value (7 vectors).
* `txinfo` on every distinct transaction in the files above plus `tx_valid.json` and
  `tx_invalid.json`.

* With `--seed S --count N`: N generated operations (`crates/gen/src/auxgen.rs`): byte-mutated
  and freshly built transactions for `txinfo`, and legacy / BIP143 / BIP341 key-path and
  script-path requests with annexes, undefined hash types, `SIGHASH_SINGLE` without a matching
  output, out-of-range input indexes and unparsable scriptCodes. Each is named `gen:S:n` and can
  be regenerated from `(S, n)`.

Cross-implementation disagreements, crashes and timeouts are written to `findings/private/`
(`aux_diverge-*.json`, `aux_crash-*.json`) and only counted on stdout.

Results on 2026-11-14:

* Upstream vectors: 1140 checks; rust-bitcoin, btcd and NBitcoin agree on every check and meet
  every expected digest; Core abstains on all.
* Generated: seeds 1, 2 and 3 with `--count 100000` each (300k checks): no divergence, crash or
  timeout after the adapter preconditions above. Triage found no implementation bug relevant to
  consensus. CI runs seed 1 with 20k generated checks.

## Building on Windows inside OneDrive

OneDrive turns synced files into reparse points, which the Go loader rejects with
"cannot find package". `scripts/build_adapters.sh` therefore builds the btcd adapter from a
temporary copy; run `go vet` / `go test` from a copy as well, or keep the checkout outside
OneDrive.
