# rust-bitcoin adapter

Auxiliary-only adapter around `bitcoin` (rust-bitcoin) 0.32.102, pinned in `Cargo.toml`.
Binary: `diffuzz-adapter-rust-bitcoin`, implementation name `rust-bitcoin`.

rust-bitcoin has no script interpreter, so script-verification requests are answered with
`error_class: "UNSUPPORTED"` (an abstention). Do not pass it to `diffuzz fuzz`; use it with
`diffuzz aux`.

Supported operations (wire format: `crates/types/src/auxop.rs`):

* `txinfo`: `consensus::deserialize` (rejects trailing bytes), txid, wtxid, weight, re-serialization.
  Zero-input transactions abstain: rust-bitcoin deliberately serializes them in BIP141 format
  (see the `Transaction` docs, "to avoid deserialization ambiguity"), so it accepts a witness
  flag followed by zero inputs, which Core rejects ("Superfluous witness record").
* `sighash` `legacy`: `SighashCache::legacy_signature_hash`. Its documented contract leaves
  `OP_CODESEPARATOR` to the caller, so the adapter first removes them exactly like Core's
  `SerializeScriptCode` (walk opcodes, drop each `OP_CODESEPARATOR`, copy raw bytes from the first
  unparsable opcode on).
* `sighash` `bip143`: `p2wsh_signature_hash`. It takes a normalized `EcdsaSighashType` and hashes
  the normalized value, while BIP143 hashes the raw 32-bit nHashType, so non-canonical hash types
  are answered `unsupported`.
* All `sighash` kinds: the adapter rejects an out-of-range `input_index` itself, because
  `taproot_encode_signing_data_to` only checks it for ANYONECANPAY (0.32.102, still on master
  271f662a as of 2026-11-14; no upstream report found).
* `sighash` `bip341`: `taproot_signature_hash` with all prevouts, optional annex and
  `(leaf_hash_hex, codesep_pos)` for script path.
