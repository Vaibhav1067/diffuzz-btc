# fuzz

Coverage-guided cargo-fuzz (libFuzzer) targets. This directory is its own Cargo workspace and
needs a nightly toolchain:

```
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run sighash_diff -- -max_total_time=600
```

| Target | What it checks |
|---|---|
| `tx_decode` | Our lenient tx parser round-trips, and decodes everything rust-bitcoin decodes to the same txid/wtxid. |
| `sighash_diff` | Our legacy/BIP143/BIP341 sighash code (which signs every generated case) matches rust-bitcoin's digests and agrees on when no digest exists. |
| `core_verify` | Structured requests into the Core adapter's verify path never panic or abort. libbitcoinconsensus itself is not coverage-instrumented. |
| `adapter_lines` | Arbitrary protocol lines into the Rust adapters always get valid JSON back. |

Crashes land in `fuzz/artifacts/<target>/` (git-ignored). Treat any crash in `sighash_diff` or
`tx_decode` under rule 2 until triaged: a mismatch could be in either implementation.

CI runs each target for 30 seconds on Linux.

On Windows (MSVC), cargo-fuzz needs AddressSanitizer's runtime DLL on `PATH`, otherwise every
target exits with `STATUS_DLL_NOT_FOUND`; `-s none` does not help because the MSVC linker then
cannot resolve libFuzzer's coverage symbols. Add the MSVC tools directory that contains
`clang_rt.asan_dynamic-x86_64.dll`, e.g.
`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<version>\bin\Hostx64\x64`.

Smoke run on 2026-11-18 (Windows, 60 s each): tx_decode 352k, sighash_diff 289k, core_verify
274k, adapter_lines 163k executions, no crashes.
