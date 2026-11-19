# core-kernel adapter

Verifies with current Bitcoin Core through `libbitcoinkernel` (crate `bitcoinkernel` 0.3.2,
which vendors Core master at 70d9ec7f3d4). Built only in Docker, because building Core needs
Boost headers and CMake:

```
docker build -f docker/core-kernel.Dockerfile -t diffuzz-core-kernel .
export DIFFUZZ_ADAPTER_CORE_KERNEL=adapters/core-kernel-rs/diffuzz-adapter-core-kernel.sh   # or the .cmd on Windows
diffuzz replay --impls core,core-kernel --vectors vectors/core/script_tests.json
```

Script verification only; auxiliary operations are answered as unsupported. Flag mapping and
limits: `docs/flag-mapping.md`.
