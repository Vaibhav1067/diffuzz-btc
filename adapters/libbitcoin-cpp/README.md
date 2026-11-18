# libbitcoin-cpp adapter

Adapter around libbitcoin-system v4 (tag pinned in `docker/libbitcoin.Dockerfile`), an
independent C++ implementation with taproot and tapscript support. It is built and run in a
pinned Debian container, so it works the same on Linux and Windows.

```
docker build -f docker/libbitcoin.Dockerfile -t diffuzz-libbitcoin .
# Linux / Git Bash
DIFFUZZ_ADAPTER_LIBBITCOIN=adapters/libbitcoin-cpp/diffuzz-adapter-libbitcoin.sh \
  target/release/diffuzz replay --impls core,btcd,nbitcoin,libbitcoin --vectors ...
# Windows cmd
set DIFFUZZ_ADAPTER_LIBBITCOIN=adapters\libbitcoin-cpp\diffuzz-adapter-libbitcoin.cmd
```

The wrapper scripts run `docker run -i --rm --network none diffuzz-libbitcoin`: the adapter has
no network access.

## How it verifies

- The transaction is decoded with `chain::transaction(data, witness=true)` and must be valid and
  re-serialize to the same length, otherwise `DESERIALIZE`.
- Every input's `prevout` is set from the request (taproot needs all spent outputs).
- `machine::interpreter<contiguous_stack>::connect(context, tx, index)` verifies the input.
  Success is `error::script_success`; any other code is reported as `UNKNOWN` with libbitcoin's
  message as `raw_error`.
- Exceptions become `CRASH`. Auxiliary (`op`) requests are answered `unsupported`.

## Flag mapping

| Abstract flag | libbitcoin `chain::flags` |
|---|---|
| `P2SH` | `bip16_rule` |
| `DERSIG` | `bip66_rule` |
| `NULLDUMMY` | `bip147_rule` |
| `CLTV` | `bip65_rule` |
| `CSV` | `bip112_rule` |
| `WITNESS` | `bip141_rule \| bip143_rule` |
| `TAPROOT` | `bip341_rule \| bip342_rule` |

Policy flags have no mapping and are answered `INVALID_FLAGS`.
