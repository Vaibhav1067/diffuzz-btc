# libbitcoin-cpp adapter (not built)

The plan named libbitcoin-system as the third oracle. It has not been built; NBitcoin
(`adapters/nbitcoin-cs`) was added as the third oracle instead. The reasons and what a
libbitcoin adapter would need are in `docs/flag-mapping.md` under "NBitcoin adapter".

What is required to add it:

1. A container image in `docker/` that builds libbitcoin-system at a pinned tag with its
   dependencies (Boost, ICU, libsecp256k1).
2. A C++ program speaking protocol v1 (see `adapters/btcd-go/main.go` for a compact reference)
   that maps the seven consensus flags to libbitcoin's rule forks and calls its script
   verification with all previous outputs.
3. `diffuzz replay --impls core,btcd,nbitcoin,libbitcoin` must pass before any fuzzing.
