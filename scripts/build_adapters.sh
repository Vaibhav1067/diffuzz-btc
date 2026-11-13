#!/usr/bin/env bash
# Build every adapter into the locations `diffuzz` searches (see crates/oracle/src/resolve.rs):
#   Rust adapters -> target/<profile>/      (next to the diffuzz binary)
#   Go adapters   -> target/adapters/
#   .NET adapters -> target/adapters/ (skipped with a note if `dotnet` is not installed)
# Usage: scripts/build_adapters.sh [--release]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_FLAG=""
if [ "${1:-}" = "--release" ]; then
    PROFILE_FLAG="--release"
fi

EXE=""
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) EXE=".exe" ;;
esac

echo "building core adapter (Rust, libbitcoinconsensus 26.0)" >&2
(cd "$ROOT" && cargo build $PROFILE_FLAG -p diffuzz-adapter-core)

echo "building btcd adapter (Go)" >&2
mkdir -p "$ROOT/target/adapters"
(cd "$ROOT/adapters/btcd-go" && go build -trimpath -o "$ROOT/target/adapters/diffuzz-adapter-btcd$EXE" .)

if command -v dotnet > /dev/null 2>&1; then
    echo "building nbitcoin adapter (.NET)" >&2
    dotnet publish "$ROOT/adapters/nbitcoin-cs" -c Release -o "$ROOT/target/adapters" --nologo -v q
else
    echo "note: dotnet not found, skipping the nbitcoin adapter" >&2
fi

echo "adapters built" >&2
