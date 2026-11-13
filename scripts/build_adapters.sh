#!/usr/bin/env bash
# Build every adapter into the locations `diffuzz` searches (see crates/oracle/src/resolve.rs):
#   Rust adapters -> target/<profile>/      (next to the diffuzz binary)
#   Go adapters   -> target/adapters/
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

echo "adapters built" >&2
