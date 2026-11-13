#!/usr/bin/env bash
# Long unattended fuzz run, split into segments so that a crash, a full disk or a reboot loses
# at most one segment.
#
#   scripts/run_overnight.sh <hours> [workers] [seed] [extra diffuzz fuzz args...]
#
# Output goes to out/run-<start time>/:
#   segment-NNN.json   machine-readable summary of each segment
#   segment-NNN.log    progress log of each segment (older logs are gzipped)
#   summary.json       merged summary of all completed segments
#
# Each segment uses seed + segment number. The run stops early on a hard divergence (rule 2),
# when free disk space drops below MIN_FREE_MB, or when a segment cannot start.
set -uo pipefail

HOURS="${1:?usage: run_overnight.sh <hours> [workers] [seed] [extra args...]}"
WORKERS="${2:-4}"
SEED="${3:-1}"
shift $(( $# < 3 ? $# : 3 ))
SEGMENT_MINUTES="${SEGMENT_MINUTES:-10}"
MIN_FREE_MB="${MIN_FREE_MB:-1024}"
IMPLS="${IMPLS:-core,btcd}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BIN="$ROOT/target/release/diffuzz"
[ -x "$BIN" ] || BIN="$BIN.exe"
if [ ! -x "$BIN" ]; then
    echo "error: build first: cargo build --release && scripts/build_adapters.sh --release" >&2
    exit 2
fi

OUT="$ROOT/out/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
END=$(( $(date +%s) + $(awk "BEGIN { printf \"%d\", $HOURS * 3600 }") ))
echo "run: $HOURS h, $WORKERS workers, seed $SEED, impls $IMPLS -> $OUT" | tee "$OUT/run.log"

n=0
status=0
while :; do
    now=$(date +%s)
    left=$(( END - now ))
    [ "$left" -le 5 ] && break
    free_mb=$(df -Pm "$OUT" | awk 'NR == 2 { print $4 }')
    if [ "${free_mb:-0}" -lt "$MIN_FREE_MB" ]; then
        echo "stopping: only ${free_mb} MB free" | tee -a "$OUT/run.log"
        status=3
        break
    fi
    secs=$(( SEGMENT_MINUTES * 60 ))
    [ "$left" -lt "$secs" ] && secs="$left"
    name=$(printf "segment-%03d" "$n")
    "$BIN" fuzz --seed $(( SEED + n )) --duration "${secs}s" --workers "$WORKERS" \
        --impls "$IMPLS" --summary "$OUT/$name.json" "$@" > "$OUT/$name.log" 2>&1
    code=$?
    tail -n 1 "$OUT/$name.log" | sed "s/^/$name: /" | tee -a "$OUT/run.log"
    # Rotate: keep the latest log readable, compress the one before it.
    prev=$(printf "segment-%03d.log" $(( n - 1 )))
    [ "$n" -gt 0 ] && [ -f "$OUT/$prev" ] && gzip -f "$OUT/$prev"
    if [ "$code" -eq 2 ]; then
        echo "stopping: segment could not run (see $name.log)" | tee -a "$OUT/run.log"
        status=2
        break
    fi
    if [ "$code" -eq 1 ] && grep -q '"HARD_DIVERGE"' "$OUT/$name.json" 2>/dev/null; then
        echo "stopping: hard divergence. Review findings/private/ before doing anything else." \
            | tee -a "$OUT/run.log"
        status=1
        break
    fi
    n=$(( n + 1 ))
done

if ls "$OUT"/segment-*.json > /dev/null 2>&1; then
    "$BIN" summarize --in "$OUT"/segment-*.json --out "$OUT/summary.json" | tee -a "$OUT/run.log"
fi
exit "$status"
