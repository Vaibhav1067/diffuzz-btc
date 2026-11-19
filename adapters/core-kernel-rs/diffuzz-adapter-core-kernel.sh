#!/usr/bin/env sh
# Runs the current-Core (libbitcoinkernel) adapter container. Point the orchestrator at this script:
#   DIFFUZZ_ADAPTER_CORE_KERNEL=adapters/core-kernel-rs/diffuzz-adapter-core-kernel.sh
exec docker run -i --rm --network none diffuzz-core-kernel
