#!/usr/bin/env sh
# Runs the libbitcoin adapter container. Point the orchestrator at this script:
#   DIFFUZZ_ADAPTER_LIBBITCOIN=adapters/libbitcoin-cpp/diffuzz-adapter-libbitcoin.sh
exec docker run -i --rm --network none diffuzz-libbitcoin
