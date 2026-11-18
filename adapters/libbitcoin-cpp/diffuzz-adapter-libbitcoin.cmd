@echo off
rem Runs the libbitcoin adapter container. Point the orchestrator at this script:
rem   set DIFFUZZ_ADAPTER_LIBBITCOIN=adapters\libbitcoin-cpp\diffuzz-adapter-libbitcoin.cmd
docker run -i --rm --network none diffuzz-libbitcoin
