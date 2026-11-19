@echo off
rem Runs the current-Core (libbitcoinkernel) adapter container. Point the orchestrator at this script:
rem   set DIFFUZZ_ADAPTER_CORE_KERNEL=adapters\core-kernel-rs\diffuzz-adapter-core-kernel.cmd
docker run -i --rm --network none diffuzz-core-kernel
