# Current Bitcoin Core through libbitcoinkernel, built from source in a pinned Debian image.
#
#   docker build -f docker/core-kernel.Dockerfile -t diffuzz-core-kernel .
#
# The adapter then runs as `docker run -i --rm diffuzz-core-kernel` (see
# adapters/core-kernel-rs/diffuzz-adapter-core-kernel*). Building Core takes a while.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS build

# Same toolchain as rust-toolchain.toml.
ARG RUST_VERSION=1.100.0
ARG JOBS=8

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates curl pkg-config libboost-dev \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf -o /tmp/rustup-init \
        https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rm /tmp/rustup-init

WORKDIR /src
# Copy only what the build reads, so unrelated edits do not rebuild Core. The adapter depends on
# crates/types, which inherits fields from the root workspace manifest; the other members are
# only stubbed for cargo's workspace check.
COPY Cargo.toml rust-toolchain.toml ./
COPY crates/types/ crates/types/
COPY adapters/core-kernel-rs/ adapters/core-kernel-rs/
# cargo passes -j to the Core CMake build as NUM_JOBS. Tests run in the same profile, so Core is
# compiled once.
RUN cargo test --release --locked -j "${JOBS}" --manifest-path adapters/core-kernel-rs/Cargo.toml     && cargo build --release --locked -j "${JOBS}" --manifest-path adapters/core-kernel-rs/Cargo.toml

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=build /src/adapters/core-kernel-rs/target/release/diffuzz-adapter-core-kernel /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/diffuzz-adapter-core-kernel"]
