# libbitcoin-system v4 adapter, built from a pinned tag in a pinned Debian image.
#
#   docker build -f docker/libbitcoin.Dockerfile -t diffuzz-libbitcoin .
#
# The adapter then runs as `docker run -i --rm diffuzz-libbitcoin` (see
# adapters/libbitcoin-cpp/diffuzz-adapter-libbitcoin*).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS build

ARG LIBBITCOIN_TAG=v4.0.10537
ARG JOBS=8

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates pkg-config nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${LIBBITCOIN_TAG}" \
        https://github.com/libbitcoin/libbitcoin-system.git libbitcoin-system

# Library only: no tests, console app or CUDA; native (embedded) secp256k1.
RUN cmake -S libbitcoin-system/builds/cmake -B build-lbs \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/lbs \
        -Dwith-tests=OFF -Dwith-console=OFF -Dwith-cuda=OFF \
    && cmake --build build-lbs -j"${JOBS}" \
    && cmake --install build-lbs

COPY adapters/libbitcoin-cpp/ /src/adapter/
RUN cmake -S /src/adapter -B /src/build-adapter -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH=/opt/lbs -DLIBBITCOIN_PIN="${LIBBITCOIN_TAG}" \
    && cmake --build /src/build-adapter -j"${JOBS}"

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=build /src/build-adapter/diffuzz-adapter-libbitcoin /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/diffuzz-adapter-libbitcoin"]
