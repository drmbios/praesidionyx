#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker build --network "${PRAESIDIONYX_BUILD_NETWORK:-default}" --target development -t praesidionyx-dev -f docker/Dockerfile .
docker run --rm -v "$PWD:/app" -v praesidionyx-cargo:/usr/local/cargo/registry -v praesidionyx-target:/app/target praesidionyx-dev cargo fetch --locked
# Toolchain/protoc/dependencies are now present. These checks have no network.
docker run --rm --network none -e ANTHROPIC_API_KEY= -e PRAESIDIONYX_PROVIDER=mock \
  -v "$PWD:/app" -v praesidionyx-cargo:/usr/local/cargo/registry -v praesidionyx-target:/app/target \
  praesidionyx-dev sh -c 'cargo test --workspace --locked --offline && cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked --offline -- -D warnings'
