#!/bin/sh
# Current shallow RustSec checkout plus a populated registry avoids a large Git fetch.
set -eu
cd "$(dirname "$0")/.."
advisory_dir=$(mktemp -d)
trap 'rm -rf "$advisory_dir"' EXIT
git clone --depth 1 https://github.com/RustSec/advisory-db.git "$advisory_dir"
docker build --network "${PRAESIDIONYX_BUILD_NETWORK:-default}" --target development -t praesidionyx-dev -f docker/Dockerfile .
docker run --rm -v "$PWD:/app:ro" -v praesidionyx-cargo:/usr/local/cargo/registry \
  -v praesidionyx-audit-tools:/opt/praesidionyx-audit praesidionyx-dev sh -ec '
    if ! /opt/praesidionyx-audit/bin/cargo-audit --version 2>/dev/null | grep -q "0.22.2"; then
      cargo install cargo-audit --version 0.22.2 --locked --root /opt/praesidionyx-audit
    fi
    cargo fetch --locked
  '
# The advisory checkout and registry metadata are now present; do not suppress warnings.
docker run --rm --network none -v "$PWD:/app:ro" -v "$advisory_dir:/audit-db:ro" \
  -v praesidionyx-cargo:/usr/local/cargo/registry -v praesidionyx-audit-tools:/opt/praesidionyx-audit \
  praesidionyx-dev /opt/praesidionyx-audit/bin/cargo-audit audit --db /audit-db --no-fetch
