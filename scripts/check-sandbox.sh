#!/bin/sh
# Run after scripts/check.sh. Runtime checks remain offline, including HTTP fixture.
set -eu
cd "$(dirname "$0")/.."
metadata=$(mktemp)
trap 'rm -f "$metadata"' EXIT
# Build the standalone worker and the explicitly selected test harness first.
docker run --rm --network none -v "$PWD:/app" -v praesidionyx-cargo:/usr/local/cargo/registry -v praesidionyx-target:/app/target \
  praesidionyx-dev cargo build --bin praesidionyx-tool --locked --offline
docker run --rm --network none -v "$PWD:/app" -v praesidionyx-cargo:/usr/local/cargo/registry -v praesidionyx-target:/app/target \
  praesidionyx-dev cargo test -p praesidionyxd --lib --no-run --locked --offline --message-format=json > "$metadata"
test_binary=$(python3 -c 'import json,sys; print(next(x["executable"] for x in map(json.loads,open(sys.argv[1])) if x.get("profile",{}).get("test") and x.get("executable")))' "$metadata")
docker run --rm --network none -v praesidionyx-target:/app/target praesidionyx-dev \
  cp /app/target/debug/praesidionyx-tool /app/target/debug/deps/praesidionyx-tool
set --
if [ -n "${PRAESIDIONYX_APPARMOR_PROFILE:-}" ]; then
  set -- --security-opt "apparmor=$PRAESIDIONYX_APPARMOR_PROFILE"
fi
docker run --rm --network none "$@" --cap-drop ALL \
  --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP --cap-add CHOWN \
  --security-opt no-new-privileges:true --security-opt "seccomp=$PWD/docker/seccomp-container.json" --cgroupns private \
  -v "$PWD:/app:ro" -v praesidionyx-target:/app/target:ro \
  --entrypoint /app/docker/entrypoint.sh praesidionyx-dev \
  "$test_binary" tool_bus::tests::real_sandbox_offline --exact --ignored --nocapture
