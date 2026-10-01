#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
for example in lifecycle capabilities tools injection-demo researcher memory scheduler; do
    printf '\n$ python3 examples/%s/demo.py\n' "$example"
    python3 -u "examples/$example/demo.py"
done
printf '\n$ praesidionyx audit verify (supervisor Unix socket)\n'
docker compose exec -T --user 10001:10001 praesidionyxd praesidionyx audit verify
