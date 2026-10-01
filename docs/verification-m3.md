# Milestone 3 verification

Verified locally on 2026-09-29 using Apple Silicon, Docker Desktop Linux/arm64,
Rust stable 1.98.1, and the deterministic mock provider. No API keys were used.
The earlier [M2 report](verification-m2.md) and [M1 report](verification-m1.md)
remain available as historical records.

## Results

| Check | Result |
|---|---|
| Workspace tests, Cargo locked/offline, Docker network disabled | 24 passed; real-confinement test selected separately below |
| Real confinement test, Docker network disabled, delegated private cgroups | 1 passed; not skipped in the dedicated script |
| rustfmt check | Passed |
| Strict Clippy, workspace/all targets, warnings denied | Passed |
| arm64 release build and Compose health check | Passed; tool_execution_enabled=true |
| HTTP lifecycle and Unix gRPC CLI demo | Passed |
| Capability attenuation, shared quotas and copied-log tamper demo | Passed |
| HTTP + Unix gRPC tool demo | Passed; real file write/read and negative authorization checks |
| Deliberately undelegated container | Booted; reported blocked controls and tool_execution_enabled=false |
| Runtime daemon identity/capabilities | UID/GID 10001; Inh/Prm/Eff/Bnd/Amb all zero; NoNewPrivs=1 |
| Optional Linux AppArmor profile | Ubuntu 24.04 parser accepted it without kernel loading |
| Compose base + AppArmor override, shell/Python syntax | Passed |
| cargo-audit | No vulnerability errors; one upstream unmaintained dependency warning |

## Real sandbox coverage

`scripts/check-sandbox.sh` builds the worker and explicitly selects the ignored
confinement test in a container with the required setup capabilities and outer seccomp
profile. The test must pass; absence of controls does not skip it. Both build/test
execution and the HTTP fixture run with Docker networking disabled.

The test verifies seven distinct namespaces, Landlock FullyEnforced at ABI V3,
actual denial of opening `/usr/bin/true`, and syscall-filter denials of a new network
socket, exec and a new user namespace. The parent creates and rechecks cgroup CPU,
memory, swap and PID limits. It does not benchmark CPU throttling or induce an OOM.

A real rmcp client/server round trip writes and reads a file. Symlink escape,
hard-linked writes and files over 32 KiB are rejected. The hard-link target remains
unchanged. An offline HTTP fixture is reached through a preconnected descriptor while
the worker has an isolated network namespace. A stalled HTTP fixture triggers caller
cancellation; the socket closes and the agent cgroup becomes unpopulated within the
bounded check. Private-network broker destinations are rejected.

The local fixture bypasses the public-address broker only in private test code.
Production has no bypass flag. HTTPS uses rustls certificate/hostname verification;
a public Internet HTTPS fetch was not part of this offline suite.

The release demo additionally verifies missing capabilities, wrong sessions, wrong
agent IDs, wrong file scopes, traversal and exhausted-token replay. It exercises both
HTTP Invoke and CLI Unix-socket gRPC Invoke, then verifies the resulting signed audit.
The normal integration tests also prove that an authorized call with unavailable
sandbox controls performs no workspace operation and still consumes its durable quota.

## Reproduce

```sh
./scripts/check.sh
./scripts/check-sandbox.sh
docker compose up --build -d --wait
python3 examples/lifecycle/demo.py
python3 examples/capabilities/demo.py
python3 examples/tools/demo.py
docker compose exec --user 10001:10001 praesidionyxd praesidionyx features
docker compose exec --user 10001:10001 praesidionyxd praesidionyx audit verify
```

CI runs these checks on native amd64 and arm64 Ubuntu 24.04 runners. On hosts enforcing
AppArmor, CI loads the explicit Moby-derived `docker/apparmor-praesidionyx` profile and
selects `docker-compose.apparmor.yml`. The local Mac kernel does not enforce AppArmor;
only profile syntax was checked locally. Remote CI and native amd64 execution have
not been run from this workspace. No remote repository is configured.

## Dependency warning and remaining scope

cargo-audit scanned 301 dependencies and reported `RUSTSEC-2026-0173`:
`proc-macro-error2 2.0.1` is unmaintained, brought in by biscuit-quote/biscuit-auth 6.
The warning is not suppressed. It remains the upstream issue documented in M2.

Milestone 3 implements tool confinement, exact capabilities and output provenance.
Context-wide taint tracking/approvals, memory, aggregate scheduler budgets, child-agent
execution and production hardening remain future milestones. The 64 MiB/0.5 CPU/
32-PID tool limits and 10-second deadline are fixed per-invocation controls. Workspaces
have no disk quota yet, and writes are not transactional. See the threat model and
architecture for root setup, broker and audit trust boundaries.
