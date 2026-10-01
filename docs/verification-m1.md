# Milestone 1 verification

Executed locally on 2026-09-28 using Docker Desktop on Apple Silicon.

| Check | Result |
|---|---|
| Release image build | Passed; image reports linux/arm64 |
| Docker Compose daemon startup | Passed; health check healthy |
| Rust workspace tests | 8 passed, 0 failed, 0 ignored |
| Offline test isolation | Passed with `--network none`, `cargo test --locked --offline`, no API key |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | Passed |
| `cargo audit` | Passed, cargo-audit 0.22.2; no vulnerabilities reported |
| Python HTTP spawn/exit + CLI gRPC listing | Passed against the running release container |
| CLI spawn/exit over Unix gRPC | Passed against the running release container |
| Compose configuration | Valid; host binds 127.0.0.1:18080 and 127.0.0.1:18081 |
| amd64 CI execution | Configured, not executed locally; no remote repository or CI run exists yet |

The Rust suite checks deterministic mock outputs, key persistence/permissions,
agent identities, lifecycle transitions, separate supervisor/bootstrap/session
rights, rejection of cross-agent exit, transport separation, unsupported features,
concurrent spawning and all five required kernel probes. It includes actual Unix
gRPC sockets, not just direct function calls.

Observed runtime feature report:

| Feature | Observed |
|---|---|
| Landlock | ABI 8 detected; enforcement not installed |
| seccomp | Mode 2 outer container filter; per-tool allowlist not installed |
| User namespaces | Kernel support detected; creation denied by container |
| cgroup v2 | Controllers detected; hierarchy read-only, no per-agent delegation |
| eBPF | Kernel support detected; map creation denied |

Every unverified/blocked control produces a warning. `tool_execution_enabled` is
false. These results validate lifecycle-only boot with explicit degraded security
reporting; they do not validate the future sandbox or any later milestone.

The complete final acceptance checklist remains in [milestones.md](milestones.md).
