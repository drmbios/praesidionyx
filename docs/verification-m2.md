# Milestone 2 verification

Validated locally on 2026-09-28 and 2026-09-29 using Docker Desktop on Apple Silicon.
The milestone-1 evidence is retained in [verification-m1.md](verification-m1.md).

| Check | Result |
|---|---|
| Full Rust workspace suite | 21 tests passed, 0 failed, 0 ignored |
| Offline execution | Docker `--network none`, Cargo `--locked --offline`, mock provider, no API key |
| Formatting | `cargo fmt --all -- --check` passed |
| Strict workspace Clippy | `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` passed |
| Release container | linux/arm64 build and healthy Compose startup passed |
| Lifecycle demo | HTTP spawn/exit, Unix gRPC list, CLI spawn/exit, signed audit verification passed |
| Capability demo | Missing-token denial, holder-side attenuation, shared call quota and audit tamper rejection passed |
| Audit after restart | Existing signed history verifies and daemon continues the chain |
| Dependency audit | 218 locked packages scanned; no known vulnerabilities; one unmaintained-dependency warning (below) |
| Python scripts / Compose | Python compilation and Compose configuration validation passed |
| arm64/amd64 CI | Both architectures configured; no remote CI run or publishing has occurred |

The suite covers signature, issuer, subject, scope, expiry and budget checks; attenuated
rights; forged grant IDs/context facts; concurrent one-use tokens; quota persistence
across restart; authentication/service separation; private key permissions; corrupt-log
startup/mutation refusal; edits, whitespace, signature-hex case changes, wrong keys,
reordering, truncation and partial audit records.

The live tamper demonstration exports public audit data to a temporary directory,
verifies it in an isolated container, changes exactly one byte, and requires the CLI
to exit nonzero with a hash mismatch. The live log is verified again afterward.
No live history or secret key is modified by that demonstration.

## Dependency maintenance warning

`cargo audit` exits successfully but reports **RUSTSEC-2026-0173**:
`proc-macro-error2 2.0.1` is unmaintained. The dependency path is
`praesidionyx-caps → biscuit-auth 6.0.0 → biscuit-quote 0.3.0 → proc-macro-error2 2.0.1`.
Rust also emits an upstream future-compatibility warning for this crate. No warning
was suppressed or advisory ignored. Disabling Biscuit's macro feature currently
breaks compilation inside biscuit-auth 6.0.0, so the supported default features remain
in use. Reassess upstream releases before production/publication.

Advisory: https://rustsec.org/advisories/RUSTSEC-2026-0173

## Boundaries

Milestone 2 is a capability/audit implementation, not the tool sandbox. The five Linux
probes still report Landlock ABI 8, outer seccomp mode 2, blocked user namespace/eBPF
operations and a read-only cgroup hierarchy on this host. Tool execution stays disabled.
Runtime budgets, taint approvals and actual parent/child scheduling remain pending.
The local audit checkpoint cannot detect rollback of the entire state volume; external
checkpoint anchoring is not implemented. See [architecture](architecture.md) and
[threat model](threat-model.md) for these explicit limits.
