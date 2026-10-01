# Final MVP verification

Verified locally on **2026-10-01**, Apple Silicon, Docker Desktop Linux/arm64,
Rust stable **1.98.1**, with mock and no API key or live model calls.
Historical reports: [M1](verification-m1.md), [M2](verification-m2.md), [M3](verification-m3.md).

## Results

| Check | Result |
|---|---|
| Workspace tests, Cargo locked/offline, Docker network none | **34 passed**; real-confinement test selected separately |
| Real confinement/cancellation, Docker network none | **1 passed**, explicitly required rather than skipped |
| rustfmt and strict workspace/all-target Clippy | Passed, warnings denied |
| Browser policy simulation tests / JavaScript syntax | **5 passed** / syntax passed |
| Browser UI checks | Injection denial, exact approved retry, immutable child floor, sticky rollback, desktop and 390 px mobile layout |
| Full measured quickstart including all seven demos/audit | **272.6 seconds**, under five minutes on this host |
| Quickstart arm64 image and feature report | Healthy; tool_execution_enabled=true |
| Optimized release arm64 image | Historical pre-rename build/boot passed; current renamed run uses quickstart profile |
| HTTP / Unix gRPC lifecycle and tool calls | Passed |
| Capability attenuation/shared counters/copied audit tamper | Passed |
| Hidden injection + CLI denial | Passed; retry denied and target file absent |
| Derived researcher summary + exact CLI approval | Passed; trusted label could not declassify summary |
| SQLite paging/vector recall/snapshots/ownership/taint | Passed through HTTP and Unix gRPC; reopen persistence unit check |
| Typed messages, child scope, pause/resume/parent kill | Passed live; nested ancestor-token and inference-cancellation unit checks |
| Token, positive cost, tool and wall exhaustion | Stopped in one tick call; live final-tool completion then termination |
| Missing cgroup delegation, all capabilities dropped | Current daemon booted; health OK and tools disabled visibly |
| Runtime identity/capabilities | UID/GID 10001; Inh/Prm/Eff/Bnd/Amb all zero; NoNewPrivs=1 |
| Base Compose + explicit AppArmor override | Configuration valid; profile parser validation retained from M3 |
| Python/shell/documented JSON syntax | Passed |
| Recorded terminal demo | All seven demos passed; 43 output events, 60.8 s; asciicast v2 validated, no credential fields/long tokens |
| cargo-audit 0.22.2 against current RustSec checkout | 331 dependencies, 1,278 advisories; no vulnerability/yanked errors; one unmaintained warning |

The full Rust test count is **35**, comprising 34 normal tests and the dedicated confinement
case. The ordinary test suite marks that case ignored because it needs cgroup/namespace
setup; scripts/check-sandbox.sh explicitly selects it and fails if enforcement is missing.
Build dependency downloads and advisory checkout occur before offline execution.

## Publication review fixes

The pre-publication review fixed inconsistent taint after empty external messages or
failed untrusted memory writes; stopped agents queuing approvals; cancellation that
could leave descendants running when audit storage failed; and orphaned spawned agents
after provider/context/audit errors. Emergency kill and budget termination now cancel
all descendants before reporting storage failure. Terminal states remain terminal.

The rename has a regression test for legacy audit records/checkpoints: new events use
the new signing domains, old bytes remain intact and tampering still fails. Existing
runtime state was copied with ownership/modes retained; the original volume was preserved.
Docker package downloads now use IPv4 with explicit timeouts/retries. Docker Desktop's
default build bridge stalled on this host; a build-only host-network override downloaded
the same index in 2 seconds. The optional override leaves runtime networking unchanged.

The Space is a static browser simulation with a replay of the real runtime recording.
It does not enforce Linux controls or verify Biscuit tokens inside the browser. Its
separate tests cover denial, one-use/context-bound/expiring approvals, stopped agents,
and the inherited child floor even when a broader grant is selected.

## Reproduce

```sh
./scripts/check.sh
./scripts/check-sandbox.sh
./scripts/audit.sh
python3 scripts/quickstart.py
python3 scripts/record-demo.py
docker compose exec --user 10001:10001 praesidionyxd praesidionyx features
docker compose exec --user 10001:10001 praesidionyxd praesidionyx audit verify
```

The quickstart selects mock, clears the remote key, builds/boots, runs lifecycle,
capabilities, tools, injection, researcher, memory and scheduler demos, then verifies
the audit. Recorded output is in [demo-transcript.txt](demo-transcript.txt) and
[demo.cast](demo.cast); replay with `asciinema play docs/demo.cast`. Credentials remain
captured privately inside the demo programs rather than printed or written into the recording.

Timing conditions matter: the current renamed complete run took 272.6 s with a build-only
host-network workaround and concurrent local verification. It rebuilt development packages
and renamed binaries. An earlier 113.7 s complete run used cached base images, registry
packages and some compilation cache, and rebuilt changed daemon code. An earlier first
compilation of the quickstart profile took 96.3 s with existing base images/dependency
cache. The first optimized release compilation took 332.9 s; the final cached release
build took 44.7 s. Compose therefore defaults to a no-debug-symbol, unoptimized quickstart
profile. No security checks differ by profile. A fully uncached Docker/toolchain/network
bootstrap was **not** measured and cannot be guaranteed under five minutes on every host.

## Security coverage and limits of the evidence

Real workers demonstrate seven distinct namespaces, Landlock FullyEnforced V3,
denial of opening /usr/bin/true, and denials of new sockets, exec and user namespaces.
The parent installs/rechecks CPU, memory, swap and PID cgroup limits. Tests do not
benchmark CPU throttling or induce OOM. File I/O goes through rmcp; symlink escape,
hard-linked writes and oversized reads fail. A hard-link target remains unchanged.
A preconnected offline HTTP fixture reaches the isolated network namespace. Cancelling
a stalled request closes its socket and leaves its cgroup unpopulated within the check.
This proves worker-future cancellation; scheduler tests separately prove cancellation
token propagation, including parent kill during child inference.

Missing capabilities, wrong sessions/agents/scopes, traversal, private broker addresses
and exhausted/replayed authority fail. Two exact immutable demo URLs are intentional
runtime exceptions to public DNS/address resolution; they cannot forward arbitrary
private requests and still require capabilities/confinement/taint. See architecture.md.
No Internet HTTPS fetch or IPv6 success was claimed.

Approval tests check exact arguments, supervisor-only decision, one-use consumption,
changed-context invalidation and inability to override unavailable confinement. Memory
reopening preserves taint; checkpoint rollback restores resident context without erasing
history, taint or budgets. Child checks preserve the inherited floor even when presenting
an ancestor token; nested re-delegation rejects that ancestor. Runtime budgets kill within
one invocation of tick; the 50 ms scheduler is cooperative and can be delayed by synchronous
storage, CPU saturation or the host. It is not a hard realtime deadline.

## Dependency audit and unverified environments

scripts/audit.sh shallow-clones the current official RustSec repository, fetches locked
registry metadata, then scans offline without suppressed advisories. The local checkout
was `3461c0d8f85d084552dd999c58d97c7123a9e0fd` (2026-10-01).
The remaining warning is [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173):
proc-macro-error2 2.0.1 is unmaintained, inherited through biscuit-quote/biscuit-auth 6.
Rust also reports its future incompatibility warning. Strict Clippy itself passes.

CI is configured for native Ubuntu 24.04 arm64 and amd64 runners, all tests/demos and
the audit script. It explicitly loads the Moby-derived AppArmor 4 profile when enforced.
Remote CI status is visible in [GitHub Actions](https://github.com/drmbios/praesidionyx/actions).
Native amd64 execution is delegated to CI; local measurements are arm64.
Docker Desktop on this Mac does not enforce AppArmor, so local parser acceptance is
not proof of AppArmor runtime behavior.

Ollama and Anthropic request/response/usage contracts are tested with offline loopback
HTTP fixtures. Real services, API keys, paid usage and model quality were not tested.
The daemon makes one initial completion at spawn; SDK programs drive subsequent syscalls.
Byte-based input estimates plus operator-configured conservative rates are admission
and accounting controls, not a hard remote billing cap after cancellation.

The MVP still trusts the host/kernel/Docker administrator/daemon/adapters. Persistent
agent recovery, global disk quotas, capability revocation, audit rotation/remote anchoring,
rate limits and production hardening remain open. SQLite is not independently signed or
encrypted; audit plus local checkpoint can be rolled back together by a volume administrator.
