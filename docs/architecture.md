# Architecture

The daemon is the trust boundary. A model cannot mint authority. Agent-directed
external work flows through the authenticated, capability-checked `invoke` API,
then a private MCP connection to a disposable worker.

## Authentication, capabilities and policy

`praesidionyxd` owns lifecycle state and invokes `praesidionyx-policy` before each implemented
agent syscall. Authentication identifies the bootstrap caller or an agent session.
A Biscuit independently grants the requested authority. Supervisors use their separate
key and socket; their available operations are explicitly allowlisted. No agent token
can issue capabilities, list agents or inspect audit records.

`praesidionyx-caps` uses biscuit-auth 6 with an Ed25519 root key. The authority block includes
a unique grant ID and exact operation/resource pair, plus checks for authenticated
subject, expiry, cumulative calls used and requested budget ceilings. Ambient context
comes only from the server. Explicit `trusting authority` scopes include the authorizer
but exclude appended blocks; attacker-supplied facts cannot change trusted scope or
context. Identifier syntax is intentionally narrow and values are never interpolated
as arbitrary Datalog source. Tokens are size/block bounded, with 256 facts, 16 iterations
and a 50 ms evaluation limit. The pinned root public key verifies every token.

Attenuation appends checks without the private issuer key. It cannot remove ancestor
checks or introduce rights the root never issued. Exact scopes are intersected; broader
or conflicting appended values cannot widen the parent's permissions. All token branches
retain the same authority grant ID and share a durable usage counter. A `max_calls` of 1
means total calls under the root must be below 1, not an extra call after delegation.
The holder retains its original token: attenuation is not revocation.

The bootstrap CLI is a human provisioning tool. When a human calls `praesidionyx spawn`
without a token file, it makes an authenticated supervisor issuance request first.
The agent SDK cannot do this implicitly. Spawned agents receive a UUID-bound session,
a one-use exit token, and an own-UUID local capability for memory, messages, yield
and child creation. Local authority cannot touch files or networks. Child creation
requires the exact delegated tool capability in addition to local authority.

## Audit integrity and ordering

`praesidionyx-audit` opens the JSONL file with append semantics and a single-writer lock.
Each canonical record contains its sequence, previous hash, timestamp, actor, operation,
outcome, optional grant ID and target. Domain-separated SHA-256 hashes are signed with
a kernel Ed25519 key distinct from the capability root and both authentication keys.
Verification rejects changed content/whitespace, malformed or partial lines, reordered
records, incorrect hashes and invalid signatures, using a separately pinned public key.

A signed `audit.head` checkpoint records the last committed sequence/hash. Append order:
revalidate disk against the current head, append record, fsync the log, write/fsync a
new checkpoint, atomically rename it, then fsync the parent directory. Log truncation
is detected against that checkpoint. An interrupted two-file commit is an error, never
an implicit repair. Any write/integrity failure poisons the writer and refuses further
operations. Startup also verifies all history and refuses missing/replaced keys.

Capability verification, recording authorization, and incrementing usage happen under
one security mutex. Registry transitions are serialized. An `authorized` record is
durable **before** inference or lifecycle mutation. It proves authorization, not that
a later side effect completed; a crash may consume a call without producing an agent.
No automatic replay refunds the call. Usage is reconstructed from verified authorized
records after restart. Agent registry state still is not persisted.

## Explicit tradeoffs and limits

- The checkpoint is local. An attacker who can roll back **both** log and checkpoint
  can replay an older consistent history; compromise of signing keys can forge records.
  External checkpoint anchoring and key isolation are future work. Host administrators
  and Docker administrators are trusted. Pin/export the public key independently.
- Audit uses synchronous fsync and full verification before each append, favoring
  integrity over throughput. The MVP stops at 16 MiB of log data and fails closed.
  Automatic rotation/recovery is not implemented. Preserve the full volume on errors;
  investigate with offline verification before any operator-approved recovery. Deleting
  the log/checkpoint or starting with fresh keys would destroy evidence and quota history.
- Unknown routes, malformed transport payloads and health checks do not reach a syscall
  and are not signed audit records. Parsed syscall authorization attempts and supervisor
  access decisions are recorded. Flood protection and audit retention remain open work.
- Call quotas survive restarts. Runtime budgets are enforced by the scheduler described
  below. Capability expiry uses the host wall clock; runtime deadlines use monotonic time.
- Agent metadata remains in the daemon; tool execution runs in separate per-agent
  workers. This is a fixed, trusted tool adapter, not an arbitrary-code execution API.
- HTTP has no TLS and is published only on the Mac loopback interface (18080/18081).
  The standard Docker bridge permits trusted-daemon egress; an internal bridge did not
  publish working host ports in local tests. Only the trusted broker opens sockets;
  workers receive a single connection for an authorized URL.
- Secret key files/sockets use mode 0600 inside a 0700 state directory. The daemon lock
  prevents replacing live sockets. State and bootstrap/supervisor authentication keys
  survive container upgrades; new audit and capability keys are generated on first M2 boot.
- Ed25519 identities and session keys are ephemeral. Agent exit capabilities expire
  after 24 hours. Supervisor kill is immediate; registry recovery remains future work.

## MCP tools and confinement

`fs.read`, `fs.write`, and `http.get` use rmcp over private stdin/stdout pipes.
There is no public MCP listener. Every launch is bound to one tool and canonical
resource, and the worker rejects a second call or arguments that differ from its
launch grant. Supervisor issuance binds the Biscuit subject to a running agent UUID.
The resource is `file:<sha256(relative path)>` or `url:<sha256(canonical URL)>`, avoiding
Datalog string interpolation and keeping URL queries out of audit records. File tool
names remain distinct operations even when the resource hash matches.

Calls for one agent are serialized; exit waits for an in-flight call. Authorization
and shared-quota consumption are durable before a worker or connection is created.
Success and tool errors receive separate completion records. Cancellation/crash may
leave only an authorization record. Writes are bounded but not transactional: a
partial write or a missing completion record does not imply rollback. No automatic
retry/refund occurs. A failed post-operation audit append is an ambiguous outcome.

Every worker has new user, mount, PID, network, IPC, UTS and cgroup namespaces via
bubblewrap. It sees its own workspace at `/work`, runtime libraries read-only, minimal
`/dev`, and a private temporary mount. No daemon state, keys, host source, cgroup tree,
or `/proc` mount is exposed. A temporary proc directory descriptor supplies namespace
evidence during startup, then closes before Landlock/MCP. The parent compares all
seven namespace IDs against its own. The UID has no capabilities after bubblewrap setup.

Landlock V3 must report **FullyEnforced**. It handles all V3 filesystem access types,
allowing only reads under `/work`, plus regular-file creation/write/truncation for
`fs.write`. Seccomp defaults to EPERM, allows the syscalls listed in
`docker/seccomp-worker.json`, and denies socket creation/connect, exec, process fork,
mounts, namespace creation, ptrace and BPF. Conditional rules permit only same-process
threads and anonymous AF_UNIX socket pairs for Tokio bookkeeping. `clone3` returns
ENOSYS so glibc falls back to the filterable `clone` flags. Actual outside-file,
socket, exec and namespace denial probes run before serving requests.

The launcher moves the child into a cgroup **before** executing bubblewrap. Each
agent has a 128 MiB, 0.5 CPU, 32-PID parent; each invocation has 64 MiB, zero swap,
0.5 CPU (`50000 100000`) and 32 PIDs, including its monitor. The daemon checks these
values again before accepting the worker's result. Ten seconds bounds resolution,
connection, MCP startup and execution as observed by the caller. An underlying
system DNS lookup may continue on the daemon blocking pool after cancellation.
Timeout/cancellation kills the entire invocation
cgroup. Empty cgroups from interrupted calls are reaped on the next launch. These are
fixed isolation limits independent of the aggregate scheduler budgets.
Workspaces persist on disk, while identities/registry still do not survive restart.
There is no workspace disk quota or garbage collection yet.

File paths are relative, at most 512 bytes, with plain ASCII components. Absolute
paths, empty/dot/parent components, escapes and separators other than `/` are rejected.
`openat2` uses BENEATH, NO_SYMLINKS and NO_MAGICLINKS; hard-linked and non-regular files
are rejected before truncation. Parents must already exist. Reads, writes and HTTP
bodies are UTF-8 and limited to 32 KiB. A write replaces the existing file contents.

For HTTP, the broker resolves an exact authorized HTTP(S) URL once, rejects private,
loopback, link-local, multicast, reserved and documentation IPv4 ranges, and connects
to the validated address. IPv6-only destinations are unsupported and denied. Only
ports 80/443 for their respective schemes are allowed. No credentials, fragments,
custom request headers, proxies, cookies or redirect following are implemented.
The socket crosses into the otherwise disconnected network namespace; the worker
performs HTTP and, for HTTPS, verified TLS using bundled public roots and URL hostname.
It cannot create or connect another socket. The broker and trusted worker adapter
remain part of the security boundary: a compromised adapter could send other bytes
to its already-authorized endpoint. Plain HTTP provides no transport confidentiality.
Private confinement tests can supply a local connection directly. The daemon also
recognizes exactly two immutable offline demo URLs: `http://fixtures.praesidionyx.invalid/injection`
and `http://fixtures.praesidionyx.invalid/research`. They return compiled-in fixture bytes via
a loopback connection and still require a URL capability, a real isolated worker, and
normal taint/approval checks. These two reserved URLs never resolve DNS or forward input
to another service. There is no arbitrary-address bypass flag. This convenience remains
available with every provider and is an explicit exception to public-address resolution.

## Provenance and approvals

Labels form `trusted < user < untrusted`; joins retain the least trusted input. Prompts
and model responses start as user data; all tool output, including errors, taints the
agent before external I/O. Derived memory and messages inherit context provenance.
Taint is sticky for the lifetime of the agent and in its SQLite owner record. Paging,
recall, rollback and an agent-requested trusted label cannot clear it. This intentionally
over-blocks innocuous subsequent operations to avoid treating model reasoning as declassification.

An untrusted agent needs supervisor approval for `fs.write`, `http.get` and child creation.
`fs.read` remains available with its exact capability. Payments and arbitrary tools are
not implemented. A valid capability is checked before enqueueing; approval grants no
new authority. A request binds agent, operation, canonical arguments, capability digest,
context revision and a five-minute expiry. Approve/deny never executes anything; the
agent retries the exact request with its approval ID. Consumption is one-use and durable
before execution, followed by normal capability, budget and sandbox checks. Failure can
consume approval and quota. Changed context invalidates an earlier approval.

Per-agent gates serialize invokes, memory, child creation and exit. Inter-agent sends
acquire sender/recipient gates in UUID order, so new taint cannot race an approved effect
and cross-sends cannot deadlock. Supervisor kill bypasses a busy gate to cancel work.
Approval queues (maximum 32 entries per agent) are ephemeral, including decisions; there
is no blanket approval, declassification API, or silent retry.

## Memory

SQLite WAL with FULL synchronous commits stores owner-scoped pages, 128 resident-page
snapshots per agent and an episodic event history. Each agent has at most 4,096 items,
each 1..32,768 UTF-8 bytes. A context token is conservatively counted as one UTF-8 byte,
not an exact model tokenizer. Oldest whole pages leave the resident set when it exceeds
the context limit; oversized pages remain available in long-term storage.

Offline embeddings are normalized 64-dimensional hashed word vectors. `sqlite-vec`
calculates L2 distance over the owner's ordinary page table; this is deterministic
lexical retrieval, not a learned semantic model or a scalable vector index. Recall
replaces the resident set with best-fitting ranked items within the requested/context
limit. Rollback restores resident IDs, not files, budgets, taint, messages, or external
effects, and never erases subsequent long-term items/history. Ownership is part of every
query; another agent cannot restore an owner's snapshot. SQLite itself is trusted state,
not independently signed or encrypted. Its extension registration FFI lives only in
`praesidionyx-sandbox`; memory and all other crates forbid unsafe Rust.

Pages/history persist across restart, but identities, sessions, delegation maps and
registry entries do not. The MVP has no API to recover an old owner after restart.
Per-owner bounds do not replace global storage quotas, archival or garbage collection.

## Scheduler, providers and children

A Tokio scheduler ticks every 50 ms. Wall deadlines use monotonic time and continue
while paused. Token/cost usage comes from provider responses; the mock conservatively
counts bytes and costs zero. Tool calls reserve usage before dispatch; failed calls
count. The final allowed tool call can complete, then the next tick kills the exhausted
agent. Admission also checks exhaustion, and zero tool budget rejects the first tool
attempt. Token, positive cost, tool and wall exhaustion stop the agent and sign a reason
record in one call to `tick`. This is a cooperative userspace guarantee, not hard realtime:
blocking SQLite/fsync, CPU saturation or a stalled host can delay a tick.

Pause cancels current inference/tool work; resume creates a fresh cancellation token.
Kill, deadline exhaustion and parent termination cancel work and cascade through descendants,
including children registered as created before inference. Dropping a tool future kills
its invocation cgroup. Resume does not replenish budgets. Typed text/task/result messages
are bounded to 16 KiB and 64 queued messages per receiver; receive dequeues one and yield
cooperatively gives Tokio a turn. This is a concurrent agent registry, not an OS process
for arbitrary agent binaries or an autonomous model/tool planning loop. SDK scripts drive
subsequent syscalls; the configured provider performs one initial completion at spawn.

Child creation reserves tokens, tool calls and cost from the parent's remaining budget
up front, without refunds on failure; it cannot extend the parent's wall deadline. A
full reservation can exhaust the parent on the next tick. The child gets a separate
workspace/session/identity and inherits provenance. Its tool token appends expiry/quota
checks to the supplied parent token. The kernel pins that token as the child's floor
and checks both floor and presented token on every use, retaining the original subject
and shared root counter. Possessing an ancestor token cannot lift the floor. Nested
re-delegation must use the exact inherited token so no earlier block is discarded;
additional holder-side narrowing is supported for invocation, not nested re-delegation.
Supervisors cannot issue fresh tool grants directly to children. Children receive only
own-UUID memory/message/exit authority plus the one delegated tool scope.

Inference releases the registry mutex, allowing other agents and ticks to proceed.
Unknown usage after timeout/cancellation retains the full reserved token/cost budget.
`mock` is default. Ollama uses the configured host endpoint; Anthropic uses its fixed
HTTPS endpoint with a pinned model and explicit conservative integer micro-USD rates
per input/output token. Requests bound output using a byte-based input estimate plus
framing; responses supply authoritative usage. No automatic retries, redirects, proxies,
streaming or provider-side tool calls are enabled. Responses are bounded to 1 MiB and
text to 32 KiB. These are accounting/admission controls, not a contractual billing cap:
remote servers can finish/bill cancelled work or report more usage than estimated.
Provider secrets stay in daemon environment and never enter worker mounts/environment.

Provider contracts: [Ollama generate](https://github.com/ollama/ollama/blob/main/docs/api.md),
[Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create).


## Linux features and container authority

Five diagnostic probes cover Landlock, seccomp, user namespaces, cgroup v2 and eBPF.
An additional real worker self-test gates `tool_execution_enabled`. Missing any
mandatory tool control disables tools while lifecycle/audit remain available. eBPF
is diagnostic and not required by this implementation. Every launch reinstalls its
controls; startup success is not a cached permission to skip later enforcement.

The entrypoint starts as root only to remount the container's **private** cgroup v2
hierarchy writable, move itself into a daemon leaf, enable cpu/memory/pids controllers,
and delegate the agents subtree. It then switches to UID/GID 10001 and clears all
effective, permitted, inheritable, ambient and bounding capabilities before praesidionyxd.
Each setup step must succeed; failures are logged and the real sandbox probe decides
availability. There is no privileged mode, Docker socket, host cgroup bind or host PID
namespace. The root filesystem is read-only; state and bounded `/tmp` are writable.
Outer limits remain 1 CPU, 256 MiB and 128 PIDs.

| Container setup capability | Reason |
|---|---|
| SYS_ADMIN | Remount the private cgroup hierarchy writable during setup |
| CHOWN | Delegate the cgroup control files/subtree to UID 10001 |
| SETUID | Drop to the daemon UID |
| SETGID | Drop group identity and clear supplementary groups |
| SETPCAP | Empty the capability bounding set before daemon execution |

SYS_ADMIN is broad authority during the trusted entrypoint. This is an explicit
Docker Desktop compatibility tradeoff, not a capability retained by the daemon.
`docker/seccomp-container.json` preserves a vendored Moby default allowlist plus
`pivot_root` for bubblewrap setup; see its provenance file. Kernel capability checks
still gate namespace/mount operations. Each worker adds its much narrower filter.
On Linux with AppArmor, Docker's default profile denies mounts. CI explicitly loads
`docker/apparmor-praesidionyx` and selects `docker-compose.apparmor.yml`; this opt-in
Moby-derived profile permits mount/pivot_root/userns setup while retaining proc/sys
write denials. It does not disable AppArmor globally. The profile requires AppArmor 4
(Ubuntu 24.04). Docker Desktop on this Mac has no active AppArmor layer. Other hosts
may fail the probe and must report disabled tools rather than skip a control. Human Docker
exec commands specify `--user 10001:10001`; health checks also drop capabilities/UID.
Unsafe FFI is limited to the sandbox crate, with safety comments; all other crates
forbid unsafe code.

References: [rmcp](https://docs.rs/rmcp/3.5.0/rmcp/),
[Biscuit authorizers](https://docs.rs/biscuit-auth/6.0.0/biscuit_auth/builder/struct.AuthorizerBuilder.html),
[Linux Landlock](https://docs.kernel.org/userspace-api/landlock.html),
[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

Compose defaults to the unoptimized `quickstart` Cargo profile with debug symbols disabled
to shorten initial compilation. `PRAESIDIONYX_BUILD_PROFILE=release` selects optimization. Both
profiles use identical policy and confinement code; neither relaxes a security control.
