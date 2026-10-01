# Threat model

Assets: authentication secrets, capability/audit signing keys, agent identities,
authority/quota decisions, private context/workspaces, provider credentials and audit
history. Prompts, external content and agent syscall requests can be adversarial.
The host kernel, Docker administrator, daemon, root entrypoint, fixed adapters and
build supply chain are trusted. Separate agent/supervisor APIs are trust boundaries.

STRIDE: S = spoofing; T = tampering; R = repudiation; I = information disclosure;
D = denial of service; E = elevation of privilege.

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| Agent transport | Bootstrap/session authentication plus Biscuit | Loopback HTTP has no TLS; host trusted | Parsed syscall decisions signed | Never log bearer secrets; supervisor can see prompts | 64 KiB bodies; floods remain possible | Supervisor service absent from agent socket/routes |
| Capability authority | Ed25519 root and server-authenticated subject | Ancestor checks preserved; trusted facts exclude appended blocks | Grant issuance/use signed | Tokens are bearer authority; keep private | Size/block/fact/iteration/evaluation bounds | Default policy rejects unsupported operations |
| Policy / quotas | Server supplies caller/resource/time/usage | Durable shared root counters; no refunds | Authorization signed before effect | Audit omits content/serialized tokens | Security mutex; 16 MiB audit cap stops service | Floor plus presented token prevents ancestor-token widening |
| Taint / approvals | Supervisor key decides; agent cannot self-approve | Exact args/cap digest/context revision; one-use expiry | Request/decision/consume signed | Supervisor sees requested args; no public queue | 32 queued requests per agent | Sticky taint survives derived data/rollback; approval cannot bypass capability |
| Registry / scheduler | UUID/session/private identity | Serialized state; monotonic deadlines | Budget/kill/pause/resume reasons signed | Private identity never returned | 1,024 registry entries; budgets and cancellation; no hard realtime | No arbitrary agent executables; parent termination cascades |
| Children / messages | Session plus own local cap | Exact inherited scope/floor; child budgets reserved | Delegation/send signed | Only addressed receiver; content omitted from audit | 64 messages/16 KiB; child budget/deadline ceilings | Ordered gates propagate taint before recipient effects; no fresh child grants |
| Provider | Only configured provider; Anthropic model pinned | Fixed Anthropic endpoint; trusted Ollama configuration | Authorization before dispatch; usage completion recorded | Prompt goes to selected service; API key never reaches workers | Output/token/cost estimates, 60 s timeout, bounded response | No provider tool-call interpreter; cancellation is not a billing guarantee |
| Memory | Session + own-UUID local cap | Owner-qualified queries, WAL/FULL transactions; DB itself trusted | Syscall audit plus episodic history | Owner scope; no encryption; supervisor/host trusted | Per-owner pages/snapshots; global disk quota absent | Agent cannot declassify data; rollback never restores authority |
| Audit / checkpoint | Independent pinned public key | Hash chain, signatures, canonical encoding, signed head | Edit/reorder/partial/suffix loss detected | No secrets/content in records | Sync verification/fsync, 16 MiB; rotation pending | Whole-volume rollback/key theft remain trusted-host risks |
| Tool bus / worker | Private single-use launch-bound MCP | Exact resource; openat2 prevents traversal/symlinks/hardlink writes | Separate authorization and outcome events | Namespaces, Landlock, no state mount; pinned destination socket | cgroups, timeout, I/O limits; disk quota absent | Fail closed on missing controls; seccomp denies exec/new sockets/namespace creation |
| Supervisor / key store | Separate key, 0600 files in 0700 directory | Daemon lock; replaced/missing keys refuse existing history | Supervisor decisions recorded | Host/Docker admins can read secrets; approval args private | Trusted supervisor can kill; floods can fill history | Only bootstrap-spawn/exact top-level tool issuance; no blanket approvals |

## Tested adversarial scenarios

- Missing/forged/wrong-issuer/wrong-subject/expired/exhausted tokens fail; unknown
  operations remain denied even with valid signatures. Concurrent one-call use cannot double spend.
- Appended scope/time/usage facts cannot override authority facts. Parent and descendants
  share counters across token branching and daemon restart. A child possessing an ancestor
  token still cannot lift its pinned floor; nested re-delegation rejects that ancestor.
- Wrong session/agent/path, traversal, symlink escape, hard-linked writes, oversized reads,
  private broker addresses and replay are denied. Real rmcp workers install mandatory controls.
- Hidden web instructions trigger needs_approval before a write. CLI denial prevents retry
  and no file exists. Approved requests cannot change arguments or replay; changed context
  invalidates approval. Derived trusted-labelled memory stays untrusted.
- Memory evicts/recalls within limits; cross-owner retrieval/snapshot rollback fails. Rollback
  restores resident context and retains sticky taint/history.
- Token, positive cost, tool and wall exhaustion stop an agent in one tick call. Pause cancels
  work; parent kill cancels even a child awaiting inference. Real worker cancellation closes
  its socket and leaves its cgroup unpopulated.
- One modified byte, whitespace, wrong key, reorder, partial record and suffix deletion
  against the signed checkpoint fail audit verification. Live mutation and corrupted startup fail closed.

## Prompt injection boundary

Taint is a conservative permission gate, not a classifier for malicious text. Every tool
output taints the process; untrusted writes, HTTP and child creation need an exact human
approval. Messages and derived memory inherit provenance. Paging and rollback cannot
launder it. Reads remain permitted only under their exact capability. An approved harmful
request can still cause harm; the human must review content and destination. Unknown
operations (including payments) remain unsupported. The demonstration uses a deterministic
adversarial harness and immutable pages, not a measured live-model detection rate.

## Residual risks

Host/Docker/kernel or daemon compromise is outside this boundary and can expose all state.
A volume administrator can roll back log and checkpoint together, steal signing keys or
change the host clock. External anchoring, isolated keys, revocation and clock hardening
remain future work. SQLite/episodic history is not separately signed/encrypted. Unknown
routes, malformed messages and health checks are outside parsed syscall auditing.

Authorization is intent, not a receipt: crashes can consume quota/approval without
completion. Filesystem writes can be partial and are not rolled back. Post-effect storage
failure leaves an ambiguous outcome. Interrupted two-file audit commits require investigation;
there is no automatic evidence-discarding repair. Preserve the volume and pinned public key.

Synchronous SQLite/fsync/full-audit verification can delay cooperative scheduler ticks.
Rate limiting, safe archival, global concurrency/storage limits and workspace garbage
collection are absent. The outer container can exhaust resources when many agents run.
Registry/session/identity/approval/delegation recovery is absent; persisted memory has no
owner recovery API. Exit/local grants expire after 24 hours, while agents have at most a
one-day wall budget. Pausing does not extend deadlines or replenish authority.

The root entrypoint briefly holds broad SYS_ADMIN for private cgroup setup, then clears
all capability sets. The outer Moby-derived filter allows pivot_root; workers install a
stricter filter. Linux AppArmor enforcement has only CI configuration plus local parser
validation here. No privileged mode, Docker socket or host cgroup mount is used.

Broker sockets constrain a destination, not every byte a compromised adapter could send
there; public servers can relay traffic. DNS itself is daemon egress; a cancelled resolver
may finish on a blocking pool. HTTP lacks confidentiality; HTTPS verifies hostname/roots.
IPv6-only destinations, nondefault ports and redirects are denied. Two exact reserved
fixture URLs return immutable compiled-in pages through loopback; no arbitrary private
URL forwarding is possible. Provider access is a separate trusted daemon egress path.

Remote usage can exceed byte-based estimates or continue after cancellation, so runtime
cost accounting is not a hard billing cap. Operator-supplied model prices must be
conservative; no live paid calls were verified. Dependency/adapter vulnerabilities remain
possible; the unsuppressed upstream maintenance warning is recorded in verification.md.
