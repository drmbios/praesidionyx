# Agent and supervisor API

Agent HTTP: `127.0.0.1:18080`; supervisor HTTP: `127.0.0.1:18081`. gRPC services use
separate `agent.sock` / `supervisor.sock` in PRAESIDIONYX_STATE_DIR. Except `/healthz`, requests
require `Authorization: Bearer KEY`. JSON uses snake_case; large uint64 values need care
in JavaScript. The source contract is `crates/praesidionyxd/proto/praesidionyx.proto`.

| Operation | gRPC | HTTP | Authority |
|---|---|---|---|
| Spawn | AgentSyscalls.Spawn | POST agent /v1/agents | bootstrap key + spawn Biscuit |
| Invoke | AgentSyscalls.Invoke | POST agent /v1/invoke | own session + exact tool Biscuit |
| Memory | AgentSyscalls.Memory | POST agent /v1/memory | own session + own local Biscuit |
| Message/yield | AgentSyscalls.Message | POST agent /v1/message | own session + own local Biscuit |
| Child | AgentSyscalls.SpawnChild | POST agent /v1/children | own session + local and delegated tool Biscuit |
| Exit | AgentSyscalls.Exit | POST agent /v1/agents/{id}/exit | own session + own exit Biscuit |
| List | Supervisor.ListAgents | GET supervisor /v1/agents | supervisor key |
| Features | Supervisor.Features | GET supervisor /v1/features | supervisor key |
| Issue spawn | Supervisor.IssueCapability | POST supervisor /v1/capabilities | supervisor key |
| Issue tool | Supervisor.IssueToolCapability | POST supervisor /v1/capabilities/tools | supervisor key |
| Approvals | Supervisor.ListApprovals | GET supervisor /v1/approvals | supervisor key |
| Approve/deny | Supervisor.DecideApproval | POST supervisor /v1/approvals/decide | supervisor key |
| Kill/pause/resume | Supervisor.Control | POST supervisor /v1/control | supervisor key |
| Verify/tail | Supervisor.AuditVerify/AuditTail | GET supervisor /v1/audit/verify or /tail | supervisor key |

## Lifecycle, budgets and grants

A budget has tokens, wall_time_ms, tool_calls, cost_microusd. Spawn validates positive
tokens (at most 1,000,000), wall 1..86,400,000 ms, tools at most 100,000, cost at most
1,000,000,000 micro-USD. A zero tool budget allows local syscalls, but the first tool
attempt stops the agent. Cost zero permits only free usage. Tool grants reserve one
call/10,000 ms/zero model tokens or cost per invocation; root quotas count failed calls.

Supervisor spawn issuance takes max_calls 1..1024, ttl_seconds 1..86400, and budget.
It grants only bootstrap / agent.spawn / agents. Spawn:

```json
{"spec":{"name":"demo","provider":"mock","model":"mock-v1","prompt":"Hello","context_window":4096},"budget":{"tokens":4096,"wall_time_ms":60000,"tool_calls":16,"cost_microusd":0},"capability":"SPAWN_BISCUIT"}
```

Spawn returns agent plus secret session_token, exit_capability and local_capability.
The own-UUID exit grant is one-use; local grant covers only memory/message/yield/child
creation and lasts 24 hours with 100,000 calls. Authentication and authority are separate.
Agent includes public identity, spec, budget, used, state, context_label/context_revision
and parent_id. `mock_response` is the legacy field for the initial response of every
provider. Wall usage is sampled on scheduler ticks; it continues while paused.
Exit body: `{"status":0,"capability":"EXIT_BISCUIT"}`. Exit stops descendants.

Control body: `{"agent_id":"UUID","action":"kill"}` (or pause/resume). Kill cancels
work and descendants; resume never refunds budget. List excludes credentials but
includes prompts/results for the trusted supervisor. Typed state transitions reject
invalid combinations with 409. Token/cost/tool/wall exhaustion writes an agent.kill
record with a budget reason. Tick interval is 50 ms, without hard realtime guarantees.

## Tools and exact approvals

Issue-tool body: agent_id, tool (`fs.read`, `fs.write`, `http.get`), exact relative path
or URL in resource, max_calls, ttl_seconds. No globs; direct tool issuance to a child
is forbidden. Scope uses file/url SHA-256 canonical bytes. Invoke:

```json
{"agent_id":"UUID","tool":"fs.write","args_json":"{\"path\":\"note.txt\",\"content\":\"hello\"}","capability":"TOOL_BISCUIT","approval_id":""}
```

Read arguments: path; write: path/content; HTTP: url. Unknown arguments fail. Paths are
plain relative ASCII, no traversal/symlink/hardlinks; parent directories must exist.
UTF-8 I/O is bounded to 32 KiB. HTTP permits public IPv4 on scheme-default port 80/443,
verified HTTPS, no redirects/proxy/credentials/fragments/custom headers. Two exact
reserved URLs, `http://fixtures.praesidionyx.invalid/injection` and `/research`, return
immutable offline fixtures through the same confined worker.

Invoke returns outcome completed, label untrusted, result_json with output, sandbox,
limits and is_error, or outcome needs_approval with request_id and result_json `{}`.
Tool-level errors return is_error true; setup/broker/cancellation errors return 503.
Any tool result taints future context. Untrusted writes/HTTP/child creation require
approval. An approval request does not execute or consume tool quota.

List approvals to review agent/tool/args/expiry/revision; decide with
`{"request_id":"UUID","approve":true}` (false to deny). Retry the identical invoke
with approval_id. A decision never executes it. Changed arguments/capability/context,
expiry, denial or replay fail. Approval cannot override a capability or unavailable
confinement. Queue decisions are ephemeral and expire after five minutes.

CLI: `praesidionyx approvals`, `praesidionyx approve REQUEST`, `praesidionyx deny REQUEST`;
`praesidionyx invoke fs.read --credentials-file SPAWN_JSON --capability-file GRANT_JSON
--args '{"path":"note.txt"}'`. Add --approval-id for an exact approved retry. Token
files may contain raw tokens or issuance JSON. Keep credentials private.

## Memory

Memory body: agent_id, local capability, operation, content, label, max_tokens,
snapshot_id. Operations context/checkpoint ignore content; remember uses content and
label; recall uses content as query and max_tokens; rollback uses snapshot_id.

```json
{"agent_id":"UUID","capability":"LOCAL_BISCUIT","operation":"recall","content":"apple","label":"user","max_tokens":128,"snapshot_id":""}
```

Response is result_json: remember returns item (id/content/label/tokens), recall returns
items, context/rollback returns items/tokens/limit/label, checkpoint returns snapshot_id.
Context estimates one UTF-8 byte as one token. Recall replaces the resident set with
ranked items within min(requested limit, context limit). Rollback restores resident
IDs without deleting long-term history or clearing taint. Cross-owner access fails.
Agent-supplied trusted labels cannot promote current provenance.

CLI `praesidionyx memory --credentials-file SPAWN_JSON context` prints parsed JSON;
remember/recall/checkpoint/rollback accept --content, --label, --max-tokens, --snapshot-id.

## Messages and children

Message body: agent_id, local capability, operation send/receive/yield, target_id,
kind text/task/result, content. Send returns message_id; receive returns message or
null; yield returns yielded true. A delivered message includes sender/kind/content/label
and taints its receiver before an external effect. Payload 16 KiB, queue 64 entries.

Child body: agent_id (parent), local capability, spec, budget, tool, resource,
delegated_capability and approval_id. Outcome needs_approval follows the same exact
review/retry flow; completed returns child (SpawnResponse) and delegated_capability.
Child budgets are positive for token/time/tools and cannot exceed parent's remaining
allocation/deadline. Tokens/tools/cost are reserved up front, without failure refunds.
Separate workspace/session/identity, inherited taint, original scope and root quota
remain. Nested delegation must use the exact inherited token; invocation can further
attenuate it. Parent termination kills descendants, even during initial inference.

Dependency-free SDK: AgentClient(bootstrap_key, base_url, timeout=65); spawn accepts
provider/model/context_window/budget overrides; memory(credentials, operation, ...),
message(credentials, operation, ...), spawn_child(credentials, spec, budget, tool,
resource, delegated_capability, approval_id=""). Invoke parses result_json into result.
See executable demos for complete credential-safe requests. Provider completion happens
once on spawn; callers drive subsequent syscalls, not an automatic planner.

## Audit and errors

Audit omits prompts/results/secrets/serialized capabilities. Tail returns JSON strings
(gRPC 1..100 limit; HTTP defaults 20). Verify returns record count, hash and public key.
For an exported copy, pin the public key through a trusted channel:

```sh
praesidionyx audit verify --file audit.jsonl --public-key-file audit.pub --checkpoint audit.head
```

Without checkpoint, suffix deletion cannot be detected. Corrupted live history refuses
new appends/API actions; offline verification remains available. Joint rollback of log
and checkpoint is a host trust limitation. Never reset keys/history to pass verification.

Errors: 401 auth; 403 capability/policy/approval; 400 validation; 404 unknown agent/request;
409 state/provider conflict; 429 quotas/capacity; 503 storage/provider/tool/confinement.
64 KiB transport body; 16 KiB capability/eight blocks. Unknown routes are not no-ops.
Malformed transport requests and health checks are outside signed syscall auditing.
