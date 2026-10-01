# Milestones and acceptance

All seven milestones are implemented and locally verified on Apple Silicon/Docker
Desktop. The user's standing approval authorized continuing through the remaining
milestones. No remote repository, publication or remote CI execution was performed.

| Milestone | Status and evidence |
|---|---|
| 1 — workspace, boot, probes, providers, lifecycle | Complete; HTTP/Unix gRPC demos and feature report |
| 2 — Biscuit, policy, signed audit | Complete; attenuation/shared-quota/tamper tests and CLI demo |
| 3 — MCP tools and confinement | Complete; mandatory real-worker checks, offline fixture and cancellation |
| 4 — taint and approvals | Complete; hidden write denied, approved summary written, exact/stale/replay tests |
| 5 — SQLite/sqlite-vec memory | Complete; paging/recall/rollback/ownership/sticky taint and persistence tests |
| 6 — scheduler and multi-agent | Complete; all budgets stopped in one tick call, inference preemption, messages, child floor/delegation/cascade |
| 7 — quickstart, docs and terminal demo | Complete locally; 113.7 s measured quickstart, Mermaid/STRIDE docs, validated cast/transcript |

| Required acceptance | Current evidence |
|---|---|
| No capability means no file/network access | Exact authenticated capability required; denial before worker launch; real sandbox probes |
| Child never widens parent rights | Biscuit ancestor checks, kernel-pinned floor, shared counters; ancestor-token/nested-delegation tests; child write/path denied live |
| One byte changes audit verification | Unit/live/restart tests plus exported-copy CLI demo; signed head detects suffix loss |
| Hidden prompt injection blocked by default | Real HTTP fixture -> untrusted context -> needs_approval -> supervisor CLI denial -> no created file |
| Budget exhaustion kills in one scheduling tick | Direct one-tick tests for wall/token/cost/tool exhaustion; live tool-budget kill; 50 ms cooperative tick, not hard realtime |
| Full suite offline with mock | 31 workspace tests plus 1 explicitly selected real-confinement test, Docker network none/Cargo offline; no API keys |

See [verification](verification.md) for reproduction, timing/cache conditions, the
unsuppressed dependency warning and unverified CI/platform/provider boundaries.
