# Security

This is a local-development MVP, not a production or hostile multi-tenant boundary.
Read [the threat model](docs/threat-model.md). Keep HTTP on loopback and the state volume
private. Only the fixed capability-scoped tools are supported. Sticky provenance requires
supervisor approval for writes, HTTP and child creation from untrusted context. Approval
is exact, one-use, expiring, and cannot create new authority.

Do not include keys, tokens, private prompts or .env files in issue reports.
Private vulnerability reporting is enabled. Report sensitive concerns to maintainer
[drmbios through a private security advisory](https://github.com/drmbios/praesidionyx/security/advisories/new).

Never mount the Docker socket or use privileged mode to make a probe pass. Missing
mandatory controls disable tools; never silently skip them. Root setup drops every
capability before the daemon. The fixed offline fixture URLs cannot forward arbitrary
requests. Model services and the trusted network broker remain daemon trust boundaries.

Audit failures refuse new authorized effects. Authenticated emergency kill and budget
termination still cancel the entire agent tree, then report the storage failure.
Preserve the state volume and verify a copy using an
independently pinned public key. Never delete history or regenerate keys to pass a check.
A local signed checkpoint detects suffix deletion but cannot detect joint rollback of
log and checkpoint by a volume administrator. SQLite is not independently signed/encrypted.

Provider cost estimates and cancellation are not contractual billing guarantees. The
scheduler is cooperative userspace scheduling, not hard realtime. Workspaces have no disk
quota and writes may be partial after cancellation. See verification.md for actual checks,
the upstream dependency warning and unverified platforms/provider integrations.
