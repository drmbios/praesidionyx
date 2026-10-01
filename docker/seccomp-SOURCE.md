# Outer seccomp profile provenance

Base: [Moby profiles/default.json](https://github.com/moby/profiles/blob/main/seccomp/default.json), retrieved 2026-09-29.

Original SHA-256: `785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334`. Licensed Apache-2.0; see [upstream license](https://github.com/moby/profiles/blob/main/LICENSE).

Changes: retain the supported arm64/amd64 architecture mappings and allow `pivot_root` under the existing SYS_ADMIN setup condition. Other baseline rules are preserved. The daemon drops all capabilities after setup. Workers install the much smaller `seccomp-worker.json` allowlist before serving MCP; see architecture.md.

The optional `apparmor-praesidionyx` Linux profile is adapted from [Moby's AppArmor template](https://github.com/moby/profiles/blob/main/apparmor/template.go), Apache-2.0, Copyright The Moby Authors. It preserves proc/sys denials while permitting mount/pivot_root/userns setup, targets AppArmor ABI 4 with explicit Unix networking, and fixes the peer name to praesidionyx-sandbox. It must be explicitly loaded by the host operator (CI does this on ephemeral runners).
