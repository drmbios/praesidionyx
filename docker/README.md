# Runtime security

Compose defaults to linux/arm64 and the short-compilation `quickstart` Cargo profile.
Set `PRAESIDIONYX_PLATFORM=linux/amd64` on x86; CI has native runners for both architectures.
Set `PRAESIDIONYX_BUILD_PROFILE=release` for optimized binaries. No images are published.

The trusted root entrypoint uses SYS_ADMIN to remount its private cgroup hierarchy,
CHOWN to delegate it, and SETUID/SETGID/SETPCAP to drop identity/groups/all capability sets.
The daemon is UID/GID 10001 with no effective/permitted/inheritable/ambient/bounding
capabilities. Compose enables no-new-privileges, a read-only root, 256 MiB/1 CPU/128 PID
outer limits, a bounded tmpfs and a private managed state volume. No Docker socket,
host source directory, host cgroup bind, host PID namespace or privileged mode is used.
Docker exec defaults to image UID 0, so human CLI commands explicitly use `--user 10001:10001`.

The outer seccomp profile is a vendored Moby default plus pivot_root; see
[provenance](seccomp-SOURCE.md). Each tool installs the narrower [worker allowlist](seccomp-worker.json),
Landlock V3, seven namespaces and delegated cgroup limits. Startup probes actual
confinement. Missing controls leave lifecycle/memory/audit available and disable tools.

Docker Desktop on the verified Mac has no AppArmor enforcement. On Ubuntu 24.04 with
AppArmor 4, load `docker/apparmor-praesidionyx` with apparmor_parser and select the explicit
`docker-compose.apparmor.yml` override. CI does this when AppArmor is present. The
Moby-derived profile permits required setup mounts/userns and retains proc/sys denials;
it does not disable AppArmor globally. Local parser validation is not enforcement proof.

Only the state volume and tmpfs are writable. Development containers mount source for
compilation and are not the runtime boundary. Compose passes optional provider settings
and the Anthropic API key from .env; never print resolved Compose configuration containing
secrets. Worker environments/mounts do not receive provider credentials.
