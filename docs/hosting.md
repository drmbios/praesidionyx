# Hugging Face Space and project migration

The public Space is a free static website: policy simulation, context visualization,
and an actual credential-safe runtime recording. It uses local JavaScript and no API
keys, external inference, remote fonts or runtime daemon. Browser events are unsigned;
the recording is evidence from a separate Linux run, not a live session.

The Linux runtime requires real namespaces, Landlock, seccomp and delegated cgroups.
Its root-only container setup is intentionally not represented as a portable browser
or managed Space security boundary. Run it locally using the repository quickstart.

## Publish an update

After changing runtime code, rerun the checks and record the fixed demos. Copy
`docs/demo.cast` and `docs/demo-transcript.txt` into `space/`, and update the verified
counts in `space/verification.json`. Check the browser policy with:

```sh
node --test space/tests/*.test.mjs
node --check space/app.mjs
python3 -m http.server 18765 --bind 127.0.0.1 --directory space
```

Use the official Hugging Face CLI with a write-capable token supplied privately through
`HF_TOKEN` or its standard login flow. Never place tokens in files committed here,
command-line arguments, Git remotes, recordings or public logs.

```sh
hf upload drmbios/praesidionyx space --repo-type space
```

Space metadata lives in `space/README.md`; only that directory is uploaded to the Space.
The complete Rust runtime, tests and documentation live on GitHub.

## Rename compatibility

Praesidionyx replaces the previous development name. Crates, binaries, environment
variables, Python module, gRPC package, fixture URLs, AppArmor profile and state path
use the new name. HTTP request shapes remain unchanged. Existing clients must update
imports, commands, environment variables and the gRPC package.

The two old audit signing domains are intentionally retained for verification of
pre-rename records and checkpoints. New records/checkpoints use the new domains.
A regression test proves an old log can continue without rewriting any old bytes,
and that tampering still fails. Old agent identities/sessions are ephemeral and do
not recover at daemon restart; SQLite history and signing keys must be preserved.

On the verified host, the old daemon was stopped before copying the entire state
volume, preserving ownership/modes, into `praesidionyx_praesidionyx-state`. The original
volume remains untouched as a backup. Never mount both daemons against one writable
volume, discard a corrupt log, regenerate signing keys or reset history to pass checks.

Historical milestone reports use current command/path names for navigation. Their
original measurements remain historical; see `verification.md` for the current run.
