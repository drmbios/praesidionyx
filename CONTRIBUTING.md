# Contributing

Use stable Rust, `cargo fmt`, strict Clippy, and `cargo test --workspace --locked`.
Install `protoc`, or use `scripts/check.sh` to run everything in Docker. Keep the
lockfile committed. Tests must not need a model service or API key.

All crates forbid unsafe code except praesidionyx-sandbox; every unsafe block there must
explain its safety invariants. Document security/convenience tradeoffs and update the
STRIDE threat model whenever authority or trust boundaries change. Do not implement
future security controls as successful no-ops. Add tests for cross-agent and cross-role
authority whenever extending the API. Keep milestones independently reviewable.

Run `scripts/check-sandbox.sh` for mandatory real enforcement tests, `scripts/audit.sh`
for RustSec, and `sh scripts/demo.sh` against a mock Compose daemon for acceptance flows.
Do not remove the dedicated confinement case from CI because it is ignored in the normal
suite. Keep runtime documentation honest about cache conditions, unverified platforms,
provider billing and cooperative deadlines. Terminal recordings must never expose credentials.

The Space source is in `space/`. Run `node --test space/tests/*.test.mjs` and
`node --check space/app.mjs` after policy/UI changes. Keep simulation labels and
recorded-runtime evidence accurate. See [hosting](docs/hosting.md) before publishing.
