# Repository security

GitHub protections configured on 2026-10-04 for
[drmbios/praesidionyx](https://github.com/drmbios/praesidionyx):

- Dependabot vulnerability alerts and automatic security update PRs are enabled.
  Weekly version update PRs cover Cargo, GitHub Actions and Docker. Updates require
  the same checks as other contributions; there is no automatic merge policy.
- Secret scanning and secret push protection are enabled. A separate Gitleaks job
  scans full Git history on pushes, pull requests and a weekly schedule. Its release
  archive has a pinned SHA-256 checksum and output redacts detected secret values.
- CodeQL default setup uses the extended query suite and remote/local sources for
  Rust, Python, JavaScript/TypeScript and GitHub Actions. GitHub manages its push,
  pull request and weekly scans. Rust uses analysis without a build; this does not
  cover generated code in the same way as a traced build.
- Actions are limited to GitHub-owned actions and full commit SHAs. Default tokens
  are read-only and cannot approve PRs. Checked-in workflows disable persistent
  checkout credentials and do not expose secrets to contributor code. External
  contributor workflow runs require maintainer approval.
- Private vulnerability reporting is enabled; use the link in SECURITY.md.

The active [main ruleset](https://github.com/drmbios/praesidionyx/rules/24429916)
requires pull requests, resolved conversations and up-to-date successful checks:
both native Linux architecture jobs, RustSec, dependency review and secret scanning.
Required checks are bound to the GitHub Actions application. CodeQL results are
required and block errors or security findings at medium severity or higher.
Deletion and force pushes are blocked, including for administrators; no bypass
actors are configured.

CODEOWNERS routes changes to @drmbios. There is currently one maintainer, so the
ruleset does not require an independent approval that the author cannot give to
their own PR. Add an independent review requirement when another trusted maintainer
joins. Before approving external workflow runs, inspect changes to workflows,
build scripts and executable source, including dependencies.

Checks are evidence for their specific coverage, not a production security guarantee.
Dependabot and RustSec depend on published advisories, while static analysis may
miss runtime logic flaws. The existing proc-macro-error2 maintenance advisory is
unsuppressed: disabling Biscuit 6.0.0's macro feature currently breaks its compilation.
Non-provider secret patterns and validity checks were not enabled by GitHub's API
in this repository configuration. Preserve the limitations in the threat model and
verification report when deploying or extending the runtime.
