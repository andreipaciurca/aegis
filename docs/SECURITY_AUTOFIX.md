# Security Autofix Workflow

## Table of Contents

- [Goal](#goal)
- [Recommended Setup](#recommended-setup)
- [Human Review Gate](#human-review-gate)

## Goal

aegis should let automation do the boring first pass, but a human should still
review security-sensitive code before merge.

The recommended flow is:

1. CodeQL, `govulncheck`, dependency review, tests and release packaging run on
   every pull request.
2. GitHub CodeQL/Copilot Autofix proposes a patch or opens a fix PR when the
   repository has that feature enabled.
3. CI proves the generated fix on Linux, macOS and Windows.
4. The `Ready for review` workflow labels the PR once all checks pass.
5. A maintainer reviews and merges.

## Recommended Setup

In GitHub repository settings:

- Enable **Code scanning** with CodeQL.
- Enable **Copilot Autofix for CodeQL alerts** if it is available for the
  account/organization.
- Keep branch protection on `main`.
- Require these checks before merge:
  - `Test (ubuntu-latest)`
  - `Test (macos-latest)`
  - `Test (windows-latest)`
  - `staticcheck`
  - `Installer syntax`
  - `Release package dry run`
  - `Analyze (Go)`
  - `CodeQL`
  - `govulncheck`
  - `Dependency review`

For dependency updates, Dependabot can safely open PRs automatically; keep
automatic merge disabled unless the change is patch-level, CI is green, and a
maintainer has approved the repository policy.

## Human Review Gate

The repository workflow `.github/workflows/ready-for-review.yml` adds a
`ready-for-review` label and one comment after all checks on a PR have passed.
It does not merge. That keeps generated or mechanical fixes out of `main` until
someone has read the diff.
