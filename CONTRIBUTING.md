# Contributing to aegis

Thanks for looking at aegis. It's a defensive security tool, so contributions
that make detection better, code clearer, or claims more honest are all
welcome. This doc covers dev setup, testing, and the shape of a good PR.

## Table of Contents

- [Dev setup](#dev-setup)
- [Before you send a PR](#before-you-send-a-pr)
- [Where things live](#where-things-live)
- [Adding a detection rule](#adding-a-detection-rule)
- [Adding a persistence or checkup signal](#adding-a-persistence-or-checkup-signal)
- [Design constraints that PRs should respect](#design-constraints-that-prs-should-respect)
- [Reporting a security issue instead](#reporting-a-security-issue-instead)

## Dev setup

Requires Go 1.21+ (the toolchain auto-fetches the exact version pinned in
`go.mod` if needed).

```sh
git clone https://github.com/andreipaciurca/aegis
cd aegis
make build   # → ./aegis
make run     # build + launch the TUI
```

No other services, containers, or credentials are needed to build, test, or
run aegis locally. A few optional integrations (`aegis intel`, `aegis
clamav`, `aegis ai`) talk to services you configure yourself; none of them
are required for development.

## Before you send a PR

```sh
go vet ./...
go test -race ./...
gofmt -l .          # must print nothing
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

This is exactly what CI runs (`.github/workflows/ci.yml`), on Linux, macOS
and Windows, plus CodeQL and `govulncheck` (`.github/workflows/codeql.yml`,
`.github/workflows/security.yml`). Branch protection on `main` requires all
of it green before a PR can merge — including for the repo owner, so there's
no "just this once" direct push; go through a branch and a PR. If a change
touches a Windows-only code path (`internal/persist`
scheduled tasks/services, `internal/firewall`, `internal/checkup`), please
say so in the PR description — CI will exercise it, but a human should know
it wasn't hand-tested on real Windows.

For anything with non-obvious logic (a new detection rule, a parser, a
heuristic), add a table-driven test in the same package (`package x`, not
`package x_test` — this repo tests unexported functions directly; see any
existing `*_test.go` for the pattern) rather than only testing through the
CLI/TUI.

## Where things live

Each `internal/` package is one subsystem with a narrow job — read the
package doc comment at the top of its main file before changing it. The TUI
(`internal/ui`) and the browser GUI (`internal/gui`) are two separate
front-ends over the same core packages; a new capability usually means
touching the core package plus both front-ends plus `main.go`'s CLI wiring,
not just one of them.

## Adding a detection rule

The rule engine (`internal/rules`) is the easiest place to add a new
detection without touching scanner internals. See
[docs/rules.md](docs/rules.md) for the full schema and worked examples.
Built-in rules live in the `Builtin` slice in `internal/rules/rules.go`; add
a test case to `internal/rules/rules_test.go` alongside any new rule so a
future refactor can't silently break it.

Keep new rules conservative — a rule that fires on a real developer tool or a
common library string does more harm than a missed detection, because false
positives are what erode trust in a security tool.

## Adding a persistence or checkup signal

`internal/persist` audits autostart locations; `internal/checkup` audits OS/
dependency posture. Both follow the same shape: gather real state (a file, a
registry key, a command's output), turn it into `Entry`/`Check` values, and
let a small heuristic function decide what's suspicious. If you're adding a
new Windows/Linux/macOS signal, follow the existing per-OS function pattern
(`auditDarwin`/`auditLinux`/`auditWindows*`) rather than branching inline.

## Design constraints that PRs should respect

These aren't arbitrary — they're why aegis can plausibly ask antivirus
vendors for false-positive exceptions (see [SECURITY.md](SECURITY.md)) and
why it's safe to run with elevated capabilities like process termination and
firewall changes:

- **No daemons, kernel extensions, or background services.** Everything runs
  on demand and exits cleanly when closed.
- **Privacy-first, opt-in externalities.** Local AI is the default; remote
  backends, VirusTotal, and ClamAV are all explicit and user-triggered.
  Normal scans never call out to the network except to fetch signatures.
- **Prefer free, self-hostable, or public intelligence sources** over paid or
  closed ones — see the "Free and free-to-use detection sources" table in the
  [README](README.md#free-and-free-to-use-detection-sources).
- **Don't overclaim.** aegis is honest about not being a Bitdefender/
  Kaspersky replacement. Feature descriptions and marketing copy should stay
  in that register.

If a change would cut against one of these, it's not automatically wrong —
but explain the tradeoff in the PR description so it can be discussed
deliberately rather than drifting in unnoticed.

## Reporting a security issue instead

If you found a vulnerability rather than a feature to contribute, please
follow [SECURITY.md](SECURITY.md) instead of opening a public PR or issue
with exploit details.
