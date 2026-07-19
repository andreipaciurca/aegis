## What changed and why

<!-- One or two sentences. Link an issue if there is one. -->

## Checklist

- [ ] `go vet ./...`, `go test -race ./...` and `gofmt -l .` all pass locally
- [ ] New logic has a table-driven test in the same package (see any `*_test.go` for the pattern)
- [ ] If this touches detection (`internal/rules`, `internal/persist`, `internal/scanner`), I ran it against a clean sample to confirm it doesn't false-positive
- [ ] This doesn't add a background service, daemon, or default-on network call — see [CONTRIBUTING.md](../CONTRIBUTING.md#design-constraints-that-prs-should-respect)

CI (tests, CodeQL, govulncheck) must be green before this merges to `main`.
