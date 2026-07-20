<table align="center">
<tr><td align="center">

<img src="docs/favicon.svg" width="72" height="72" alt="aegis logo">

# aegis

[![CI](https://github.com/andreipaciurca/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/andreipaciurca/aegis/actions/workflows/ci.yml)
[![Release](https://github.com/andreipaciurca/aegis/actions/workflows/release.yml/badge.svg)](https://github.com/andreipaciurca/aegis/actions/workflows/release.yml)
[![Pages](https://github.com/andreipaciurca/aegis/actions/workflows/pages/pages-build-deployment/badge.svg)](https://andreipaciurca.github.io/aegis/)
[![Go](https://img.shields.io/github/go-mod/go-version/andreipaciurca/aegis)](go.mod)
[![Latest release](https://img.shields.io/github/v/release/andreipaciurca/aegis?include_prereleases)](https://github.com/andreipaciurca/aegis/releases)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-a6e3a1)](LICENSE)

</td></tr>
</table>

**aegis** is a fast, small internet-security app for people who want useful
protection without a heavyweight agent: malware and ransomware scanning,
firewall control, network monitoring, persistence audits, OS/dependency
checkups, encrypted quarantine and optional local AI.

It ships as one static binary for macOS, Linux and Windows. No daemon. No
kernel extension. No browser extension. It runs when you run it and uses the
security machinery your OS already provides.

**AEGIS** means **Adaptive Endpoint Guard for Internet Safety**.

- Official site: <https://andreipaciurca.github.io/aegis/>
- Releases: <https://github.com/andreipaciurca/aegis/releases>
- Full user guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- Trust and verification: <https://andreipaciurca.github.io/aegis/trust.html>

## Table of Contents

- [What You Get](#what-you-get)
- [Install](#install)
- [First Run](#first-run)
- [Daily Commands](#daily-commands)
- [Safety Model](#safety-model)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## What You Get

```text
 AEGIS    1 Dashboard   2 Scanner   3 Shield   4 Network   5 Firewall   6 Audit   7 AI
────────────────────────────────────────────────────────────────────────────────────────

  FIREWALL        MALWARE SCAN      RANSOM SHIELD     NETWORK
  ● ACTIVE        ● CLEAN           ● MONITORING       0 flagged

  PERSISTENCE     SIGNATURES        LOCAL AI           CHECKUP
  15 entries      1067 hashes       optional           OS + deps
```

- **Scanner:** SHA-256 signatures, YARA-lite rules, entropy checks, EICAR,
  filename heuristics and encrypted-file clues.
- **Ransomware shield:** harmless canary files plus ransom-note, extension and
  magic-byte mismatch checks.
- **Firewall panel:** native macOS Application Firewall/pf, Linux ufw/nftables/
  iptables, and Windows Defender Firewall helpers.
- **Network monitor:** live connections and risky listeners, with remediation
  hints.
- **Persistence audit:** LaunchAgents, systemd, cron, registry Run keys,
  Scheduled Tasks and services.
- **Encrypted quarantine:** suspicious files are sealed into `.aqv` vaults with
  signed metadata. Restore defaults to a safe review folder.
- **GUI and TUI:** use `aegis`, `aegis gui` or `aegis app` depending on how you
  like to work.
- **Optional analyst:** local llama.cpp or an explicit OpenAI-compatible
  backend can explain findings, but never overrides deterministic detections.
  Run `aegis ai install` for the default local llama.cpp + Gemma setup.

## Install

macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/andreipaciurca/aegis/main/scripts/install.sh | sh
aegis version
```

User-local macOS/Linux install:

```sh
curl -fsSL https://raw.githubusercontent.com/andreipaciurca/aegis/main/scripts/install.sh | sh -s -- --user
```

Windows PowerShell:

```powershell
iwr https://raw.githubusercontent.com/andreipaciurca/aegis/main/scripts/install.ps1 -UseB | iex
aegis version
```

Windows system-wide install:

```powershell
$p="$env:TEMP\aegis-install.ps1"
iwr https://raw.githubusercontent.com/andreipaciurca/aegis/main/scripts/install.ps1 -OutFile $p
powershell -ExecutionPolicy Bypass -File $p -System
```

The installer also updates an existing installation. It downloads the latest
GitHub release, verifies `SHA256SUMS`, installs `aegis` or `aegis.exe`, and
adds the install directory to PATH where appropriate.

Build from source. Requires Go 1.25.12 or a newer compatible toolchain:

```sh
git clone https://github.com/andreipaciurca/aegis
cd aegis
make build
./aegis version
```

## First Run

```sh
aegis app
```

That opens the TUI and the local browser GUI together. On startup, aegis checks
for fresh signatures, newer aegis releases and newer llama.cpp releases. It
reports what it finds; it does not silently replace itself.

For a quick safe scanner test:

```sh
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
aegis scan /tmp
```

On Windows, use a temporary folder such as `%TEMP%` and PowerShell's
`Set-Content` or download the EICAR test file from the official EICAR site.

## Daily Commands

```sh
aegis                     # TUI
aegis gui                 # local browser GUI on 127.0.0.1
aegis app                 # TUI + GUI paired together
aegis scan ~/Downloads    # headless scan; exit 1 when threats are found
aegis shield              # ransomware sweep
aegis audit               # persistence/autostart audit
aegis network             # live network connections and listeners
aegis firewall            # native firewall status and helper commands
aegis checkup             # OS/dependency/security-feed check
aegis update              # refresh signatures + check aegis/llama.cpp versions
aegis ai install          # one-command local llama.cpp + Gemma setup
aegis history             # quarantine history
aegis restore <id>        # decrypt quarantine to a review folder
```

Need every option, keyboard shortcut, diagram and AI setup path? Use the
[full user guide](docs/USER_GUIDE.md).

## Safety Model

aegis is privacy-first by default:

- normal scans do not upload files
- VirusTotal is opt-in and sends only the hash you provide
- local AI is optional and advisory
- remote AI requires explicit configuration
- quarantine encrypts files before removing originals
- restore refuses overwrites and defaults to a review folder

It is not a replacement for Defender, XProtect, Gatekeeper or a paid endpoint
security suite. Think of it as a fast, inspectable operator console that adds
useful checks and remediation helpers without living permanently in the kernel.

## Documentation

- [Full user guide](docs/USER_GUIDE.md): architecture, diagrams, commands,
  options, AI setup, update flow and performance notes.
- [Rules guide](docs/rules.md): custom YARA-lite rule schema and examples.
- [Trust page](docs/trust.html): checksums, signatures and false-positive
  guidance.
- [Release signing](docs/RELEASE_SIGNING.md): GPG, macOS and Windows signing.
- [Security policy](SECURITY.md): vulnerability reporting and trust boundaries.
- [Contributing](CONTRIBUTING.md): local dev setup and PR expectations.

## Contributing

Bug reports, rules, docs improvements and platform fixes are welcome. Please
keep the core design intact: no surprise daemons, no hidden cloud calls, no
kernel hooks, clear remediation commands and reproducible release artifacts.

Start with:

```sh
go test ./...
go vet ./...
go install honnef.co/go/tools/cmd/staticcheck@2026.1
"$(go env GOPATH)/bin/staticcheck" ./...
```

## License

aegis is open source under [GPL-3.0-or-later](LICENSE). In practical terms:
use it, study it, modify it, publish it and build on it, as long as
redistributed copies and modified versions remain open source under the same
license terms and keep attribution. See [NOTICE](NOTICE) for project credit and
inspiration notes.
