# Security Policy

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [False Positives](#false-positives)
- [Trust Boundaries](#trust-boundaries)
- [Release Integrity](#release-integrity)

## Supported Versions

Security fixes are applied to the latest `main` branch and the latest published
release. If you package aegis downstream, rebuild from the latest tag before
reporting an issue.

## Reporting a Vulnerability

Please do not open a public issue for exploitable vulnerabilities.

Email the maintainer with:

- affected version or commit
- operating system and architecture
- reproduction steps
- expected impact
- any proof of concept, kept minimal and non-destructive

If email is unavailable, open a public issue that asks for a private contact
channel and avoid including exploit details.

## False Positives

aegis is a defensive security tool, so antivirus products may flag it because it
contains detection strings, malware-family names, quarantine logic, process
termination code, firewall commands, and vulnerability intelligence fetchers.

When submitting a false positive to an antivirus vendor, include:

- project URL: https://github.com/andreipaciurca/aegis
- official website: https://andreipaciurca.github.io/aegis/
- release URL, when using a tagged release artifact
- binary SHA-256
- signed `SHA256SUMS` file when available
- operating system and architecture
- exact vendor detection name
- short explanation that aegis is an open-source defensive scanner/TUI

## Trust Boundaries

aegis does not install a daemon, kernel extension, browser extension, login item,
or background service. It runs when invoked and exits when closed.

Potentially sensitive actions are explicit:

- quarantine moves a selected file into the aegis config directory and records a
  JSON audit log
- process termination requires user confirmation in the TUI
- firewall changes call native OS tools and report privilege requirements
- local AI analysis is optional and uses local llama.cpp backends only
- `aegis intel <hash>` is an explicit VirusTotal OSINT lookup; it sends only
  the MD5/SHA-1/SHA-256 hash you provide and requires your own API key
- `aegis clamav <path>` is explicit and sends file bytes only to the `clamd`
  address you choose; keep `clamd` bound to localhost or a trusted Unix socket
  unless you intentionally operate a private scanning service

Normal `scan`, `update`, `shield`, `audit`, `status`, TUI and GUI dashboard
views do not upload files to external reputation services.

## Release Integrity

Official releases should include:

- platform binaries
- `SHA256SUMS`
- detached signature for `SHA256SUMS`, when a signing key is available
- code-signed macOS/Windows binaries, when platform certificates are available

See [docs/RELEASE_SIGNING.md](docs/RELEASE_SIGNING.md).
