# Release Signing

This guide keeps aegis releases verifiable and easier to clear with antivirus
vendors.

## Table of Contents

- [Automatic GitHub Releases](#automatic-github-releases)
- [Local Build Artifacts](#local-build-artifacts)
- [Sign Checksums](#sign-checksums)
- [macOS Code Signing](#macos-code-signing)
- [Windows Authenticode Signing](#windows-authenticode-signing)
- [Linux](#linux)
- [Antivirus False-Positive Packet](#antivirus-false-positive-packet)

## Automatic GitHub Releases

The normal release path is GitHub Actions driven:

1. Open GitHub Actions.
2. Select the `Release` workflow.
3. Run it manually and choose `patch`, `minor` or `major`.

The workflow computes the next semantic version tag, creates it, builds macOS,
Linux and Windows archives, generates `SHA256SUMS`, verifies them, and publishes
a GitHub Release.

You can also push an exact semantic version tag yourself:

```sh
git checkout main
git pull
git tag -a v1.6.0 -m "aegis v1.6.0"
git push origin v1.6.0
```

The release workflow uploads:

```text
aegis-1.6.0-darwin-arm64.tar.gz
aegis-1.6.0-darwin-amd64.tar.gz
aegis-1.6.0-linux-amd64.tar.gz
aegis-1.6.0-linux-arm64.tar.gz
aegis-1.6.0-windows-amd64.zip
SHA256SUMS
```

Each platform archive includes the executable plus `README.md`, `SECURITY.md`
and `LICENSE`.

You can also run the `Release` workflow manually from GitHub Actions and pass an
existing tag such as `v1.6.0`.

## Local Build Artifacts

```sh
make clean
make checksums
```

`make checksums` builds the raw binaries, packages public archives, and writes
`dist/SHA256SUMS` for every downloadable archive.

Verify locally:

```sh
make verify-release
```

## Sign Checksums

Use a maintainer-controlled GPG key:

```sh
GPG_KEY="KEYID_OR_EMAIL" make sign-checksums
```

This creates:

```text
dist/SHA256SUMS
dist/SHA256SUMS.asc
```

## macOS Code Signing

Requirements:

- Apple Developer Program membership
- Developer ID Application certificate installed in Keychain
- `codesign` available

```sh
make release
CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" make sign-darwin
make checksums
```

For distribution outside the App Store, notarize the signed binaries or archives:

```sh
xcrun notarytool submit dist/aegis-1.6.0-darwin-arm64.zip \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD" \
  --wait
```

Staple notarization tickets when distributing archives or app bundles that
support stapling.

## Windows Authenticode Signing

Requirements:

- OV or EV code-signing certificate
- Windows SDK `signtool.exe`

```powershell
$env:SIGNTOOL="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
$env:WINDOWS_CERT_SHA1="CERTIFICATE_THUMBPRINT"
make sign-windows
make checksums
```

EV certificates usually build reputation faster, but OV signing plus consistent
release history is still useful.

## Linux

Linux binaries usually rely on checksum and detached-signature verification:

```sh
gpg --verify dist/SHA256SUMS.asc dist/SHA256SUMS
cd dist && shasum -a 256 -c SHA256SUMS
```

Package maintainers may also sign distro-native packages.

## Antivirus False-Positive Packet

When a vendor flags a release, submit:

- binary file and SHA-256
- `SHA256SUMS` and `SHA256SUMS.asc`
- source repository URL: https://github.com/andreipaciurca/aegis
- official website: https://andreipaciurca.github.io/aegis/
- trust page: https://andreipaciurca.github.io/aegis/trust.html
- release tag URL, when using a tagged release artifact
- build command
- short product description
- explanation of sensitive behavior:
  - scans files and hashes them
  - contains detection strings for known malware behavior
  - can quarantine selected files
  - can terminate selected processes with confirmation
  - can call native firewall tools

Avoid packing binaries with UPX or similar compressors; packed security tools
are more likely to trigger heuristic detections.
