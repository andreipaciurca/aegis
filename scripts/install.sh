#!/usr/bin/env sh
set -eu

repo="${AEGIS_REPO:-andreipaciurca/aegis}"
version="${AEGIS_VERSION:-latest}"
prefix="${PREFIX:-/usr/local}"
bin_dir=""
scope="system"
target_explicit=0

usage() {
  cat <<'USAGE'
Install or update aegis from the latest GitHub release.

Usage:
  scripts/install.sh [--version v1.2.3] [--prefix /usr/local] [--bin-dir DIR] [--user]

Environment:
  AEGIS_REPO       GitHub repo, default andreipaciurca/aegis
  AEGIS_VERSION    Release tag, default latest
  PREFIX           Install prefix, default /usr/local

Examples:
  curl -fsSL https://raw.githubusercontent.com/andreipaciurca/aegis/main/scripts/install.sh | sh
  sh scripts/install.sh --user
  sudo sh scripts/install.sh --prefix /usr/local

If aegis is already on PATH and no target is provided, the installer updates
that existing binary. Otherwise it installs to /usr/local/bin, or ~/.local/bin
with --user.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --prefix)
      prefix="${2:-}"
      target_explicit=1
      shift 2
      ;;
    --bin-dir)
      bin_dir="${2:-}"
      target_explicit=1
      shift 2
      ;;
    --user)
      scope="user"
      prefix="${HOME}/.local"
      target_explicit=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "install.sh: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "install.sh: missing required command: $1" >&2
    exit 1
  fi
}

fetch() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    echo "install.sh: need curl or wget" >&2
    exit 1
  fi
}

need tar
need sed
need awk
need uname

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  darwin) os="darwin" ;;
  linux) os="linux" ;;
  *)
    echo "install.sh: unsupported OS: $os" >&2
    exit 1
    ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "install.sh: unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

tmp="${TMPDIR:-/tmp}/aegis-install.$$"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ "$version" = "latest" ]; then
  latest_json="$tmp/latest.json"
  fetch "https://api.github.com/repos/${repo}/releases/latest" "$latest_json"
  version="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$latest_json" | head -1)"
  if [ -z "$version" ]; then
    echo "install.sh: could not determine latest release for ${repo}" >&2
    exit 1
  fi
fi

plain_version="${version#v}"
archive="aegis-${plain_version}-${os}-${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${version}"

if [ -z "$bin_dir" ]; then
  if [ "$target_explicit" -eq 0 ] && command -v aegis >/dev/null 2>&1; then
    existing_cmd="$(command -v aegis)"
    bin_dir="$(dirname "$existing_cmd")"
  else
    bin_dir="${prefix}/bin"
  fi
fi

target="${bin_dir}/aegis"
current_version=""
if [ -x "$target" ]; then
  current_version="$("$target" version 2>/dev/null | awk 'NR == 1 {print $2}')"
fi

if [ -n "$current_version" ]; then
  if [ "$current_version" = "$plain_version" ]; then
    echo "Reinstalling aegis ${version} for ${os}/${arch} at ${target}"
  else
    echo "Updating aegis ${current_version} -> ${version} for ${os}/${arch} at ${target}"
  fi
else
  echo "Installing aegis ${version} for ${os}/${arch} at ${target}"
fi

fetch "${base_url}/${archive}" "$tmp/$archive"
fetch "${base_url}/SHA256SUMS" "$tmp/SHA256SUMS"

if command -v shasum >/dev/null 2>&1; then
  (cd "$tmp" && grep "  ${archive}\$" SHA256SUMS | shasum -a 256 -c -)
elif command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && grep "  ${archive}\$" SHA256SUMS | sha256sum -c -)
else
  echo "install.sh: warning: no shasum or sha256sum found; skipping checksum verification" >&2
fi

tar -xzf "$tmp/$archive" -C "$tmp"
src="$tmp/aegis-${plain_version}-${os}-${arch}/aegis"

mkdir_install() {
  mkdir -p "$bin_dir"
  install -m 0755 "$src" "$target"
}

if [ "$scope" = "user" ]; then
  mkdir_install
else
  if [ -w "$bin_dir" ] || { [ ! -e "$bin_dir" ] && [ -w "$(dirname "$bin_dir")" ]; }; then
    mkdir_install
  elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$bin_dir"
    sudo install -m 0755 "$src" "$target"
  else
    echo "install.sh: ${bin_dir} is not writable and sudo is unavailable" >&2
    echo "Try: sh scripts/install.sh --user" >&2
    exit 1
  fi
fi

echo "aegis ready at ${target}"
if ! command -v aegis >/dev/null 2>&1; then
  echo "Add ${bin_dir} to PATH, then run: aegis version"
else
  aegis version || true
fi
