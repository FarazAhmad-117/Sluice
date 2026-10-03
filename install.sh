#!/bin/sh
# Installs the Sluice CLI on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/FarazAhmad-117/Sluice/HEAD/install.sh | sh
#
# Downloads the standalone `sluice` executable for this machine from the
# project's GitHub releases, checks it against the release's SHA256SUMS, and
# puts it in ~/.sluice/bin. It never edits your shell profile; it tells you the
# line to add if that directory is not on your PATH.
#
# Settings, all optional:
#   SLUICE_VERSION   a release such as 0.1.0 (default: the latest)
#   SLUICE_INSTALL   where to install (default: ~/.sluice); the binary goes in bin/
#   SLUICE_DOWNLOAD_BASE  a mirror of the release files (https:// or file://)
set -eu

REPO="FarazAhmad-117/Sluice"
INSTALL_DIR="${SLUICE_INSTALL:-$HOME/.sluice}"
BIN_DIR="$INSTALL_DIR/bin"

say() { printf 'sluice-install: %s\n' "$1"; }
fail() { printf 'sluice-install: error: %s\n' "$1" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *) fail "this script is for macOS and Linux. On Windows, use install.ps1 or winget." ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) fail "no build for $(uname -m). Install with npm instead: npm install -g @getsluice/cli" ;;
esac

if [ -n "${SLUICE_DOWNLOAD_BASE:-}" ]; then
  case "$SLUICE_DOWNLOAD_BASE" in
    https://* | file://*) base="${SLUICE_DOWNLOAD_BASE%/}" ;;
    *) fail "SLUICE_DOWNLOAD_BASE must start with https:// or file://" ;;
  esac
elif [ -n "${SLUICE_VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/cli-v${SLUICE_VERSION#v}"
else
  base="https://github.com/$REPO/releases/latest/download"
fi
archive="sluice-$os-$arch.tar.gz"

if command -v curl >/dev/null 2>&1; then
  # https only, or a local file:// mirror: never plain http.
  fetch() { curl -fsSL --proto '=https,file' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
else
  fail "needs curl or wget."
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "needs sha256sum or shasum to check the download."
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $archive"
fetch "$base/$archive" "$tmp/$archive" || fail "could not download $base/$archive"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download the release's SHA256SUMS"

expected="$(grep " $archive\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
[ -n "$expected" ] || fail "SHA256SUMS has no entry for $archive"
actual="$(sha256 "$tmp/$archive")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive; nothing was installed"

tar -xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$BIN_DIR"
mv "$tmp/sluice" "$BIN_DIR/sluice"
chmod 755 "$BIN_DIR/sluice"

say "installed $("$BIN_DIR/sluice" --version) to $BIN_DIR/sluice"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    case "${SHELL:-}" in
      */zsh) profile="~/.zshrc" ;;
      */bash) profile="~/.bashrc" ;;
      */fish) profile="~/.config/fish/config.fish" ;;
      *) profile="your shell profile" ;;
    esac
    say "add it to your PATH by putting this line in $profile, then open a new terminal:"
    if [ "$profile" = "~/.config/fish/config.fish" ]; then
      printf '\n  fish_add_path %s\n\n' "$BIN_DIR"
    else
      printf '\n  export PATH="%s:$PATH"\n\n' "$BIN_DIR"
    fi
    ;;
esac
say "next: create a token for this machine in the Sluice dashboard (Environments, then Connect)."
