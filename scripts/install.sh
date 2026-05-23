#!/usr/bin/env bash
# secrevo CLI installer for Linux / macOS.
#
# Usage:
#   curl -fsSL https://github.com/getsecrevo/cli/releases/latest/download/install.sh | bash
#
# Env overrides:
#   SECREVO_VERSION  - install a specific tag (default: latest)
#   SECREVO_INSTALL_DIR - target directory (default: $HOME/.local/bin)
#   SECREVO_BIN_NAME - rename the binary (default: secrevo)
set -euo pipefail

REPO="getsecrevo/cli"
VERSION="${SECREVO_VERSION:-latest}"
INSTALL_DIR="${SECREVO_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="${SECREVO_BIN_NAME:-secrevo}"

log()  { printf '\033[34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m==>\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m==>\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}
need curl
need tar
need uname

OS=""
case "$(uname -s)" in
  Linux)  OS=linux  ;;
  Darwin) OS=macos  ;;
  *) fail "unsupported OS: $(uname -s) — use install.ps1 on Windows" ;;
esac

ARCH=""
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "unsupported arch: $(uname -m)" ;;
esac

if [[ "$VERSION" == "latest" ]]; then
  log "resolving latest release for $REPO"
  VERSION=$(curl -fsSL -H 'Accept: application/json' \
    "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [[ -n "$VERSION" ]] || fail "could not resolve latest tag (rate-limited? set SECREVO_VERSION=vX.Y.Z)"
fi

VERSION_NO_V="${VERSION#v}"
ASSET="secrevo_${VERSION_NO_V}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
SUMS_URL="https://github.com/$REPO/releases/download/$VERSION/checksums.txt"

log "installing secrevo $VERSION ($OS/$ARCH) → $INSTALL_DIR/$BIN_NAME"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL --retry 3 -o "$TMP/$ASSET"        "$URL"        || fail "download failed: $URL"
curl -fsSL --retry 3 -o "$TMP/checksums.txt" "$SUMS_URL"   || fail "checksum download failed: $SUMS_URL"

# Verify sha256 — release ships a checksums.txt with `<sha>  <asset-name>` lines.
WANT=$(grep " $ASSET\$" "$TMP/checksums.txt" | awk '{print $1}')
[[ -n "$WANT" ]] || fail "checksums.txt has no entry for $ASSET"
if command -v shasum >/dev/null 2>&1; then
  GOT=$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  GOT=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
else
  fail "no sha256 tool found (install shasum or sha256sum)"
fi
[[ "$WANT" == "$GOT" ]] || fail "sha256 mismatch: want $WANT got $GOT"
log "sha256 verified"

tar -xzf "$TMP/$ASSET" -C "$TMP"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP/secrevo" "$INSTALL_DIR/$BIN_NAME"

log "installed: $INSTALL_DIR/$BIN_NAME"
"$INSTALL_DIR/$BIN_NAME" version

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    warn "$INSTALL_DIR is not in your PATH"
    warn "add this to ~/.bashrc, ~/.zshrc or ~/.profile:"
    warn "  export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac
