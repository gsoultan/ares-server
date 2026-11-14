#!/usr/bin/env bash
# One-time local setup: install the proto toolchain, the web dependencies, then
# regenerate the bindings. Safe to re-run — each step is idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GOBIN="$(go env GOBIN)"; [ -n "$GOBIN" ] || GOBIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GOBIN"

# buf version used to compile the contract. Override with BUF_VERSION=... if you
# need a different one; the committed generated code is the source of truth.
BUF_VERSION="${BUF_VERSION:-v1.75.0}"

install_go_tool() { # name module@version
  local name="$1" mod="$2"
  if command -v "$name" >/dev/null 2>&1; then
    echo "  $name already installed ($(command -v "$name"))"
  else
    echo "  installing $name ($mod)"
    go install "$mod"
  fi
}

echo "==> Go proto toolchain (into $GOBIN)"
install_go_tool buf "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"
install_go_tool protoc-gen-go "google.golang.org/protobuf/cmd/protoc-gen-go@latest"
install_go_tool protoc-gen-connect-go "connectrpc.com/connect/cmd/protoc-gen-connect-go@latest"

echo "==> Go module download"
go mod download

echo "==> Web dependencies (bun)"
if ! command -v bun >/dev/null 2>&1; then
  echo "bun not found. Install it from https://bun.sh and re-run." >&2
  exit 1
fi
( cd web && bun install )

echo "==> Regenerate bindings"
"$ROOT/scripts/gen.sh"

echo
echo "Setup complete. Start the stack with: scripts/dev.sh"
