#!/usr/bin/env bash
# Regenerate the gRPC / Connect bindings from proto/ into the committed
# generated trees: Go in internal/gen, TypeScript in web/src/gen. Run this after
# editing proto/ares/v1/ares.proto.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# buf and the Go codegen plugins install under the Go bin dir (GOBIN, else
# GOPATH/bin) — put it on PATH so a fresh `scripts/setup.sh` install is found.
GOBIN_DIR="$(go env GOBIN)"; [ -n "$GOBIN_DIR" ] || GOBIN_DIR="$(go env GOPATH)/bin"
export PATH="$PATH:$GOBIN_DIR"

if ! command -v buf >/dev/null 2>&1; then
  echo "buf not found on PATH. Run scripts/setup.sh first." >&2
  exit 1
fi
if [ ! -x web/node_modules/.bin/protoc-gen-es ]; then
  echo "protoc-gen-es missing (web deps not installed). Run scripts/setup.sh first." >&2
  exit 1
fi

echo "==> Go bindings     -> internal/gen"
buf generate

echo "==> TypeScript client -> web/src/gen"
buf generate --template web/buf.gen.web.yaml

echo "Generated."
