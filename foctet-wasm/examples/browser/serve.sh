#!/usr/bin/env bash
# Build the foctet-wasm web target and serve the in-browser harness.
# No Python required (uses a tiny Node static server).
#
# Usage: ./examples/browser/serve.sh [port]
#   FOCTET_OPEN=1 ./examples/browser/serve.sh   # also open the default browser
set -euo pipefail

# Resolve the foctet-wasm crate root (this script lives in examples/browser/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PORT="${1:-8011}"

cd "${CRATE_DIR}"

echo "Building pkg-web (wasm-pack)..."
wasm-pack build --target web --out-dir pkg-web

echo "Starting static server on port ${PORT}..."
exec node examples/browser/serve.mjs "${PORT}"
