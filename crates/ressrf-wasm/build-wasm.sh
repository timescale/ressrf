#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

TARGET="wasm32-wasip1"
PROFILE="${1:-release}"

echo "Building ressrf-wasm for $TARGET ($PROFILE)..."
cargo build -p ressrf-wasm --target "$TARGET" --profile "$PROFILE"

WASM_FILE="$WORKSPACE_ROOT/target/$TARGET/$PROFILE/ressrf_wasm.wasm"

if [ ! -f "$WASM_FILE" ]; then
    echo "ERROR: WASM file not found at $WASM_FILE"
    exit 1
fi

echo "Built: $WASM_FILE ($(wc -c < "$WASM_FILE" | tr -d ' ') bytes)"

# Optional: optimize with wasm-opt if available
if command -v wasm-opt &>/dev/null; then
    OPT_FILE="${WASM_FILE%.wasm}.opt.wasm"
    echo "Optimizing with wasm-opt..."
    wasm-opt -Os --strip-debug "$WASM_FILE" -o "$OPT_FILE"
    echo "Optimized: $OPT_FILE ($(wc -c < "$OPT_FILE" | tr -d ' ') bytes)"
else
    echo "Note: install wasm-opt (binaryen) for size optimization"
fi
