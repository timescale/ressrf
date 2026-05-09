#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET="wasm32-wasip1"
OUT="$SCRIPT_DIR/core.wasm"

echo "Building ressrf-wasm for $TARGET..."
cargo build -p ressrf-wasm --target "$TARGET" --release \
  --manifest-path "$REPO_ROOT/Cargo.toml"

RAW="$REPO_ROOT/target/$TARGET/release/ressrf_wasm.wasm"

if command -v wasm-opt &>/dev/null; then
  echo "Optimizing with wasm-opt -Oz..."
  wasm-opt -Oz -o "${RAW%.wasm}.opt.wasm" "$RAW"
  RAW="${RAW%.wasm}.opt.wasm"
fi

if command -v wasm-tools &>/dev/null; then
  echo "Stripping debug sections..."
  wasm-tools strip "$RAW" -o "$OUT"
elif command -v wasm-strip &>/dev/null; then
  wasm-strip "$RAW" -o "$OUT"
else
  cp "$RAW" "$OUT"
fi

echo "Written $(wc -c < "$OUT" | tr -d ' ') bytes to $OUT"
