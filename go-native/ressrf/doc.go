// Package ressrf provides SSRF protection via a native Go engine that
// mirrors the Rust ressrf-core semantics, cross-validated against the
// shared JSON conformance vectors at tests/vectors/ and pinned to the
// Rust core via a differential-fuzz harness that compares every random
// URL against the WASM oracle (sibling go/ressrf/ binding).
//
// No WASM runtime, no embedded .wasm, no Rust toolchain in the build
// pipeline. See the package README for the consumer-facing API and the
// docs/how-it-works.md walkthrough for an end-to-end pipeline tour.
package ressrf
