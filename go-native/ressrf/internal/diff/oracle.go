//go:build diffuzz

// Package diff hosts the differential-fuzz harness that compares the
// native Go engine against the Rust ressrf-core compiled to WASM. It
// only builds under the `diffuzz` build tag so that wazero and the
// .wasm artifact are not required for normal `go test` runs.
//
// The oracle WASM is the sibling wazero binding's checked-in artifact
// at <repo-root>/go/ressrf/core.wasm. The default resolves to that
// file via runtime.Caller so the harness is CWD-independent;
// override with RESSRF_WASM_PATH if a custom build is needed.
package diff

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const handleInvalid uint32 = 0xFFFFFFFF

// Oracle wraps a loaded ressrf-wasm module. One Oracle owns one wazero
// Runtime + CompiledModule; instantiation per call keeps the harness simple
// at the cost of ~200µs per fuzz iteration (acceptable for fuzz throughput).
type Oracle struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	cfgJSON  []byte
}

// PolicyConfig mirrors the JSON shape that ressrf-wasm's ressrf_policy_new
// expects (see crates/ressrf-wasm/src/lib.rs::PolicyConfig).
type PolicyConfig struct {
	Preset         string   `json:"preset"`
	AllowCIDRs     []string `json:"allow_cidrs,omitempty"`
	DenyCIDRs      []string `json:"deny_cidrs,omitempty"`
	CloudProviders []string `json:"cloud_providers,omitempty"`
}

// NewOracle compiles the WASM module once. The returned Oracle is safe for
// concurrent use: each Decide call instantiates its own short-lived module.
func NewOracle(ctx context.Context, cfg PolicyConfig) (*Oracle, error) {
	wasmBytes, err := os.ReadFile(wasmPath())
	if err != nil {
		return nil, fmt.Errorf("read wasm: %w", err)
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	runtime := wazero.NewRuntime(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate wasi: %w", err)
	}

	// The Rust crate imports ressrf_host_audit_event but only calls it when
	// audit is enabled (we never call ressrf_policy_set_audit_callback).
	// Wazero still requires the import to resolve at instantiation time.
	_, err = runtime.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func(context.Context, uint32, uint32) {}).
		Export("ressrf_host_audit_event").
		Instantiate(ctx)
	if err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate audit host module: %w", err)
	}

	compiled, err := runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("compile wasm: %w", err)
	}

	return &Oracle{runtime: runtime, compiled: compiled, cfgJSON: cfgJSON}, nil
}

// Close releases the wazero runtime and compiled module.
func (o *Oracle) Close(ctx context.Context) error {
	return o.runtime.Close(ctx)
}

// Decide returns whether the upstream Rust engine permits the given URL
// under the oracle's policy config. error is non-nil only for harness-level
// failures (cannot instantiate, etc.), not policy denials.
func (o *Oracle) Decide(ctx context.Context, url string) (allowed bool, err error) {
	mod, err := o.runtime.InstantiateModule(ctx, o.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return false, fmt.Errorf("instantiate module: %w", err)
	}
	defer mod.Close(ctx)

	alloc := mod.ExportedFunction("ressrf_alloc")
	dealloc := mod.ExportedFunction("ressrf_dealloc")
	policyNew := mod.ExportedFunction("ressrf_policy_new")
	policyFree := mod.ExportedFunction("ressrf_policy_free")
	isRequestAllowed := mod.ExportedFunction("ressrf_policy_is_request_allowed")
	if alloc == nil || dealloc == nil || policyNew == nil || policyFree == nil || isRequestAllowed == nil {
		return false, errors.New("oracle: wasm module is missing a required export")
	}

	cfgPtr, err := writeBytes(ctx, mod, alloc, o.cfgJSON)
	if err != nil {
		return false, err
	}
	handleResults, err := policyNew.Call(ctx, cfgPtr, uint64(len(o.cfgJSON)))
	if err != nil {
		return false, fmt.Errorf("ressrf_policy_new: %w", err)
	}
	handle := uint32(handleResults[0])
	if handle == handleInvalid {
		return false, errors.New("ressrf_policy_new returned u32::MAX (invalid config)")
	}
	defer func() { _, _ = policyFree.Call(ctx, uint64(handle)) }()

	reqJSON, err := json.Marshal(struct {
		URL string `json:"url"`
	}{URL: url})
	if err != nil {
		return false, fmt.Errorf("marshal request: %w", err)
	}
	reqPtr, err := writeBytes(ctx, mod, alloc, reqJSON)
	if err != nil {
		return false, err
	}

	resultResults, err := isRequestAllowed.Call(ctx, uint64(handle), reqPtr, uint64(len(reqJSON)))
	if err != nil {
		return false, fmt.Errorf("ressrf_policy_is_request_allowed: %w", err)
	}
	resultPtr := uint32(resultResults[0])
	resultBytes, totalLen, err := readLengthPrefixed(mod, resultPtr)
	if err != nil {
		return false, err
	}
	defer func() { _, _ = dealloc.Call(ctx, uint64(resultPtr), uint64(totalLen)) }()

	var result struct {
		Allowed bool   `json:"allowed"`
		Error   string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return false, fmt.Errorf("decode result: %w", err)
	}
	return result.Allowed, nil
}

func writeBytes(ctx context.Context, mod api.Module, alloc api.Function, b []byte) (uint64, error) {
	results, err := alloc.Call(ctx, uint64(len(b)))
	if err != nil {
		return 0, fmt.Errorf("ressrf_alloc: %w", err)
	}
	ptr := uint32(results[0])
	if ptr == 0 && len(b) > 0 {
		return 0, errors.New("ressrf_alloc returned null")
	}
	if !mod.Memory().Write(ptr, b) {
		return 0, errors.New("memory write out of range")
	}
	return uint64(ptr), nil
}

func readLengthPrefixed(mod api.Module, ptr uint32) ([]byte, uint32, error) {
	lenBytes, ok := mod.Memory().Read(ptr, 4)
	if !ok {
		return nil, 0, errors.New("result length read out of range")
	}
	jsonLen := binary.LittleEndian.Uint32(lenBytes)
	jsonBytes, ok := mod.Memory().Read(ptr+4, jsonLen)
	if !ok {
		return nil, 0, errors.New("result body read out of range")
	}
	out := make([]byte, jsonLen)
	copy(out, jsonBytes)
	return out, jsonLen + 4, nil
}

func wasmPath() string {
	if p := os.Getenv("RESSRF_WASM_PATH"); p != "" {
		return p
	}
	// here = <repo-root>/go-native/ressrf/internal/diff/oracle.go; the
	// sibling wazero binding lives at <repo-root>/go/ressrf/core.wasm.
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "..", "..", "go", "ressrf", "core.wasm")
	}
	return filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "go", "ressrf", "core.wasm")
}
