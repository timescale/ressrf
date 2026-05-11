package ressrf

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:generate bash build_wasm.sh

//go:embed core.wasm
var coreWasm []byte

var wasmRuntimeConfig = wazero.NewRuntimeConfig().
	WithCompilationCache(wazero.NewCompilationCache())

// instance wraps a single WASM module instance with its own runtime and memory.
type instance struct {
	rt             wazero.Runtime
	mod            api.Module
	alloc          api.Function
	dealloc        api.Function
	create         api.Function
	allowed        api.Function
	networkAllowed api.Function
	setAudit       api.Function
	auditSink      AuditSink
	mu             sync.Mutex
}

func newInstance(ctx context.Context, sink AuditSink) (*instance, error) {
	inst := &instance{auditSink: sink}

	rt := wazero.NewRuntimeWithConfig(ctx, wasmRuntimeConfig)
	inst.rt = rt

	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	hostBuilder := rt.NewHostModuleBuilder("env")
	hostBuilder.NewFunctionBuilder().
		WithFunc(inst.hostAuditEvent).
		Export("ressrf_host_audit_event")

	if _, err := hostBuilder.Instantiate(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("ressrf: instantiate host: %w", err)
	}

	compiled, err := rt.CompileModule(ctx, coreWasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("ressrf: compile wasm: %w", err)
	}

	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("ressrf: instantiate module: %w", err)
	}
	inst.mod = mod

	inst.alloc = mod.ExportedFunction("ressrf_alloc")
	inst.dealloc = mod.ExportedFunction("ressrf_dealloc")
	inst.create = mod.ExportedFunction("ressrf_policy_new")
	inst.allowed = mod.ExportedFunction("ressrf_policy_is_request_allowed")
	inst.networkAllowed = mod.ExportedFunction("ressrf_policy_is_network_allowed")
	inst.setAudit = mod.ExportedFunction("ressrf_policy_set_audit_callback")

	if inst.alloc == nil || inst.dealloc == nil || inst.create == nil || inst.allowed == nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("ressrf: missing required exports from wasm module")
	}

	if sink != nil && inst.setAudit != nil {
		if _, err := inst.setAudit.Call(ctx, 1); err != nil {
			_ = rt.Close(ctx)
			return nil, fmt.Errorf("ressrf: enable audit: %w", err)
		}
	}

	return inst, nil
}

func (inst *instance) hostAuditEvent(ctx context.Context, m api.Module, ptr, length uint32) {
	if inst.auditSink == nil {
		return
	}
	data, ok := m.Memory().Read(ptr, length)
	if !ok {
		return
	}
	var event AuditEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return
	}
	inst.auditSink.Emit(ctx, &event)
}

func (inst *instance) writeBytes(ctx context.Context, data []byte) (uint32, error) {
	size := uint32(len(data))
	results, err := inst.alloc.Call(ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("ressrf: alloc(%d): %w", size, err)
	}
	ptr := uint32(results[0])
	if ptr == 0 {
		return 0, fmt.Errorf("ressrf: alloc returned null for size %d", size)
	}
	if !inst.mod.Memory().Write(ptr, data) {
		return 0, fmt.Errorf("ressrf: memory write failed at ptr=%d len=%d", ptr, size)
	}
	return ptr, nil
}

func (inst *instance) readResult(ctx context.Context, ptr uint32) ([]byte, error) {
	lenBytes, ok := inst.mod.Memory().Read(ptr, 4)
	if !ok {
		return nil, fmt.Errorf("ressrf: cannot read result length at ptr=%d", ptr)
	}
	length := binary.LittleEndian.Uint32(lenBytes)
	data, ok := inst.mod.Memory().Read(ptr+4, length)
	if !ok {
		return nil, fmt.Errorf("ressrf: cannot read result body at ptr=%d len=%d", ptr+4, length)
	}
	result := make([]byte, length)
	copy(result, data)

	totalSize := uint64(4 + length)
	if _, err := inst.dealloc.Call(ctx, uint64(ptr), totalSize); err != nil {
		return nil, fmt.Errorf("ressrf: dealloc: %w", err)
	}
	return result, nil
}

func (inst *instance) close(ctx context.Context) error {
	if inst.rt != nil {
		return inst.rt.Close(ctx)
	}
	return nil
}
