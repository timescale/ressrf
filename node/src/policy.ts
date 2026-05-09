import { type AuditSink, parseWasmEvent } from "./audit.js";
import { RessrfBlockedError } from "./errors.js";
import { loadWasm, type LoadOptions, type WasmInstance } from "./wasm.js";

export type Preset = "external_only" | "internal_only" | "none";

export interface PolicyOptions {
  preset: Preset;
  allowCidrs?: string[];
  denyCidrs?: string[];
  cloudProviders?: string[];
  auditSink?: AuditSink;
  wasmPath?: string;
}

export class Policy {
  private wasm: WasmInstance;
  private handle: number;
  private sink?: AuditSink;

  private constructor(wasm: WasmInstance, handle: number, sink?: AuditSink) {
    this.wasm = wasm;
    this.handle = handle;
    this.sink = sink;
  }

  static async create(options: PolicyOptions): Promise<Policy> {
    const auditCallback = options.auditSink
      ? (raw: Record<string, unknown>) => {
          const event = parseWasmEvent(raw);
          options.auditSink!.emit(event);
        }
      : undefined;

    const loadOpts: LoadOptions = {
      wasmPath: options.wasmPath,
      auditCallback,
    };

    const wasm = await loadWasm(loadOpts);

    if (options.auditSink) {
      wasm.setAuditCallback(true);
    }

    const config = {
      preset: options.preset,
      allow_cidrs: options.allowCidrs ?? [],
      deny_cidrs: options.denyCidrs ?? [],
      cloud_providers: options.cloudProviders ?? [],
    };

    const { ptr, len } = wasm.writeJSON(config);
    const handle = wasm.policyNew(ptr, len);

    if (handle === 0xffffffff || handle === -1) {
      throw new Error("ressrf: failed to create policy (invalid config)");
    }

    return new Policy(wasm, handle, options.auditSink);
  }

  static async externalOnly(
    options?: Omit<PolicyOptions, "preset"> & { cloud?: string[] },
  ): Promise<Policy> {
    const { cloud, ...rest } = options ?? {};
    return Policy.create({
      ...rest,
      preset: "external_only",
      cloudProviders: cloud ?? rest.cloudProviders,
    });
  }

  static async internalOnly(
    options?: Omit<PolicyOptions, "preset"> & { cloud?: string[] },
  ): Promise<Policy> {
    const { cloud, ...rest } = options ?? {};
    return Policy.create({
      ...rest,
      preset: "internal_only",
      cloudProviders: cloud ?? rest.cloudProviders,
    });
  }

  isAllowed(url: string): void {
    const { ptr, len } = this.wasm.writeJSON({ url });
    const resultPtr = this.wasm.policyIsRequestAllowed(this.handle, ptr, len);
    const result = this.wasm.readResult(resultPtr);

    if (!result.allowed) {
      throw new RessrfBlockedError(result.error ?? "blocked", url);
    }
  }

  isNetworkAllowed(ips: string[]): void {
    const { ptr, len } = this.wasm.writeJSON({ ips });
    const resultPtr = this.wasm.policyIsNetworkAllowed(this.handle, ptr, len);
    const result = this.wasm.readResult(resultPtr);

    if (!result.allowed) {
      throw new RessrfBlockedError(result.error ?? "blocked");
    }
  }

  close(): void {
    this.wasm.policyFree(this.handle);
  }
}

export class PolicyBuilder {
  private preset: Preset = "none";
  private allowCidrs: string[] = [];
  private denyCidrs: string[] = [];
  private cloudProvidersList: string[] = [];
  private sink?: AuditSink;
  private wasmPath?: string;

  constructor(preset: Preset) {
    this.preset = preset;
  }

  addAllowed(...cidrs: string[]): this {
    this.allowCidrs.push(...cidrs);
    return this;
  }

  addDenied(...cidrs: string[]): this {
    this.denyCidrs.push(...cidrs);
    return this;
  }

  addCloud(...providers: string[]): this {
    this.cloudProvidersList.push(...providers);
    return this;
  }

  auditSink(sink: AuditSink): this {
    this.sink = sink;
    return this;
  }

  wasmFile(path: string): this {
    this.wasmPath = path;
    return this;
  }

  async build(): Promise<Policy> {
    return Policy.create({
      preset: this.preset,
      allowCidrs: this.allowCidrs,
      denyCidrs: this.denyCidrs,
      cloudProviders: this.cloudProvidersList,
      auditSink: this.sink,
      wasmPath: this.wasmPath,
    });
  }
}
