import { type AuditSink, parseWasmEvent } from "./audit.js";
import { RessrfBlockedError } from "./errors.js";
import { loadWasm, type LoadOptions, type WasmInstance } from "./wasm.js";

export type Preset = "external_only" | "internal_only" | "none";

/** A URL-level allow or deny matching rule. */
export interface UrlRule {
  /** Exact scheme match (e.g. "https"). Omit to match any scheme. */
  scheme?: string;
  /** Host glob pattern. `*` matches a single DNS label. */
  host?: string;
  /** Path glob pattern. `*` matches one segment, `**` matches any depth. */
  path?: string;
  /** Full regex matching the entire URL. When set, scheme/host/path are ignored. */
  regex?: string;
  /** When true on an allow rule, a matching URL skips the IP-level policy check. */
  bypassIpCheck?: boolean;
}

/** URL rules configuration. */
export interface UrlRulesConfig {
  allow?: UrlRule[];
  deny?: UrlRule[];
}

export interface PolicyOptions {
  preset: Preset;
  allowCidrs?: string[];
  denyCidrs?: string[];
  cloudProviders?: string[];
  urlRules?: UrlRulesConfig;
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

    const urlRulesWasm = options.urlRules
      ? {
          allow: (options.urlRules.allow ?? []).map(ruleToWasm),
          deny: (options.urlRules.deny ?? []).map(ruleToWasm),
        }
      : undefined;

    const config: Record<string, unknown> = {
      preset: options.preset,
      allow_cidrs: options.allowCidrs ?? [],
      deny_cidrs: options.denyCidrs ?? [],
      cloud_providers: options.cloudProviders ?? [],
    };
    if (urlRulesWasm) {
      config.url_rules = urlRulesWasm;
    }

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
  private urlAllowRules: UrlRule[] = [];
  private urlDenyRules: UrlRule[] = [];
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

  urlAllow(rule: UrlRule): this {
    this.urlAllowRules.push(rule);
    return this;
  }

  urlDeny(rule: UrlRule): this {
    this.urlDenyRules.push(rule);
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
    const urlRules: UrlRulesConfig | undefined =
      this.urlAllowRules.length > 0 || this.urlDenyRules.length > 0
        ? { allow: this.urlAllowRules, deny: this.urlDenyRules }
        : undefined;

    return Policy.create({
      preset: this.preset,
      allowCidrs: this.allowCidrs,
      denyCidrs: this.denyCidrs,
      cloudProviders: this.cloudProvidersList,
      urlRules,
      auditSink: this.sink,
      wasmPath: this.wasmPath,
    });
  }
}

function ruleToWasm(
  rule: UrlRule,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (rule.scheme) out.scheme = rule.scheme;
  if (rule.host) out.host = rule.host;
  if (rule.path) out.path = rule.path;
  if (rule.regex) out.regex = rule.regex;
  if (rule.bypassIpCheck) out.bypass_ip_check = true;
  return out;
}
