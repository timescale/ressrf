# ressrf (Node.js)

Node.js/TypeScript SSRF prevention library powered by the `ressrf-core` engine running as WebAssembly. Zero runtime dependencies. ESM-only (`"type": "module"`).

## Installation

```bash
npm install ressrf
```

Requires Node.js 20+. Optional peer dependencies for protocol adapters:

- `undici` (>=8.2.0) for `undiciConnect`
- `ssh2` (>=1.17.0) for `safeSshConnect`

## Public API

### Policy

| Method | Description |
|--------|-------------|
| `Policy.create(options: PolicyOptions)` | Create a policy from full options |
| `Policy.externalOnly(options?)` | Default deny for private/internal ranges |
| `Policy.internalOnly(options?)` | Default deny all; only allow-listed CIDRs pass |
| `policy.isAllowed(url: string)` | Validate URL (scheme + host + IP). Throws `RessrfBlockedError` if denied |
| `policy.isNetworkAllowed(ips: string[])` | Validate IPs. Throws `RessrfBlockedError` if any IP is denied |
| `policy.close()` | Release WASM resources |

### PolicyOptions

```typescript
interface PolicyOptions {
  preset: "external_only" | "internal_only" | "none";
  allowCidrs?: string[];
  denyCidrs?: string[];
  cloudProviders?: string[];
  auditSink?: AuditSink;
  wasmPath?: string;
}
```

The `externalOnly` and `internalOnly` factory methods also accept a `cloud?: string[]` shorthand for `cloudProviders`.

### PolicyBuilder

| Method | Description |
|--------|-------------|
| `new PolicyBuilder(preset)` | Create a builder with a preset |
| `.addAllowed(...cidrs: string[])` | Add CIDRs to the allow list (overrides deny) |
| `.addDenied(...cidrs: string[])` | Add CIDRs to the deny list |
| `.addCloud(provider: string)` | Add a cloud provider (`"aws"`, `"azure"`, `"gcp"`) |
| `.urlAllow(rule: UrlRule)` | Add a URL allow rule (glob/regex pattern) |
| `.urlDeny(rule: UrlRule)` | Add a URL deny rule (glob/regex pattern) |
| `.auditSink(sink: AuditSink)` | Attach an audit sink |
| `.wasmFile(path: string)` | Use a custom WASM file path |
| `.build(): Promise<Policy>` | Compile and return the policy |

```typescript
import { PolicyBuilder } from "ressrf";

const policy = await new PolicyBuilder("external_only")
  .addAllowed("10.42.0.0/16")
  .addDenied("192.0.2.0/24")
  .addCloud("aws")
  .addCloud("azure")
  .addCloud("gcp")
  .build();
```

## Protocol Adapters

### HTTP

#### `httpAgent` / `httpsAgent`

Creates `http.Agent` / `https.Agent` instances that validate DNS lookups against the policy before establishing connections.

```typescript
import http from "node:http";
import https from "node:https";
import { Policy } from "ressrf";
import { httpAgent, httpsAgent } from "ressrf/protocols/http";

const policy = await Policy.externalOnly({ cloud: ["aws"] });

// Use with http.request / http.get
const agent = httpAgent(policy);
http.get("http://api.example.com/data", { agent }, (res) => {
  // DNS was validated before connecting
});

// HTTPS variant
const secureAgent = httpsAgent(policy, { rejectUnauthorized: true });
```

#### `safeFetch`

Fetch wrapper that validates the initial URL and each redirect hop. Uses `redirect: "manual"` internally and follows redirects up to a configurable limit. DNS resolution is pre-validated on each hop.

```typescript
import { safeFetch } from "ressrf/protocols/http";

const response = await safeFetch("https://api.example.com/data", {
  policy,
  maxRedirects: 10,
  headers: { Authorization: "Bearer ..." },
});
```

Protection layers:
1. Initial URL validated via `policy.isAllowed()`
2. DNS pre-resolved and validated via `resolveSafe()`
3. Each redirect `Location` re-validated through both checks
4. HTTPS-to-HTTP downgrades are caught by the policy
5. Max redirect cap (default: 10)

#### `undiciConnect`

Creates a connect function compatible with undici's `Agent`. Dynamically imports `undici` (optional peer dependency) and validates DNS before connecting.

```typescript
import { Agent } from "undici";
import { undiciConnect } from "ressrf/protocols/http";

const agent = new Agent({ connect: undiciConnect(policy) });
const response = await fetch("https://api.example.com", {
  dispatcher: agent,
});
```

#### `validateRedirect`

Utility to validate a single redirect target URL against the policy.

```typescript
import { validateRedirect } from "ressrf/protocols/http";

validateRedirect(policy, "https://new-target.example.com/path");
// throws RessrfBlockedError if the target is denied
```

### TCP

| Function | Description |
|----------|-------------|
| `resolveSafe(policy, host): Promise<string[]>` | Resolve DNS (IPv4 + IPv6), validate all IPs, return allowed list. Throws if all IPs are denied. |
| `createConnection(policy, options): Promise<net.Socket>` | Resolve, validate, and connect. Returns a connected `net.Socket`. |
| `dnsLookup(policy)` | Returns a `dns.lookup`-compatible function for use with `http.Agent` and `net.connect` |

```typescript
import { resolveSafe, createConnection } from "ressrf/protocols/tcp";

// Resolve and validate
const ips = await resolveSafe(policy, "example.com");
console.log("Allowed IPs:", ips);

// Connect directly
const socket = await createConnection(policy, {
  host: "db.example.com",
  port: 5432,
  timeout: 10_000,
});
```

`resolveSafe` resolves both A and AAAA records, combines results, then validates the full set through `policy.isNetworkAllowed()`. If the host is already an IP literal, it validates directly without DNS lookup.

### SSH

```typescript
import { safeSshConnect } from "ressrf/protocols/ssh";
import fs from "node:fs";

const client = await safeSshConnect(policy, {
  host: "git.example.com",
  port: 22,
  username: "deploy",
  privateKey: fs.readFileSync("/home/deploy/.ssh/id_ed25519"),
  timeout: 10_000,
});
```

Under the hood:
1. `createConnection` resolves and validates the target
2. A pre-validated TCP socket is established
3. The socket is passed to `ssh2.Client` via the `sock` option
4. The SSH handshake happens over the already-validated connection

`ssh2` is dynamically imported to avoid hard dependency. Install it as a peer dependency when needed.

## URL Rules

URL-level allow/deny with glob patterns and optional regex. Deny rules are evaluated first. When allow rules are configured, URLs not matching any are blocked.

```typescript
const policy = await new PolicyBuilder("external_only")
  .urlAllow({ scheme: "https", host: "*.stripe.com", path: "/v1/**" })
  .urlAllow({ host: "internal-api.company.com", bypassIpCheck: true })
  .urlDeny({ host: "*.internal" })
  .urlDeny({ regex: "^http://.*$" })
  .build();
```

| Field | Type | Description |
|-------|------|-------------|
| `scheme` | `string?` | Exact scheme match (undefined = any) |
| `host` | `string?` | Host glob (`*` = single DNS label) |
| `path` | `string?` | Path glob (`*` = one segment, `**` = any depth) |
| `regex` | `string?` | Full URL regex (overrides scheme/host/path) |
| `bypassIpCheck` | `boolean?` | When true on allow rule, skip IP-level validation |

## Audit Logging

| Type | Description |
|------|-------------|
| `AuditSink` | Interface: `{ emit(event: AuditEvent): void }` |
| `AuditFunc` | Adapter: wraps any `(event: AuditEvent) => void` function |
| `MultiSink` | Fans out events to multiple sinks |
| `DiscardSink` | Silently drops all events |
| `AuditEvent` | `{ kind: string; fields: Record<string, unknown> }` |
| `parseWasmEvent(raw)` | Parse raw WASM JSON into a typed `AuditEvent` |

```typescript
import { AuditFunc, MultiSink, DiscardSink, Policy } from "ressrf";

// Simple console logging
const sink = new AuditFunc((event) => {
  console.log(`[${event.kind}]`, event.fields);
});

// With pino (user-provided)
import pino from "pino";
const logger = pino();
const pinoSink = new AuditFunc((event) => {
  logger.info({ kind: event.kind, ...event.fields }, "ressrf audit");
});

// Multiple sinks
const multi = new MultiSink([sink, pinoSink]);

const policy = await Policy.externalOnly({ auditSink: multi });
```

Events are emitted from the WASM guest via a host-imported function. The raw JSON is parsed by `parseWasmEvent` and dispatched to the configured sink.

## Error Handling

| Type | Description |
|------|-------------|
| `RessrfBlockedError` | Thrown when a request is denied by policy |
| `.reason` | String describing why the request was blocked |
| `.url` | The URL that was blocked (if applicable) |
| `isBlocked(err)` | Type guard: returns `true` if `err` is a `RessrfBlockedError` |

```typescript
import { Policy, isBlocked, RessrfBlockedError } from "ressrf";

const policy = await Policy.externalOnly();

try {
  policy.isAllowed("http://169.254.169.254/latest/meta-data/");
} catch (err) {
  if (isBlocked(err)) {
    console.error("SSRF blocked:", err.reason);
    // err is narrowed to RessrfBlockedError
  }
}
```

## Low-Level WASM Access

For advanced use cases, the WASM instance is directly accessible:

```typescript
import { loadWasm, type WasmInstance } from "ressrf";

const wasm: WasmInstance = await loadWasm();

// Create a policy handle directly
const handle = wasm.policyNew({
  preset: "external_only",
  allow_cidrs: [],
  deny_cidrs: [],
  cloud_providers: ["aws"],
});

// Validate
const result = wasm.isRequestAllowed(handle, { url: "http://10.0.0.1/" });
console.log(result); // { allowed: false, error: "blocked: ..." }

// Clean up
wasm.policyFree(handle);
```

## Complete Example

```typescript
import { Policy, PolicyBuilder, AuditFunc, isBlocked } from "ressrf";
import { httpAgent, safeFetch } from "ressrf/protocols/http";
import { createConnection } from "ressrf/protocols/tcp";
import http from "node:http";

// Build policy with full protection
const policy = await new PolicyBuilder("external_only")
  .addCloud("aws")
  .addCloud("azure")
  .addCloud("gcp")
  .addAllowed("10.42.0.0/16")
  .auditSink(new AuditFunc((e) => console.log(`[audit] ${e.kind}`, e.fields)))
  .build();

// HTTP with node:http agent
const agent = httpAgent(policy);
http.get("https://api.example.com/health", { agent }, (res) => {
  console.log("Status:", res.statusCode);
});

// HTTP with fetch (redirect-safe)
const response = await safeFetch("https://api.example.com/data", {
  policy,
  maxRedirects: 5,
});
console.log("Fetched:", response.status);

// Direct TCP
const socket = await createConnection(policy, {
  host: "db.example.com",
  port: 5432,
});
console.log("Connected to", socket.remoteAddress);

// Check what gets blocked
for (const url of [
  "http://169.254.169.254/latest/meta-data/",
  "http://metadata.google.internal/",
  "http://10.0.0.1/admin",
]) {
  try {
    policy.isAllowed(url);
  } catch (err) {
    if (isBlocked(err)) {
      console.log(`Blocked: ${url} -> ${err.reason}`);
    }
  }
}

policy.close();
```

## License

MIT
