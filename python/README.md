# ressrf (Python)

Python SSRF prevention library with a native Rust core via PyO3. Provides policy validation, protocol adapters for popular HTTP/SSH libraries, and pluggable audit logging.

## Installation

```bash
pip install ressrf

# With optional protocol adapters
pip install ressrf[httpx]       # httpx SafeTransport / AsyncSafeTransport
pip install ressrf[requests]    # requests SafeAdapter
pip install ressrf[ssh]         # paramiko safe_ssh_connect
pip install ressrf[all]         # all adapters
```

Requires Python 3.10+. The package ships a native extension built with PyO3/maturin.

## Public API

### Policy

| Method | Description |
|--------|-------------|
| `Policy.external_only(*, cloud=None, denied=None, allowed=None, audit_sink=None)` | Default deny for private/internal ranges; allow public internet |
| `Policy.internal_only(*, allowed=None, audit_sink=None)` | Default deny all; only explicitly allowed CIDRs pass |
| `Policy.permissive(*, audit_sink=None)` | No blocking; audit-only mode |
| `policy.is_network_allowed(ips: list[str]) -> None` | Validate IPs. Raises `RessrfBlockedError` if any IP is denied |
| `policy.validate_url(url: str) -> None` | Validate URL (scheme + host + IP). Raises `RessrfBlockedError` if denied |
| `policy.preset` | Read-only property: the preset name used to create this policy |

### PolicyBuilder

| Method | Description |
|--------|-------------|
| `PolicyBuilder(preset="external_only")` | Create a builder with a preset |
| `.add_denied(cidrs: list[str])` | Add CIDRs to the deny list |
| `.add_allowed(cidrs: list[str])` | Add CIDRs to the allow list (overrides deny) |
| `.header_rules(required=None, denied=None, auto_xff=False)` | Configure header validation |
| `.protocol_rules(allow_plaintext_http=True, require_https=True)` | Configure protocol rules |
| `.with_cloud(name: str)` | Add a cloud provider (`"aws"`, `"azure"`, `"gcp"`) |
| `.audit_sink(sink)` | Attach an audit sink (Protocol or callable) |
| `.build() -> Policy` | Finalize and return an immutable Policy |

```python
from ressrf import PolicyBuilder

policy = (
    PolicyBuilder("external_only")
    .with_cloud("aws")
    .with_cloud("azure")
    .add_denied(["10.0.0.0/8"])
    .add_allowed(["10.42.0.0/16"])  # known-safe internal service
    .build()
)
```

## Protocol Adapters

### HTTP (httpx)

Two adapters are provided: `SafeTransport` (sync) and `AsyncSafeTransport` (async). Both intercept DNS resolution via `safe_getaddrinfo` before allowing connections.

```python
import httpx
from ressrf import Policy
from ressrf.protocols.http import SafeTransport, AsyncSafeTransport, httpx_client

policy = Policy.external_only(cloud=["aws"])

# Option 1: Use the transport directly
transport = SafeTransport(policy)
client = httpx.Client(transport=transport)
response = client.get("https://api.example.com/data")

# Option 2: Use the factory (adds redirect re-validation hooks)
client = httpx_client(policy, max_redirects=10)
response = client.get("https://api.example.com/data")

# Async variant
async_transport = AsyncSafeTransport(policy)
async with httpx.AsyncClient(transport=async_transport) as client:
    response = await client.get("https://api.example.com/data")
```

The `httpx_client` factory adds a response event hook that re-validates redirect targets per hop and blocks HTTPS-to-HTTP downgrades.

### HTTP (requests)

```python
import requests
from ressrf.protocols.http import SafeAdapter, requests_session

policy = Policy.external_only()

# Option 1: Mount the adapter manually
session = requests.Session()
session.mount("https://", SafeAdapter(policy))
session.mount("http://", SafeAdapter(policy))

# Option 2: Use the factory (adds redirect hook)
session = requests_session(policy, max_redirects=10)
response = session.get("https://api.example.com/data")
```

`requests_session` mounts `SafeAdapter` on both schemes and adds a response hook that re-validates redirect `Location` headers through the policy.

### SSH (paramiko)

```python
from ressrf.protocols.ssh import safe_ssh_connect

policy = Policy.external_only()

client = safe_ssh_connect(
    policy,
    "git.example.com",
    port=22,
    timeout=10.0,
    username="deploy",
    pkey=my_private_key,
)
# client is a connected paramiko.SSHClient
stdin, stdout, stderr = client.exec_command("whoami")
```

Under the hood, `safe_ssh_connect` resolves the hostname, validates all resolved IPs through the policy, creates a TCP socket via `create_connection`, then hands the socket to `paramiko.SSHClient.connect()` via the `sock` parameter.

### TCP

| Function | Description |
|----------|-------------|
| `safe_getaddrinfo(policy, host, port, ...)` | Resolves DNS, filters results through policy, returns only allowed entries. Raises `RessrfBlockedError` if all resolved IPs are denied. |
| `create_connection(policy, (host, port), timeout=30.0, source_address=None)` | Resolves, validates, and connects. Returns a `socket.socket`. Tries all allowed addresses in order. |

```python
from ressrf.protocols.tcp import safe_getaddrinfo, create_connection

# Get validated address info
addrs = safe_getaddrinfo(policy, "example.com", 443, type_=socket.SOCK_STREAM)

# Or connect directly
sock = create_connection(policy, ("example.com", 443), timeout=10.0)
```

## URL Rules

URL-level allow/deny with glob patterns and optional regex. Deny rules are evaluated first. When allow rules are configured, URLs not matching any are blocked.

```python
policy = (
    PolicyBuilder("external_only")
    .url_allow(scheme="https", host="*.stripe.com", path="/v1/**")
    .url_allow(host="internal-api.company.com", bypass_ip_check=True)
    .url_deny(host="*.internal")
    .url_deny(regex=r"^http://.*$")
    .build()
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `scheme` | `str \| None` | Exact scheme match (None = any) |
| `host` | `str \| None` | Host glob (`*` = single DNS label) |
| `path` | `str \| None` | Path glob (`*` = one segment, `**` = any depth) |
| `regex` | `str \| None` | Full URL regex (overrides scheme/host/path) |
| `bypass_ip_check` | `bool` | When True on allow rule, skip IP-level validation |

## Audit Logging

| Type | Description |
|------|-------------|
| `AuditSink` | Protocol (PEP 544): must implement `emit(event: AuditEvent) -> None` |
| `AuditFunc` | Adapter: wraps any callable `(AuditEvent) -> None` |
| `MultiSink` | Fans out events to multiple sinks |
| `DiscardSink` | Silently drops all events |
| `AuditEvent` | Frozen dataclass with `event_type: str` and `fields: dict` |

```python
from ressrf import AuditFunc, AuditEvent, MultiSink, Policy
import logging

logger = logging.getLogger("ressrf")

# With stdlib logging
sink = AuditFunc(lambda e: logger.info("audit: %s %s", e.event_type, e.fields))

# With structlog
import structlog
log = structlog.get_logger()
sink = AuditFunc(lambda e: log.info("ressrf.audit", kind=e.event_type, **e.fields))

# Multiple sinks
multi = MultiSink([logging_sink, metrics_sink])

policy = Policy.external_only(cloud=["aws"], audit_sink=sink)
```

## Error Handling

| Type | Description |
|------|-------------|
| `RessrfBlockedError` | Raised when a request is denied by policy |
| `.message` | Human-readable error description |
| `.reason` | Structured `dict` with denial details |

```python
from ressrf import Policy, RessrfBlockedError

policy = Policy.external_only()

try:
    policy.validate_url("http://169.254.169.254/latest/meta-data/")
except RessrfBlockedError as e:
    print(e.message)  # "blocked: IP in deny range..."
    print(e.reason)   # {"type": "blocked", "ip": "169.254.169.254", ...}
```

The `reason` dict always contains a `"type"` key. Common types:

- `"blocked"` - IP matched a deny CIDR
- `"all_resolved_ips_denied"` - DNS resolved but all IPs are in deny ranges
- `"redirect_scheme_downgrade"` - HTTPS-to-HTTP redirect detected

## Complete Example

```python
from ressrf import Policy, PolicyBuilder, AuditFunc, RessrfBlockedError
from ressrf.protocols.http import httpx_client
from ressrf.protocols.tcp import create_connection
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ressrf")

# Build a comprehensive policy
policy = (
    PolicyBuilder("external_only")
    .with_cloud("aws")
    .with_cloud("azure")
    .with_cloud("gcp")
    .add_allowed(["10.42.0.0/16"])
    .audit_sink(AuditFunc(lambda e: logger.info("%s: %s", e.event_type, e.fields)))
    .build()
)

# Safe HTTP client (validates DNS + redirect targets)
client = httpx_client(policy)
response = client.get("https://api.example.com/data")
print(response.status_code)

# Direct TCP connection (validates before connect)
sock = create_connection(policy, ("db.example.com", 5432))
# ... use sock for database protocol ...

# Check what gets blocked
for url in [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://metadata.google.internal/",           # GCP metadata
    "http://10.0.0.1/admin",                      # private IP
]:
    try:
        policy.validate_url(url)
    except RessrfBlockedError as e:
        print(f"Blocked: {url} -> {e.reason['type']}")
```

## Tooling

| Tool | Purpose |
|------|---------|
| **ruff** | Formatting (`ruff format`) and linting (`ruff check`) |
| **ty** | Type checking |
| **uv** | Environment and dependency management |
| **maturin** | Build system for the PyO3 native extension |

```bash
# Development setup
cd python
uv venv && uv pip install maturin pytest
uv run maturin develop

# Run tests
uv run pytest tests/ -v

# Lint
uvx ruff format --check .
uvx ruff check .
uvx ty check
```

## License

MIT
