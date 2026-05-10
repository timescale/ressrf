# ressrf-ssh

SSH connection guard for SSRF prevention. Resolves hostnames, validates all resulting IPs against a `ressrf-core` policy, and returns a validated TCP stream suitable for SSH client libraries (russh, async-ssh2).

## Public API

| Type | Description |
|------|-------------|
| `SafeSshConnector` | Resolves and validates before establishing TCP for SSH |

## Usage

```rust
use ressrf_core::PolicyBuilder;
use ressrf_ssh::SafeSshConnector;
use std::time::Duration;

let policy = PolicyBuilder::external_only().build();
let connector = SafeSshConnector::with_timeout(policy, Duration::from_secs(10));

// Returns a validated TcpStream + SocketAddr for SSH handshake
let (stream, addr) = connector.connect("git.example.com", 22).await?;
```

The returned `TcpStream` can be passed to any SSH library that accepts a pre-connected socket.

## License

MIT
