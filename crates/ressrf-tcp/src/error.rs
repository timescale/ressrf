use std::net::SocketAddr;

/// Errors produced by the TCP guard layer.
#[derive(Debug, thiserror::Error)]
pub enum TcpGuardError {
    /// The resolved IP address was rejected by the SSRF policy.
    #[error("connection to {addr} blocked by policy: {reason}")]
    Blocked {
        addr: SocketAddr,
        reason: ressrf_core::error::DenyReason,
    },

    /// All resolved addresses were rejected by the policy.
    #[error("all resolved addresses for {host} were blocked by policy")]
    AllBlocked { host: String },

    /// DNS resolution failed.
    #[error("DNS resolution failed for {host}: {source}")]
    DnsError {
        host: String,
        #[source]
        source: std::io::Error,
    },

    /// TCP connection failed after policy validation passed.
    #[error("TCP connect to {addr} failed: {source}")]
    ConnectError {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// The target address string could not be parsed.
    #[error("invalid address: {detail}")]
    InvalidAddress { detail: String },

    /// Connection attempt timed out.
    #[error("connection timed out after {elapsed_ms}ms")]
    Timeout { elapsed_ms: u64 },
}
