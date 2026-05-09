use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ressrf_core::Policy;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, instrument};

use crate::error::TcpGuardError;
use crate::resolver::SafeResolver;

/// Default connect timeout (30 seconds) to bound SYN-blackholed hosts.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Async TCP connector that enforces SSRF policy at the network layer.
///
/// Resolves hostnames, validates all resolved IPs against the policy, then
/// connects to the first validated address that accepts the TCP handshake.
/// DNS rebinding is eliminated because the resolved IP is connected to
/// directly without re-resolution.
#[derive(Clone)]
pub struct SafeConnector {
    resolver: SafeResolver,
    timeout: Duration,
}

impl SafeConnector {
    /// Create a connector with the given policy and default 30s timeout.
    pub fn new(policy: Policy) -> Self {
        Self {
            resolver: SafeResolver::new(Arc::new(policy)),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create a connector with a custom timeout.
    pub fn with_timeout(policy: Policy, timeout: Duration) -> Self {
        Self {
            resolver: SafeResolver::new(Arc::new(policy)),
            timeout,
        }
    }

    /// Get a reference to the underlying resolver.
    pub fn resolver(&self) -> &SafeResolver {
        &self.resolver
    }

    /// Connect to a host:port pair after validating all resolved IPs.
    ///
    /// The connection is made directly to a validated IP address, preventing
    /// DNS rebinding attacks. If the host resolves to multiple addresses,
    /// each validated address is tried in order until one connects.
    #[instrument(skip(self), fields(host = %host, port = %port))]
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, TcpGuardError> {
        let start = Instant::now();

        // If the host is already an IP literal, validate it directly
        if let Ok(ip) = host.parse::<IpAddr>() {
            let addr = self.resolver.validate_ip(ip, port)?;
            return self.connect_addr(addr, start).await;
        }

        // Resolve and validate
        let resolved = self.resolver.resolve(host, port).await?;

        // Try each validated address in order
        let mut last_err = None;
        for addr in &resolved.addrs {
            match self.connect_addr(*addr, start).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    debug!(addr = %addr, error = %e, "connect attempt failed, trying next");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| TcpGuardError::AllBlocked {
            host: host.to_string(),
        }))
    }

    /// Connect to a pre-validated `SocketAddr` with the configured timeout.
    async fn connect_addr(
        &self,
        addr: SocketAddr,
        start: Instant,
    ) -> Result<TcpStream, TcpGuardError> {
        let remaining = self.timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(TcpGuardError::Timeout {
                elapsed_ms: elapsed_ms_saturating(start),
            });
        }

        match tokio::time::timeout(remaining, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                debug!(addr = %addr, elapsed_ms = elapsed_ms_saturating(start), "connected");
                Ok(stream)
            }
            Ok(Err(e)) => Err(TcpGuardError::ConnectError { addr, source: e }),
            Err(_) => Err(TcpGuardError::Timeout {
                elapsed_ms: elapsed_ms_saturating(start),
            }),
        }
    }

    /// Convenience: connect using a combined "host:port" address string.
    pub async fn connect_addr_str(&self, address: &str) -> Result<TcpStream, TcpGuardError> {
        let (host, port) = parse_host_port(address)?;
        self.connect(host, port).await
    }
}

/// Convert elapsed time to milliseconds as u64 (cannot overflow for practical timeouts).
fn elapsed_ms_saturating(start: Instant) -> u64 {
    let d = start.elapsed();
    d.as_secs()
        .saturating_mul(1000)
        .saturating_add(u64::from(d.subsec_millis()))
}

/// Parse a "host:port" string, handling IPv6 bracket notation.
fn parse_host_port(address: &str) -> Result<(&str, u16), TcpGuardError> {
    // Handle [IPv6]:port
    if let Some(bracket_end) = address.rfind(']') {
        let host = address
            .get(1..bracket_end)
            .ok_or_else(|| TcpGuardError::InvalidAddress {
                detail: format!("malformed bracketed address: {address}"),
            })?;
        let port_str =
            address
                .get(bracket_end + 2..)
                .ok_or_else(|| TcpGuardError::InvalidAddress {
                    detail: format!("missing port after bracket: {address}"),
                })?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| TcpGuardError::InvalidAddress {
                detail: format!("invalid port: {port_str}"),
            })?;
        return Ok((host, port));
    }

    // Handle host:port (last colon is the separator)
    let colon_pos = address
        .rfind(':')
        .ok_or_else(|| TcpGuardError::InvalidAddress {
            detail: format!("missing port separator: {address}"),
        })?;

    let host = &address[..colon_pos];
    let port_str = &address[colon_pos + 1..];
    let port: u16 = port_str
        .parse()
        .map_err(|_| TcpGuardError::InvalidAddress {
            detail: format!("invalid port: {port_str}"),
        })?;

    if host.is_empty() {
        return Err(TcpGuardError::InvalidAddress {
            detail: "empty host".to_string(),
        });
    }

    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_ipv4() {
        let (host, port) = parse_host_port("8.8.8.8:443").unwrap();
        assert_eq!(host, "8.8.8.8");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_host_port_hostname() {
        let (host, port) = parse_host_port("example.com:80").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_host_port_ipv6_bracket() {
        let (host, port) = parse_host_port("[::1]:8080").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_host_port_missing_port() {
        assert!(parse_host_port("example.com").is_err());
    }

    #[test]
    fn parse_host_port_empty_host() {
        assert!(parse_host_port(":80").is_err());
    }

    #[tokio::test]
    async fn blocks_private_ip_literal() {
        let policy = ressrf_core::PolicyBuilder::new(ressrf_core::Preset::ExternalOnly).build();
        let connector = SafeConnector::new(policy);
        let result = connector.connect("10.0.0.1", 80).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TcpGuardError::Blocked { .. }));
    }

    #[tokio::test]
    async fn blocks_loopback() {
        let policy = ressrf_core::PolicyBuilder::new(ressrf_core::Preset::ExternalOnly).build();
        let connector = SafeConnector::new(policy);
        let result = connector.connect("127.0.0.1", 8080).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TcpGuardError::Blocked { .. }));
    }

    #[tokio::test]
    async fn blocks_ipv6_loopback() {
        let policy = ressrf_core::PolicyBuilder::new(ressrf_core::Preset::ExternalOnly).build();
        let connector = SafeConnector::new(policy);
        let result = connector.connect("::1", 80).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TcpGuardError::Blocked { .. }));
    }

    #[tokio::test]
    async fn blocks_link_local_imds() {
        let policy = ressrf_core::PolicyBuilder::new(ressrf_core::Preset::ExternalOnly).build();
        let connector = SafeConnector::new(policy);
        let result = connector.connect("169.254.169.254", 80).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TcpGuardError::Blocked { .. }));
    }

    #[tokio::test]
    async fn addr_str_parsing() {
        let policy = ressrf_core::PolicyBuilder::new(ressrf_core::Preset::ExternalOnly).build();
        let connector = SafeConnector::new(policy);
        let result = connector.connect_addr_str("10.0.0.1:5432").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TcpGuardError::Blocked { .. }));
    }
}
