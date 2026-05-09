//! SSH protocol guard for SSRF prevention.
//!
//! Provides `SafeSshConnector` that resolves hostnames, validates all resolved
//! IPs against the `ressrf-core` policy, and returns a connected `TcpStream`
//! ready for SSH client setup. This mirrors the tiger-connect `SafeSSHDial`
//! pattern: validation happens on the resolved address, eliminating the
//! DNS-rebinding window.
//!
//! # Usage
//!
//! ```ignore
//! use ressrf_core::{PolicyBuilder, Preset};
//! use ressrf_ssh::SafeSshConnector;
//!
//! let policy = PolicyBuilder::new(Preset::ExternalOnly).build();
//! let connector = SafeSshConnector::new(policy);
//!
//! // Returns a TcpStream connected to the validated address
//! let stream = connector.connect("git.example.com", 22).await?;
//! // Use stream with russh, async-ssh2, or thrussh
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use ressrf_core::Policy;
use ressrf_tcp::{SafeConnector, TcpGuardError};
use tokio::net::TcpStream;

/// Default SSH connect timeout.
const DEFAULT_SSH_TIMEOUT: Duration = Duration::from_secs(30);

/// SSH-specific connector that validates destinations before connecting.
///
/// Returns a `TcpStream` that callers can hand to any SSH library (russh,
/// async-ssh2, thrussh). The key security property is that the TCP connection
/// is established to the validated IP directly, not to a hostname that could
/// be rebound by DNS after validation.
pub struct SafeSshConnector {
    inner: SafeConnector,
}

impl SafeSshConnector {
    /// Create a connector with the given policy.
    pub fn new(policy: Policy) -> Self {
        Self {
            inner: SafeConnector::with_timeout(policy, DEFAULT_SSH_TIMEOUT),
        }
    }

    /// Create a connector with a custom timeout.
    pub fn with_timeout(policy: Policy, timeout: Duration) -> Self {
        Self {
            inner: SafeConnector::with_timeout(policy, timeout),
        }
    }

    /// Resolve, validate, and connect to an SSH host.
    ///
    /// Returns the connected `TcpStream` and the validated `SocketAddr` that
    /// was actually connected to. The caller should use this `SocketAddr` for
    /// SSH host key verification.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(TcpStream, SocketAddr), TcpGuardError> {
        let stream = self.inner.connect(host, port).await?;
        let peer_addr = stream
            .peer_addr()
            .map_err(|e| TcpGuardError::ConnectError {
                addr: SocketAddr::new([0, 0, 0, 0].into(), port),
                source: e,
            })?;
        Ok((stream, peer_addr))
    }

    /// Convenience: resolve and validate without connecting.
    ///
    /// Returns the list of validated `SocketAddr`s. Useful when the caller
    /// needs to do the SSH handshake themselves with a specific library.
    pub async fn resolve_and_validate(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, TcpGuardError> {
        let resolved = self.inner.resolver().resolve(host, port).await?;
        Ok(resolved.addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ressrf_core::{PolicyBuilder, Preset};

    #[tokio::test]
    async fn blocks_private_ssh_target() {
        let policy = PolicyBuilder::new(Preset::ExternalOnly).build();
        let connector = SafeSshConnector::new(policy);
        let result = connector.connect("10.0.0.1", 22).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn blocks_loopback_ssh() {
        let policy = PolicyBuilder::new(Preset::ExternalOnly).build();
        let connector = SafeSshConnector::new(policy);
        let result = connector.connect("127.0.0.1", 22).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn blocks_imds_on_ssh_port() {
        let policy = PolicyBuilder::new(Preset::ExternalOnly).build();
        let connector = SafeSshConnector::new(policy);
        let result = connector.connect("169.254.169.254", 22).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_and_validate_blocks_private() {
        let policy = PolicyBuilder::new(Preset::ExternalOnly).build();
        let connector = SafeSshConnector::new(policy);
        let result = connector.resolve_and_validate("192.168.1.1", 22).await;
        assert!(result.is_err());
    }
}
