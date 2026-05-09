use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ressrf_core::Policy;
use tokio::net::lookup_host;
use tracing::debug;

use crate::TcpGuardError;

/// The result of a safe DNS resolution: only addresses that passed the policy.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    /// Validated socket addresses (only those that passed the policy).
    pub addrs: Vec<SocketAddr>,
    /// Original host that was resolved.
    pub host: String,
}

/// Resolver that validates every resolved IP against the policy before
/// returning it. This prevents DNS rebinding because the caller connects
/// directly to the validated IP, never re-resolving.
#[derive(Clone)]
pub struct SafeResolver {
    policy: Arc<Policy>,
}

impl SafeResolver {
    /// Create a new resolver bound to the given policy.
    pub fn new(policy: Arc<Policy>) -> Self {
        Self { policy }
    }

    /// Resolve a host:port pair and validate all results against the policy.
    ///
    /// Returns only addresses that pass the policy. If all addresses are
    /// blocked, returns `TcpGuardError::AllBlocked`.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<ResolveResult, TcpGuardError> {
        let lookup_target = format!("{host}:{port}");

        let addrs: Vec<SocketAddr> = lookup_host(&lookup_target)
            .await
            .map_err(|e| TcpGuardError::DnsError {
                host: host.to_string(),
                source: e,
            })?
            .collect();

        if addrs.is_empty() {
            return Err(TcpGuardError::DnsError {
                host: host.to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "DNS resolution returned no addresses",
                ),
            });
        }

        let mut validated = Vec::with_capacity(addrs.len());

        for addr in &addrs {
            let ip: IpAddr = addr.ip();
            match self.policy.is_network_allowed(&[ip]) {
                Ok(()) => {
                    debug!(ip = %ip, host = %host, "address passed policy");
                    validated.push(*addr);
                }
                Err(ressrf_core::Error::Blocked(reason)) => {
                    debug!(ip = %ip, host = %host, ?reason, "address blocked by policy");
                    // Skip this address, try the next one
                }
                Err(_) => {
                    // Non-block errors are unexpected; treat as blocked
                    debug!(ip = %ip, host = %host, "address rejected (unexpected error)");
                }
            }
        }

        if validated.is_empty() {
            return Err(TcpGuardError::AllBlocked {
                host: host.to_string(),
            });
        }

        Ok(ResolveResult {
            addrs: validated,
            host: host.to_string(),
        })
    }

    /// Resolve and validate, but for a raw `IpAddr` (no DNS needed).
    /// Validates the IP directly against the policy.
    pub fn validate_ip(&self, ip: IpAddr, port: u16) -> Result<SocketAddr, TcpGuardError> {
        match self.policy.is_network_allowed(&[ip]) {
            Ok(()) => Ok(SocketAddr::new(ip, port)),
            Err(ressrf_core::Error::Blocked(reason)) => Err(TcpGuardError::Blocked {
                addr: SocketAddr::new(ip, port),
                reason,
            }),
            Err(_) => Err(TcpGuardError::Blocked {
                addr: SocketAddr::new(ip, port),
                reason: ressrf_core::error::DenyReason::HostnameInvalid {
                    reason: "unexpected validation error".into(),
                },
            }),
        }
    }
}
