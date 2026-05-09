use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ressrf_core::Policy;
use tracing::debug;

use crate::dns::{DnsBackend, TokioDns};
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
pub struct SafeResolver<D: DnsBackend = TokioDns> {
    policy: Arc<Policy>,
    dns: D,
}

impl SafeResolver<TokioDns> {
    /// Create a new resolver with the system DNS backend.
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            dns: TokioDns,
        }
    }
}

impl<D: DnsBackend> SafeResolver<D> {
    /// Create a resolver with a custom DNS backend.
    pub fn with_dns(policy: Arc<Policy>, dns: D) -> Self {
        Self { policy, dns }
    }

    /// Resolve a host:port pair and validate all results against the policy.
    ///
    /// Returns only addresses that pass the policy. If all addresses are
    /// blocked, returns `TcpGuardError::AllBlocked`.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<ResolveResult, TcpGuardError> {
        let addrs = self
            .dns
            .resolve(host, port)
            .await
            .map_err(|e| TcpGuardError::DnsError {
                host: host.to_string(),
                source: e,
            })?;

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
                }
                Err(_) => {
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

    /// Validate a raw `IpAddr` directly against the policy (no DNS needed).
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
