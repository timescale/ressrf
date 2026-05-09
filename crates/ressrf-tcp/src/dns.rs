//! DNS resolution backends.
//!
//! Two backends are available:
//! - `TokioDns`: uses `tokio::net::lookup_host` (system resolver, always available)
//! - `HickoryDns`: uses `hickory-resolver` (DNSSEC support, custom nameservers, requires `hickory` feature)

use std::net::SocketAddr;

/// Trait for async DNS resolution.
#[allow(async_fn_in_trait)]
pub trait DnsBackend: Send + Sync {
    /// Resolve a host:port pair to a list of socket addresses.
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

/// Default backend using `tokio::net::lookup_host` (system resolver).
#[derive(Debug, Clone, Default)]
pub struct TokioDns;

impl DnsBackend for TokioDns {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let target = format!("{host}:{port}");
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
        Ok(addrs)
    }
}

/// Hickory-resolver backend with DNSSEC validation and custom nameserver support.
#[cfg(feature = "hickory")]
#[derive(Clone)]
pub struct HickoryDns {
    resolver: hickory_resolver::TokioResolver,
}

#[cfg(feature = "hickory")]
impl HickoryDns {
    /// Create a hickory resolver with default tokio runtime provider.
    pub fn new() -> std::io::Result<Self> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(std::io::Error::other)?
            .build()
            .map_err(std::io::Error::other)?;
        Ok(Self { resolver })
    }

    /// Create a hickory resolver with custom options.
    pub fn with_options(opts: hickory_resolver::config::ResolverOpts) -> std::io::Result<Self> {
        let mut builder =
            hickory_resolver::TokioResolver::builder_tokio().map_err(std::io::Error::other)?;
        *builder.options_mut() = opts;
        let resolver = builder.build().map_err(std::io::Error::other)?;
        Ok(Self { resolver })
    }
}

#[cfg(feature = "hickory")]
impl DnsBackend for HickoryDns {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(std::io::Error::other)?;
        let addrs: Vec<SocketAddr> = lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect();
        Ok(addrs)
    }
}
