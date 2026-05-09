//! Async TCP guard with DNS-pinned dialing for SSRF prevention.
//!
//! This crate provides the foundational network layer that `ressrf-http` and
//! `ressrf-ssh` build on. It resolves hostnames, validates every resolved IP
//! against the `ressrf-core` policy, and only then establishes the TCP
//! connection. Because validation happens on the actual resolved address,
//! DNS rebinding attacks are eliminated.
//!
//! # DNS Backends
//!
//! By default, the system resolver is used via `tokio::net::lookup_host`.
//! Enable the `hickory` feature for DNSSEC validation and custom nameservers:
//!
//! ```toml
//! ressrf-tcp = { version = "0.1", features = ["hickory"] }
//! ```

mod connector;
pub mod dns;
mod error;
mod resolver;

pub use connector::SafeConnector;
pub use dns::DnsBackend;
#[cfg(feature = "hickory")]
pub use dns::HickoryDns;
pub use dns::TokioDns;
pub use error::TcpGuardError;
pub use resolver::{ResolveResult, SafeResolver};
