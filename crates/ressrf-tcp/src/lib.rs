//! Async TCP guard with DNS-pinned dialing for SSRF prevention.
//!
//! This crate provides the foundational network layer that `ressrf-http` and
//! `ressrf-ssh` build on. It resolves hostnames, validates every resolved IP
//! against the `ressrf-core` policy, and only then establishes the TCP
//! connection. Because validation happens on the actual resolved address,
//! DNS rebinding attacks are eliminated.

mod connector;
mod error;
mod resolver;

pub use connector::SafeConnector;
pub use error::TcpGuardError;
pub use resolver::{ResolveResult, SafeResolver};
