//! HTTP protocol integration for SSRF prevention.
//!
//! Provides a Tower `Layer` that wraps any HTTP service and validates outbound
//! requests against the `ressrf-core` policy before forwarding them. Also
//! provides a redirect interceptor that re-validates each hop.
//!
//! # Architecture
//!
//! The `SsrfLayer` wraps an inner service (typically an HTTP client) and
//! intercepts requests to validate:
//! 1. The URL scheme is allowed
//! 2. The resolved IP addresses are not in denied ranges
//! 3. Redirect targets are re-validated per hop
//!
//! DNS-pinned dialing is delegated to `ressrf-tcp::SafeConnector`, ensuring
//! that validation and connection happen atomically on the same resolved IP.

mod error;
mod layer;
mod redirect;

pub use error::HttpGuardError;
pub use layer::{SsrfLayer, SsrfService};
pub use redirect::{RedirectPolicy, RedirectValidator};
