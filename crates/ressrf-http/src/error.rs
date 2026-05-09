/// Errors produced by the HTTP guard layer.
#[derive(Debug, thiserror::Error)]
pub enum HttpGuardError {
    /// The request URL scheme is not allowed.
    #[error("scheme {scheme:?} is not allowed")]
    SchemeNotAllowed { scheme: String },

    /// The request host resolved to a blocked IP.
    #[error("host {host:?} resolved to blocked address")]
    HostBlocked { host: String },

    /// A redirect target was blocked by policy.
    #[error("redirect hop {hop} to {url:?} was blocked")]
    RedirectBlocked { hop: u32, url: String },

    /// Too many redirects followed.
    #[error("exceeded maximum redirect count ({max})")]
    TooManyRedirects { max: u32 },

    /// The underlying TCP connection failed.
    #[error("connection failed: {0}")]
    Connection(#[from] ressrf_tcp::TcpGuardError),

    /// Missing or invalid Host header.
    #[error("request has no valid host")]
    NoHost,

    /// Inner service error (boxed for genericity).
    #[error("inner service error: {0}")]
    Inner(Box<dyn std::error::Error + Send + Sync>),
}

impl HttpGuardError {
    /// Wrap a generic inner service error.
    pub fn inner<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Inner(Box::new(err))
    }
}
