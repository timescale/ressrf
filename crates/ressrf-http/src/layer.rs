use std::sync::Arc;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use ressrf_core::Policy;
use tower_layer::Layer;
use tower_service::Service;

use crate::redirect::RedirectPolicy;

/// Tower `Layer` that adds SSRF validation to an HTTP client service.
///
/// Wrap any `Service<http::Request<B>>` with this layer to enforce policy
/// checks on the request URI before forwarding to the inner service.
#[derive(Clone)]
pub struct SsrfLayer {
    policy: Arc<Policy>,
    redirect_policy: RedirectPolicy,
}

impl SsrfLayer {
    /// Create a layer with the given SSRF policy.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
            redirect_policy: RedirectPolicy::default(),
        }
    }

    /// Create a layer with a custom redirect policy.
    pub fn with_redirect_policy(policy: Policy, redirect_policy: RedirectPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
            redirect_policy,
        }
    }
}

impl<S> Layer<S> for SsrfLayer {
    type Service = SsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SsrfService {
            inner,
            policy: Arc::clone(&self.policy),
            redirect_policy: self.redirect_policy.clone(),
        }
    }
}

/// Tower `Service` that validates outbound HTTP requests against the SSRF
/// policy before delegating to the inner service.
///
/// This service checks:
/// 1. The request URI scheme is in the allowlist
/// 2. The host is not in a denied range (pre-flight check)
///
/// For full DNS-rebinding protection, pair this with `ressrf-tcp::SafeConnector`
/// at the transport layer so that the actual resolved IP is validated at
/// connect time.
#[derive(Clone)]
pub struct SsrfService<S> {
    inner: S,
    policy: Arc<Policy>,
    redirect_policy: RedirectPolicy,
}

impl<S> SsrfService<S> {
    /// Get the redirect policy.
    pub fn redirect_policy(&self) -> &RedirectPolicy {
        &self.redirect_policy
    }
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for SsrfService<S>
where
    S: Service<http::Request<ReqBody>>,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = crate::HttpGuardError;
    type Future = SsrfFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(crate::HttpGuardError::inner)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        if let Err(e) = validate_request(&req, &self.policy) {
            return SsrfFuture::rejected(e);
        }

        SsrfFuture::forwarded(self.inner.call(req))
    }
}

/// Validate a request's URI against the SSRF policy.
fn validate_request<B>(
    req: &http::Request<B>,
    policy: &Policy,
) -> Result<(), crate::HttpGuardError> {
    let uri = req.uri();

    if let Some(scheme) = uri.scheme_str() {
        policy
            .validate_scheme(scheme)
            .map_err(|_| crate::HttpGuardError::SchemeNotAllowed {
                scheme: scheme.to_string(),
            })?;
    }

    let host = uri
        .host()
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h))
        })
        .ok_or(crate::HttpGuardError::NoHost)?;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        policy
            .is_network_allowed(&[ip])
            .map_err(|_| crate::HttpGuardError::HostBlocked {
                host: host.to_string(),
            })?;
    }

    Ok(())
}

pin_project! {
    /// Future type for the SSRF service.
    ///
    /// Either immediately returns an error (if pre-flight validation failed)
    /// or delegates to the inner service's future with sound structural pinning.
    #[project = SsrfFutureProj]
    pub enum SsrfFuture<F> {
        Rejected { error: Option<crate::HttpGuardError> },
        Forwarded { #[pin] future: F },
    }
}

impl<F> SsrfFuture<F> {
    fn rejected(e: crate::HttpGuardError) -> Self {
        Self::Rejected { error: Some(e) }
    }

    fn forwarded(fut: F) -> Self {
        Self::Forwarded { future: fut }
    }
}

impl<F, T, E> std::future::Future for SsrfFuture<F>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    type Output = Result<T, crate::HttpGuardError>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            SsrfFutureProj::Rejected { error } => {
                Poll::Ready(Err(error.take().expect("polled after completion")))
            }
            SsrfFutureProj::Forwarded { future } => {
                future.poll(cx).map_err(crate::HttpGuardError::inner)
            }
        }
    }
}
