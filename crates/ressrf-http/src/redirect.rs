use std::sync::Arc;

use ressrf_core::Policy;

use crate::HttpGuardError;

/// Policy controlling how redirects are handled.
#[derive(Debug, Clone)]
pub struct RedirectPolicy {
    /// Maximum number of redirects to follow (default: 10).
    pub max_redirects: u32,
    /// Whether to re-validate the target on each redirect hop (default: true).
    /// Should always be true for security; exposed for testing only.
    pub validate_per_hop: bool,
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            validate_per_hop: true,
        }
    }
}

impl RedirectPolicy {
    /// No redirects allowed.
    pub fn none() -> Self {
        Self {
            max_redirects: 0,
            validate_per_hop: true,
        }
    }

    /// Follow up to `n` redirects with per-hop validation.
    pub fn follow(n: u32) -> Self {
        Self {
            max_redirects: n,
            validate_per_hop: true,
        }
    }
}

/// Stateful redirect validator for per-hop re-validation.
///
/// Plug this into your HTTP client's redirect hook (e.g. reqwest's
/// `redirect::Policy`, hyper's manual redirect handling) to validate
/// each redirect target against the SSRF policy before following it.
///
/// # Example (reqwest)
///
/// ```ignore
/// use ressrf_http::RedirectValidator;
///
/// let validator = RedirectValidator::new(policy, RedirectPolicy::follow(10));
/// let client = reqwest::Client::builder()
///     .redirect(reqwest::redirect::Policy::custom(move |attempt| {
///         match validator.validate_hop(attempt.url().as_str()) {
///             Ok(()) => attempt.follow(),
///             Err(_) => attempt.stop(),
///         }
///     }))
///     .build()?;
/// ```
pub struct RedirectValidator {
    policy: Arc<Policy>,
    redirect_policy: RedirectPolicy,
    hops: std::sync::atomic::AtomicU32,
}

impl Clone for RedirectValidator {
    fn clone(&self) -> Self {
        Self {
            policy: Arc::clone(&self.policy),
            redirect_policy: self.redirect_policy.clone(),
            hops: std::sync::atomic::AtomicU32::new(
                self.hops.load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

impl RedirectValidator {
    /// Create a new redirect validator.
    pub fn new(policy: Arc<Policy>, redirect_policy: RedirectPolicy) -> Self {
        Self {
            policy,
            redirect_policy,
            hops: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Reset the hop counter (call before starting a new request chain).
    pub fn reset(&self) {
        self.hops.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Validate a redirect target URL. Call this for each hop.
    ///
    /// Returns `Ok(())` if the redirect is allowed, or an error describing
    /// why it was blocked.
    ///
    /// # Defense-in-depth (BS-7)
    ///
    /// `validate_hop` is synchronous and runs only string-level checks via
    /// `UriValidator::validate_url`: scheme allowlist, bare-IP policy match,
    /// userinfo bypass detection, ambiguous IP encoding, NUL/CRLF, trailing
    /// dot normalization, backslash normalization, and domain suffix rules.
    ///
    /// It does **not** perform DNS resolution on hostname-based redirect
    /// targets, because DNS is async and the redirect hook of most HTTP
    /// clients is synchronous. A redirect like `https://innocent-looking.com`
    /// that resolves to `10.0.0.1` will pass this check.
    ///
    /// The defense-in-depth design ensures the IP is still checked at the
    /// TCP layer: when the underlying `SafeConnector` (from `ressrf-tcp`)
    /// connects to the redirect target, it resolves the hostname and
    /// validates every resolved IP against the same `Policy`. The connection
    /// is made directly to the validated IP, so DNS rebinding between
    /// `validate_hop` and the actual connect is impossible.
    ///
    /// Therefore, always pair `RedirectValidator` with `SafeConnector` (or an
    /// equivalent DNS-pinning connector) for full SSRF protection on
    /// redirects.
    pub fn validate_hop(&self, target_url: &str) -> Result<(), HttpGuardError> {
        let hop = self.hops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if hop >= self.redirect_policy.max_redirects {
            return Err(HttpGuardError::TooManyRedirects {
                max: self.redirect_policy.max_redirects,
            });
        }

        if !self.redirect_policy.validate_per_hop {
            return Ok(());
        }

        let validator = ressrf_core::UriValidator::default();
        if let Err(_e) = validator.validate_url(target_url, Some(&self.policy)) {
            return Err(HttpGuardError::RedirectBlocked {
                hop: hop + 1,
                url: target_url.to_string(),
            });
        }

        // Also check scheme is allowed by the policy
        if let Some(scheme_end) = target_url.find("://") {
            let scheme = &target_url[..scheme_end];
            if self.policy.validate_scheme(scheme).is_err() {
                return Err(HttpGuardError::RedirectBlocked {
                    hop: hop + 1,
                    url: target_url.to_string(),
                });
            }
        }

        Ok(())
    }
}
