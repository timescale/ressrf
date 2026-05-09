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
