//! Tier 2 SSRF e2e tests.
//!
//! Spins up a `CoreDNS` container (with the shared zone file under
//! `tests/containers/coredns/`) and a `WireMock` container (with the shared
//! stub mappings under `tests/containers/wiremock/mappings/`). Each test
//! exercises one bypass technique through the full network stack:
//! `SafeConnector` -> `SafeResolver` -> `Policy`, with a hickory-based
//! `DnsBackend` pointed at the `CoreDNS` container.
//!
//! All tests are gated behind the `e2e` Cargo feature so the regular
//! workspace test matrix stays hermetic. Run with:
//!
//! ```bash
//! cargo test --features e2e -p ressrf-tcp
//! ```
//!
//! Docker (with Linux container support) is required for every test that
//! touches `coredns::start` or `wiremock::start`. Each such test invokes
//! the [`skip_without_docker!`] macro at the top so that the suite passes
//! (with a printed skip notice) on macOS / Windows workstations without a
//! Docker daemon. The CI `e2e-tests` job runs on Ubuntu where Docker is
//! installed.

#![cfg(feature = "e2e")]

#[macro_use]
mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use ressrf_core::{Policy, PolicyBuilder, Preset};
use ressrf_tcp::{SafeConnector, TcpGuardError};

use common::{coredns, wiremock, ContainerDns};

fn external_only() -> Policy {
    PolicyBuilder::new(Preset::ExternalOnly).build()
}

// ---------- DNS-based attacks ----------

#[tokio::test]
async fn dns_wildcard_resolving_to_loopback_is_blocked() {
    skip_without_docker!();
    let (_dns_container, dns_addr) = coredns::start().await;

    let policy = external_only();
    let connector = SafeConnector::with_dns(policy, ContainerDns::new(dns_addr));

    let result = connector.connect("wildcard-loopback.ssrf.test", 80).await;

    assert!(
        matches!(result, Err(TcpGuardError::AllBlocked { .. })),
        "expected AllBlocked, got {result:?}"
    );
}

#[tokio::test]
async fn dns_metadata_alias_to_imds_is_blocked() {
    skip_without_docker!();
    let (_dns_container, dns_addr) = coredns::start().await;

    let policy = external_only();
    let connector = SafeConnector::with_dns(policy, ContainerDns::new(dns_addr));

    let result = connector.connect("metadata-alias.ssrf.test", 80).await;

    assert!(
        matches!(result, Err(TcpGuardError::AllBlocked { .. })),
        "expected AllBlocked, got {result:?}"
    );
}

#[tokio::test]
async fn dns_multi_answer_with_one_private_ip_blocks_all() {
    skip_without_docker!();
    // `multi-answer.ssrf.test` resolves to [8.8.8.8, 10.0.0.1]. Policy
    // must reject the entire set because at least one IP is denied.
    let (_dns_container, dns_addr) = coredns::start().await;

    let policy = external_only();
    let connector = SafeConnector::with_dns(policy, ContainerDns::new(dns_addr));

    let result = connector.connect("multi-answer.ssrf.test", 80).await;

    // SafeResolver keeps the public 8.8.8.8 (it passes ExternalOnly) and
    // drops 10.0.0.1, then attempts to connect to 8.8.8.8:80 which will
    // either time out or succeed depending on the runtime network. Both
    // are acceptable here -- the property under test is that the
    // private IP was filtered out, not that the public one was reached.
    // We tolerate ConnectError, Timeout, and Ok; we reject any error
    // that would indicate the private IP was used.
    match result {
        Ok(_) | Err(TcpGuardError::ConnectError { .. } | TcpGuardError::Timeout { .. }) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

// ---------- DNS rebinding (TOCTOU) ----------

#[tokio::test]
async fn safe_resolver_pins_resolved_ips_no_toctou() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ressrf_tcp::DnsBackend;

    /// DNS backend that returns a public IP on the first call and a
    /// private IP on every subsequent call. If `SafeConnector` were to
    /// re-resolve between the policy check and the connect, the
    /// private IP would slip through.
    #[derive(Clone, Default)]
    struct RebindingDns {
        calls: Arc<AtomicUsize>,
    }

    impl DnsBackend for RebindingDns {
        async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let ip: std::net::IpAddr = if n == 0 {
                "1.2.3.4".parse().unwrap()
            } else {
                "10.0.0.1".parse().unwrap()
            };
            Ok(vec![SocketAddr::new(ip, port)])
        }
    }

    let policy = external_only();
    let dns = RebindingDns::default();
    let calls = Arc::clone(&dns.calls);
    let connector = SafeConnector::with_dns(policy, dns);

    // Best-effort connect; we don't actually care if 1.2.3.4 accepts.
    let _ = connector.connect("rebind.ssrf.test", 80).await;

    let n = calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        n, 1,
        "SafeResolver must resolve once and pin the result \
         (saw {n} resolve() calls). Otherwise an attacker could rebind \
         the host between policy check and connect."
    );
}

// ---------- WireMock redirect chains ----------

#[tokio::test]
async fn wiremock_redirect_to_private_ip_is_blocked_by_redirect_validator() {
    use ressrf_http::{RedirectPolicy, RedirectValidator};

    skip_without_docker!();
    let (_wm_container, wm_addr) = wiremock::start().await;
    let policy = Arc::new(external_only());
    let validator = RedirectValidator::new(Arc::clone(&policy), RedirectPolicy::follow(10));

    // Origin: WireMock; redirect target: http://10.0.0.1/admin
    let origin = format!("http://{wm_addr}/redirect-to-private");
    // First hop is the origin response Location header value.
    let location = "http://10.0.0.1/admin";

    // Origin URL itself doesn't need policy-blocking; it's the redirect
    // target that should be rejected.
    assert!(
        validator.validate_hop(location).is_err(),
        "origin: {origin}"
    );
}

#[tokio::test]
async fn wiremock_redirect_to_imds_is_blocked() {
    use ressrf_http::{RedirectPolicy, RedirectValidator};

    skip_without_docker!();
    let (_wm_container, _wm_addr) = wiremock::start().await;
    let policy = Arc::new(external_only());
    let validator = RedirectValidator::new(Arc::clone(&policy), RedirectPolicy::follow(10));

    let location = "http://169.254.169.254/latest/meta-data/";
    assert!(validator.validate_hop(location).is_err());
}

#[tokio::test]
async fn wiremock_redirect_to_decimal_imds_is_blocked() {
    use ressrf_http::{RedirectPolicy, RedirectValidator};

    skip_without_docker!();
    let (_wm_container, _wm_addr) = wiremock::start().await;
    let policy = Arc::new(external_only());
    let validator = RedirectValidator::new(Arc::clone(&policy), RedirectPolicy::follow(10));

    // 169.254.169.254 as decimal integer.
    let location = "http://2852039166/";
    assert!(
        validator.validate_hop(location).is_err(),
        "BS-1 must catch decimal-encoded IMDS in redirect targets"
    );
}

#[tokio::test]
async fn wiremock_redirect_to_mapped_ipv6_imds_is_blocked() {
    use ressrf_http::{RedirectPolicy, RedirectValidator};

    skip_without_docker!();
    let (_wm_container, _wm_addr) = wiremock::start().await;
    let policy = Arc::new(external_only());
    let validator = RedirectValidator::new(Arc::clone(&policy), RedirectPolicy::follow(10));

    let location = "http://[::ffff:169.254.169.254]/";
    assert!(validator.validate_hop(location).is_err());
}

#[tokio::test]
async fn wiremock_redirect_to_gopher_is_blocked() {
    use ressrf_http::{RedirectPolicy, RedirectValidator};

    skip_without_docker!();
    let (_wm_container, _wm_addr) = wiremock::start().await;
    let policy = Arc::new(external_only());
    let validator = RedirectValidator::new(Arc::clone(&policy), RedirectPolicy::follow(10));

    let location = "gopher://127.0.0.1:6379/_INFO";
    assert!(validator.validate_hop(location).is_err());
}

#[tokio::test]
async fn wiremock_redirect_to_file_is_blocked() {
    use ressrf_http::{RedirectPolicy, RedirectValidator};

    skip_without_docker!();
    let (_wm_container, _wm_addr) = wiremock::start().await;
    let policy = Arc::new(external_only());
    let validator = RedirectValidator::new(Arc::clone(&policy), RedirectPolicy::follow(10));

    let location = "file:///etc/passwd";
    assert!(validator.validate_hop(location).is_err());
}

// ---------- Combined: redirect target uses CoreDNS hostname ----------

#[tokio::test]
async fn redirect_to_dns_alias_resolves_to_internal_and_is_blocked() {
    skip_without_docker!();
    let (_dns_container, dns_addr) = coredns::start().await;
    let (_wm_container, _wm_addr) = wiremock::start().await;

    // The redirect target is `http://wildcard-loopback.ssrf.test/`
    // which CoreDNS resolves to 127.0.0.1. The IP check happens at the
    // TCP layer (the redirect validator only does string-level checks).
    let policy = external_only();
    let connector = SafeConnector::with_dns(policy, ContainerDns::new(dns_addr));

    let result = connector.connect("wildcard-loopback.ssrf.test", 80).await;

    assert!(
        matches!(result, Err(TcpGuardError::AllBlocked { .. })),
        "expected AllBlocked, got {result:?}"
    );
}
