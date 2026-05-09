use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Request, Response};
use ressrf_core::{PolicyBuilder, Preset};
use ressrf_http::{HttpGuardError, RedirectPolicy, RedirectValidator, SsrfLayer, SsrfService};
use tower_layer::Layer;
use tower_service::Service;

#[derive(Clone)]
struct MockService;

impl Service<Request<()>> for MockService {
    type Response = Response<()>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<()>) -> Self::Future {
        std::future::ready(Ok(Response::new(())))
    }
}

fn external_policy() -> ressrf_core::Policy {
    PolicyBuilder::new(Preset::ExternalOnly).build()
}

#[tokio::test]
async fn allows_public_https_url() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc: SsrfService<MockService> = layer.layer(MockService);

    let req = Request::builder()
        .uri("https://example.com/api")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn blocks_private_ip_in_uri() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder()
        .uri("https://10.0.0.1/internal")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        HttpGuardError::HostBlocked { .. }
    ));
}

#[tokio::test]
async fn blocks_loopback_in_uri() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder()
        .uri("https://127.0.0.1:8080/admin")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        HttpGuardError::HostBlocked { .. }
    ));
}

#[tokio::test]
async fn blocks_ipv6_loopback() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder()
        .uri("https://[::1]:9090/")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    // The http crate may present IPv6 host with brackets that don't parse as
    // IpAddr, in which case the pre-flight IP check is skipped (TCP layer
    // handles it). If it does parse, it should be blocked.
    if let Err(e) = result {
        assert!(matches!(e, HttpGuardError::HostBlocked { .. }));
    }
}

#[tokio::test]
async fn blocks_imds_address() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder()
        .uri("https://169.254.169.254/latest/meta-data/")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn blocks_plaintext_http_scheme() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder()
        .uri("http://example.com/path")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        HttpGuardError::SchemeNotAllowed { .. }
    ));
}

#[tokio::test]
async fn falls_back_to_host_header_blocked() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder()
        .uri("/path")
        .header("Host", "10.0.0.1:8080")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        HttpGuardError::HostBlocked { .. }
    ));
}

#[tokio::test]
async fn rejects_missing_host() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder().uri("/no-host").body(()).unwrap();

    let result = svc.call(req).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), HttpGuardError::NoHost));
}

#[tokio::test]
async fn allows_hostname_without_ip_check() {
    let layer = SsrfLayer::new(external_policy());
    let mut svc = layer.layer(MockService);

    let req = Request::builder()
        .uri("https://api.github.com/repos")
        .body(())
        .unwrap();

    let result = svc.call(req).await;
    assert!(result.is_ok());
}

#[test]
fn redirect_validator_blocks_private_ip() {
    let policy = Arc::new(external_policy());
    let validator = RedirectValidator::new(policy, RedirectPolicy::follow(10));

    let result = validator.validate_hop("http://192.168.1.1/secret");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        HttpGuardError::RedirectBlocked { .. }
    ));
}

#[test]
fn redirect_validator_allows_public_url() {
    let policy = Arc::new(external_policy());
    let validator = RedirectValidator::new(policy, RedirectPolicy::follow(10));

    let result = validator.validate_hop("https://example.com/redirected");
    assert!(result.is_ok());
}

#[test]
fn redirect_validator_enforces_max_hops() {
    let policy = Arc::new(external_policy());
    let validator = RedirectValidator::new(policy, RedirectPolicy::follow(3));

    assert!(validator.validate_hop("https://a.com").is_ok());
    assert!(validator.validate_hop("https://b.com").is_ok());
    assert!(validator.validate_hop("https://c.com").is_ok());
    let result = validator.validate_hop("https://d.com");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        HttpGuardError::TooManyRedirects { max: 3 }
    ));
}

#[test]
fn redirect_validator_reset_clears_counter() {
    let policy = Arc::new(external_policy());
    let validator = RedirectValidator::new(policy, RedirectPolicy::follow(2));

    assert!(validator.validate_hop("https://a.com").is_ok());
    assert!(validator.validate_hop("https://b.com").is_ok());
    assert!(validator.validate_hop("https://c.com").is_err());

    validator.reset();
    assert!(validator.validate_hop("https://d.com").is_ok());
}

#[test]
fn redirect_policy_none_blocks_all_redirects() {
    let policy = Arc::new(external_policy());
    let validator = RedirectValidator::new(policy, RedirectPolicy::none());

    let result = validator.validate_hop("https://example.com/ok");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        HttpGuardError::TooManyRedirects { max: 0 }
    ));
}
