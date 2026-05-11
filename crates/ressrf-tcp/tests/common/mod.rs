//! Shared helpers for Tier 2 SSRF e2e tests.
//!
//! Spins up `CoreDNS` and `WireMock` containers via `testcontainers-rs` and
//! exposes a `ContainerDns` `DnsBackend` adapter that points hickory
//! at a custom `CoreDNS` instance.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use ressrf_tcp::DnsBackend;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// `DnsBackend` adapter that resolves through a hickory resolver pointed
/// at a specific UDP nameserver `SocketAddr` (typically the mapped port
/// of a `CoreDNS` testcontainer).
#[derive(Clone)]
pub struct ContainerDns {
    resolver: Arc<TokioResolver>,
}

impl ContainerDns {
    pub fn new(nameserver: SocketAddr) -> Self {
        let mut udp = ConnectionConfig::udp();
        udp.port = nameserver.port();

        let mut tcp = ConnectionConfig::tcp();
        tcp.port = nameserver.port();

        let ns_config = NameServerConfig::new(
            nameserver.ip(),
            true, // trust negative responses
            vec![udp, tcp],
        );

        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        config.add_name_server(ns_config);

        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .expect("failed to build hickory resolver for ContainerDns");

        Self {
            resolver: Arc::new(resolver),
        }
    }
}

impl DnsBackend for ContainerDns {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(std::io::Error::other)?;
        Ok(lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }
}

pub mod coredns {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use testcontainers::core::{ContainerPort, IntoContainerPort, Mount, WaitFor};
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{ContainerAsync, GenericImage, ImageExt};

    use super::workspace_root;

    /// Start a `CoreDNS` container serving the shared `ssrf.test` zone.
    /// Returns the running container handle (drop = stop) and the
    /// host-side `SocketAddr` of the mapped DNS port.
    pub async fn start() -> (ContainerAsync<GenericImage>, SocketAddr) {
        let zones_dir = workspace_root()
            .join("tests")
            .join("containers")
            .join("coredns");

        let mount = Mount::bind_mount(
            zones_dir.to_str().expect("non-utf8 path").to_string(),
            "/zones",
        );

        let image = GenericImage::new("coredns/coredns", "1.11.3")
            .with_exposed_port(ContainerPort::Udp(53))
            .with_wait_for(WaitFor::message_on_stdout("CoreDNS-"))
            .with_mount(mount)
            .with_cmd(vec!["-conf", "/zones/Corefile"]);

        let container = image
            .start()
            .await
            .expect("failed to start coredns container");

        let port = container
            .get_host_port_ipv4(53.udp())
            .await
            .expect("coredns container did not expose port 53/udp");

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        (container, addr)
    }
}

pub mod wiremock {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use testcontainers::core::{ContainerPort, IntoContainerPort, Mount, WaitFor};
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{ContainerAsync, GenericImage, ImageExt};

    use super::workspace_root;

    /// Start a `WireMock` container with the shared stub mappings.
    /// Returns the running container handle and the host-side
    /// `SocketAddr` of the mapped HTTP port.
    pub async fn start() -> (ContainerAsync<GenericImage>, SocketAddr) {
        let mappings_dir = workspace_root()
            .join("tests")
            .join("containers")
            .join("wiremock")
            .join("mappings");

        let mount = Mount::bind_mount(
            mappings_dir.to_str().expect("non-utf8 path").to_string(),
            "/home/wiremock/mappings",
        );

        let image = GenericImage::new("wiremock/wiremock", "3.9.1")
            .with_exposed_port(ContainerPort::Tcp(8080))
            .with_wait_for(WaitFor::message_on_stdout("port:"))
            .with_mount(mount);

        let container = image
            .start()
            .await
            .expect("failed to start wiremock container");

        let port = container
            .get_host_port_ipv4(8080.tcp())
            .await
            .expect("wiremock container did not expose port 8080/tcp");

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        (container, addr)
    }
}
