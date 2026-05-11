# Container Assets for SSRF E2E Tests

This directory contains shared container configuration consumed by the
Tier 2 SSRF e2e tests across all supported language bindings (Rust, Go,
Python, Node.js).

The actual container orchestration lives in each language's e2e test
file:

- Rust: `crates/ressrf-tcp/tests/ssrf_e2e.rs` (feature-gated `e2e`)
- Go: `go/ressrf/ssrf_e2e_test.go` (build tag `e2e`)
- Python: `python/tests/test_ssrf_e2e.py` (`@pytest.mark.e2e`)
- Node.js: `node/tests/ssrf-e2e.test.ts` (env var `E2E=1`)

Docker is required to run any Tier 2 test.

## Layout

```
tests/containers/
  coredns/
    Corefile        # CoreDNS config with `ssrf.test` zone authority
    ssrf.zone       # Zone records for the synthetic test domain
  wiremock/
    mappings/       # WireMock stub-mapping JSON, one file per scenario
```

## CoreDNS

`coredns/ssrf.zone` defines a controlled `ssrf.test` zone whose names
resolve to specific IPs that exercise individual SSRF defenses:

| Hostname                          | Resolves to       | Tests                               |
| --------------------------------- | ----------------- | ----------------------------------- |
| `wildcard-loopback.ssrf.test`     | `127.0.0.1`       | DNS-based loopback bypass           |
| `wildcard-imds.ssrf.test`         | `169.254.169.254` | DNS-based IMDS bypass               |
| `wildcard-private.ssrf.test`      | `10.0.0.1`        | DNS-based RFC1918 bypass            |
| `metadata-alias.ssrf.test`        | `169.254.169.254` | Looks like a hostname, hits IMDS    |
| `multi-answer.ssrf.test`          | `8.8.8.8` + `10.0.0.1` | Mixed-answer "all must pass" check |
| `trailing-dot.ssrf.test`          | `169.254.169.254` | Trailing-dot FQDN handling          |
| `public-ok.ssrf.test`             | `93.184.216.34`   | Control: legitimate public IP       |
| `rebind-first.ssrf.test`          | `1.2.3.4`         | DNS rebinding seed (public)         |
| `rebind-second.ssrf.test`         | `10.0.0.1`        | DNS rebinding pivot (private)       |

Test runners spin up `coredns/coredns` (any 1.10+ tag), mount
`coredns/` at `/zones/`, and point their resolver at the container's
mapped UDP/53 port.

## WireMock

`wiremock/mappings/*.json` defines redirect-chain scenarios:

| Endpoint                       | Behavior                                                  |
| ------------------------------ | --------------------------------------------------------- |
| `/`                            | 200 OK (origin baseline)                                  |
| `/redirect-to-private`         | 302 -> `http://10.0.0.1/admin`                            |
| `/redirect-to-imds`            | 302 -> `http://169.254.169.254/latest/meta-data/`         |
| `/redirect-to-ipv6-loopback`   | 302 -> `http://[::1]:8080/`                               |
| `/redirect-to-mapped-imds`     | 302 -> `http://[::ffff:169.254.169.254]/`                 |
| `/redirect-to-decimal-ip`      | 302 -> `http://2852039166/` (IMDS as decimal int)         |
| `/redirect-to-gopher`          | 302 -> `gopher://127.0.0.1:6379/_INFO`                    |
| `/redirect-to-file`            | 302 -> `file:///etc/passwd`                               |
| `/redirect-scheme-downgrade`   | 302 -> `http://example.com/insecure` (from HTTPS origin)  |
| `/multi-hop-1` -> `/multi-hop-2` -> `/multi-hop-3` -> `http://10.0.0.1/` | 3-hop progressive |
| `/redirect-to-dns-alias`       | 302 -> `http://wildcard-loopback.ssrf.test/` (combined)   |
| `/redirect-ok`                 | 302 -> `http://public-ok.ssrf.test/` (control: allowed)   |

Test runners spin up `wiremock/wiremock` (any 3.x tag), mount
`wiremock/mappings/` at `/home/wiremock/mappings/`, and direct
SSRF-test HTTP requests at the container's mapped port.

## Running the e2e tests

Each language has a feature gate so the regular CI is unaffected:

```bash
# Rust
cargo test --features e2e -p ressrf-tcp

# Go
go test -tags e2e -v ./go/ressrf/...

# Python
pytest -m e2e python/

# Node.js
E2E=1 node --test node/tests/
```

All four runners require Docker to be running locally.
