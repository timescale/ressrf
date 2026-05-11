# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

Only the latest minor release receives security patches. When a new minor version is released, the previous minor version moves to unsupported.

## Reporting a Vulnerability

If you discover a security vulnerability in ressrf, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Private Advisory** (preferred): Go to the [Security Advisories](https://github.com/timescale/ressrf/security/advisories/new) page and create a new private advisory.

2. **Email**: Send a description to **security@tigerdata.com** with the subject line `[ressrf] Security Report`.

### What to Include

- A description of the vulnerability and its impact.
- Steps to reproduce, ideally with a minimal code example or test case.
- The affected component (e.g. `ressrf-core`, `ressrf-wasm`, Go/Python/Node bindings).
- Your assessment of severity (Critical, High, Medium, Low).

### Scope

The following are in scope for security reports:

- SSRF bypass (any technique that circumvents the policy engine to reach a denied destination).
- DNS rebinding or TOCTOU attacks that bypass the resolve-once-pin guarantee.
- Memory safety issues in `unsafe` Rust code or WASM FFI boundaries.
- Denial of service through unbounded resource consumption in the library.
- Cross-language parity gaps where one language binding is less restrictive than another.
- Supply chain concerns (CI/CD, dependency vulnerabilities, codegen integrity).

The following are out of scope:

- Misconfiguration by the library consumer (e.g. setting `bypass_ip_check: true` on overly broad URL rules).
- Denial of service at the application level (the library does not rate-limit policy evaluations by design).
- Vulnerabilities in transitive dependencies unless they are exploitable through ressrf's usage of those dependencies.

## Security Design

For a detailed threat model covering trust boundaries, STRIDE analysis per component, and accepted risks, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Verification

When release artifacts include provenance attestations, verify them with:

```bash
gh attestation verify ressrf-<target>.tar.gz --repo timescale/ressrf
```
