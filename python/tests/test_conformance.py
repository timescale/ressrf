"""Cross-language conformance tests using shared JSON vectors."""

from __future__ import annotations

import pytest

from ressrf._core import cidr_contains
from ressrf.audit import AuditEvent, AuditFunc
from ressrf.errors import RessrfBlockedError
from ressrf.policy import Policy, PolicyBuilder


class TestCidrContainment:
    """Test CIDR containment using shared vectors."""

    def test_all_vectors(self, cidr_vectors: list[dict]) -> None:
        for case in cidr_vectors:
            cidr = case["cidr"]
            ip = case["ip"]
            expected = case["expected"]
            result = cidr_contains(cidr, ip)
            assert result == expected, (
                f"cidr_contains({cidr!r}, {ip!r}) = {result}, "
                f"expected {expected} ({case.get('note', '')})"
            )


class TestPolicyDecisions:
    """Test policy decisions using shared vectors."""

    def test_all_vectors(self, policy_vectors: list[dict]) -> None:
        for case in policy_vectors:
            preset = case["preset"]
            ips = case["ips"]
            expected = case["expected"]
            name = case["name"]

            builder = PolicyBuilder(preset)

            if "allow" in case:
                builder.add_allowed(case["allow"])
            if "deny" in case:
                builder.add_denied(case["deny"])
            for provider in case.get("cloud_providers", []):
                builder.with_cloud(provider)

            policy = builder.build()

            if expected == "allowed":
                policy.is_network_allowed(ips)
            else:
                with pytest.raises(RessrfBlockedError) as exc_info:
                    policy.is_network_allowed(ips)
                if "reason_type" in case:
                    reason_type = case["reason_type"]
                    got = exc_info.value.reason.get("type", "")
                    assert reason_type in str(exc_info.value) or reason_type in str(
                        got
                    ), f"case {name}: expected {reason_type}, got {got}"


class TestUrlValidation:
    """Test URL validation using shared vectors."""

    def test_all_vectors(self, url_vectors: list[dict]) -> None:
        policy = Policy.external_only()

        for case in url_vectors:
            case["name"]
            url = case["url"]
            expected = case["expected"]

            has_custom_config = "denied_suffixes" in case or "trusted_suffixes" in case
            if has_custom_config:
                continue

            if expected == "allowed":
                policy.validate_url(url)
            else:
                with pytest.raises((RessrfBlockedError, ValueError)):
                    policy.validate_url(url)


class TestSsrfTechniques:
    """End-to-end SSRF bypass technique vectors.

    Walks every URL in tests/vectors/ssrf_techniques.json through the
    PyO3-backed `Policy.validate_url` and asserts the expected
    allow/block decision. Cases that need denied/trusted domain
    suffix configuration are skipped (mirroring the
    `TestUrlValidation` pattern) since those knobs are not exposed
    on the Python `PolicyBuilder` surface yet.
    """

    def test_all_vectors(self, ssrf_techniques_vectors: list[dict]) -> None:
        policy = Policy.external_only()

        for case in ssrf_techniques_vectors:
            name = case["name"]
            url = case["url"]
            expected = case["expected"]
            category = case.get("category", "uncategorized")

            has_custom_config = "denied_suffixes" in case or "trusted_suffixes" in case
            if has_custom_config:
                continue

            if expected == "allowed":
                try:
                    policy.validate_url(url)
                except (RessrfBlockedError, ValueError) as e:
                    pytest.fail(
                        f"[{category}] {name}: expected allowed for {url!r}, got {e}"
                    )
            elif expected == "blocked":
                with pytest.raises((RessrfBlockedError, ValueError)):
                    policy.validate_url(url)
            else:
                pytest.fail(f"{name}: unknown expected value {expected!r}")


class TestUrlRules:
    """Test URL rules using shared vectors."""

    def test_all_vectors(self, url_rules_vectors: list[dict]) -> None:
        for case in url_rules_vectors:
            name = case["name"]
            preset = case.get("preset", "external_only")
            url = case["url"]
            expected = case["expected"]
            url_rules = case.get("url_rules", {})

            builder = PolicyBuilder(preset)

            for rule in url_rules.get("allow", []):
                builder.url_allow(
                    scheme=rule.get("scheme"),
                    host=rule.get("host"),
                    path=rule.get("path"),
                    regex=rule.get("regex"),
                    bypass_ip_check=rule.get("bypass_ip_check", False),
                )

            for rule in url_rules.get("deny", []):
                builder.url_deny(
                    scheme=rule.get("scheme"),
                    host=rule.get("host"),
                    path=rule.get("path"),
                    regex=rule.get("regex"),
                )

            policy = builder.build()

            if expected == "allowed":
                try:
                    policy.validate_url(url)
                except (RessrfBlockedError, ValueError) as e:
                    pytest.fail(f"{name}: expected allowed but got {e}")
            else:
                with pytest.raises((RessrfBlockedError, ValueError), match=".*"):
                    policy.validate_url(url)


class TestAuditEvents:
    """Test audit event generation using shared vectors."""

    def test_all_vectors(self, audit_event_vectors: list[dict]) -> None:
        for case in audit_event_vectors:
            name = case["name"]
            action = case["action"]
            config = case["config"]

            if action == "create_policy":
                is_no_sink = case.get("expected_event") is None

                if is_no_sink:
                    PolicyBuilder(config["preset"]).build()
                    continue

                events: list[AuditEvent] = []
                sink = AuditFunc(lambda e: events.append(e))

                builder = PolicyBuilder(config["preset"])
                for provider in config.get("cloud_modules", []):
                    builder.with_cloud(provider)
                builder.audit_sink(sink)
                builder.build()

                expected = case["expected_event"]
                variant = expected["variant"]
                assert variant == "PolicyCreated", f"{name}: expected PolicyCreated"
                assert len(events) >= 1, f"{name}: expected at least one audit event"

                created = [e for e in events if e.event_type == "policy_created"]
                assert len(created) >= 1, f"{name}: no policy_created event"

                fields = expected["fields"]
                assert created[0].fields["preset"] == fields["preset"], (
                    f"{name}: preset mismatch"
                )
                if "deny_count_min" in fields:
                    assert (
                        created[0].fields["deny_count"] >= fields["deny_count_min"]
                    ), f"{name}: deny_count too low"
                assert created[0].fields["allow_count"] == fields["allow_count"], (
                    f"{name}: allow_count mismatch"
                )

            elif action in (
                "validate_url",
                "validate_host",
                "connection_attempt",
                "redirect_intercepted",
            ):
                # These event types are not yet emitted by the core engine.
                pass
            else:
                pytest.fail(f"{name}: unknown action: {action}")


class TestRedirectChains:
    """Test redirect chain validation using shared vectors."""

    def test_all_vectors(self, redirect_chain_vectors: list[dict]) -> None:
        for case in redirect_chain_vectors:
            name = case["name"]
            chain = case["chain"]
            preset = case["policy_preset"]
            expected = case["expected"]
            max_redirects = case.get("max_redirects")
            allow_plaintext = case.get("allow_plaintext_http", False)

            builder = PolicyBuilder(preset)
            for cidr in case.get("allow_cidrs", []):
                builder.add_allowed([cidr])

            policy = builder.build()

            require_https = preset == "external_only" and not allow_plaintext
            limit = max_redirects if max_redirects is not None else float("inf")

            blocked_at = None
            for i in range(1, len(chain)):
                if i >= limit:
                    blocked_at = i
                    break

                url = chain[i]
                if require_https and url.startswith("http://"):
                    blocked_at = i
                    break

                try:
                    policy.validate_url(url)
                except (RessrfBlockedError, ValueError):
                    blocked_at = i
                    break

            if expected == "allowed":
                assert blocked_at is None, (
                    f"{name}: expected allowed, blocked at hop {blocked_at}"
                )
            elif expected == "blocked":
                expected_hop = case.get("blocked_at_hop")
                assert blocked_at is not None, f"{name}: expected blocked, got allowed"
                if expected_hop is not None:
                    assert blocked_at == expected_hop, (
                        f"{name}: expected blocked at hop {expected_hop}, "
                        f"got {blocked_at}"
                    )


class TestIpv4Ipv6Mapping:
    """Test IPv4-to-IPv6 mapping normalization using shared vectors."""

    def test_all_vectors(self, ipv4_ipv6_mapping_vectors: list[dict]) -> None:
        for case in ipv4_ipv6_mapping_vectors:
            name = case["name"]
            ipv4 = case["ipv4"]
            ipv6_mapped = case["ipv6_mapped"]
            cidr = case["cidr"]
            both_contained = case["both_contained"]

            ipv4_result = cidr_contains(cidr, ipv4)
            assert ipv4_result == both_contained, (
                f"{name}: cidr_contains({cidr!r}, {ipv4!r}) = {ipv4_result}, "
                f"expected {both_contained}"
            )

            ipv6_result = cidr_contains(cidr, ipv6_mapped)
            assert ipv6_result == both_contained, (
                f"{name}: cidr_contains({cidr!r}, {ipv6_mapped!r}) = {ipv6_result}, "
                f"expected {both_contained}"
            )
