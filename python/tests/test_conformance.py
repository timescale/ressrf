"""Cross-language conformance tests using shared JSON vectors."""

from __future__ import annotations

import pytest

from ressrf._core import cidr_contains
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
