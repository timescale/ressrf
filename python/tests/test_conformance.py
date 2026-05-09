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
