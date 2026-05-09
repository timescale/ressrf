"""Unit tests for the Policy and PolicyBuilder wrappers."""

from __future__ import annotations

import pytest

from ressrf.errors import RessrfBlockedError
from ressrf.policy import Policy, PolicyBuilder


class TestPolicyBuilder:
    def test_external_only_blocks_private(self) -> None:
        policy = PolicyBuilder("external_only").build()
        with pytest.raises(RessrfBlockedError):
            policy.is_network_allowed(["10.0.0.1"])

    def test_external_only_allows_public(self) -> None:
        policy = PolicyBuilder("external_only").build()
        policy.is_network_allowed(["8.8.8.8"])

    def test_none_allows_everything(self) -> None:
        policy = PolicyBuilder("none").build()
        policy.is_network_allowed(["10.0.0.1"])
        policy.is_network_allowed(["127.0.0.1"])

    def test_internal_only_blocks_all_without_allowlist(self) -> None:
        policy = PolicyBuilder("internal_only").build()
        with pytest.raises(RessrfBlockedError):
            policy.is_network_allowed(["8.8.8.8"])

    def test_internal_only_with_allowlist(self) -> None:
        policy = PolicyBuilder("internal_only").add_allowed(["8.8.8.0/24"]).build()
        policy.is_network_allowed(["8.8.8.8"])

    def test_add_denied_blocks_ip(self) -> None:
        policy = PolicyBuilder("external_only").add_denied(["1.2.3.0/24"]).build()
        with pytest.raises(RessrfBlockedError):
            policy.is_network_allowed(["1.2.3.4"])

    def test_allow_overrides_deny(self) -> None:
        policy = PolicyBuilder("external_only").add_allowed(["10.0.0.5/32"]).build()
        policy.is_network_allowed(["10.0.0.5"])

    def test_cloud_provider_blocks_imds(self) -> None:
        policy = PolicyBuilder("external_only").with_cloud("aws").build()
        with pytest.raises(RessrfBlockedError):
            policy.is_network_allowed(["169.254.169.254"])

    def test_invalid_preset_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown preset"):
            PolicyBuilder("bogus")

    def test_builder_consumed_after_build(self) -> None:
        builder = PolicyBuilder("none")
        builder.build()
        with pytest.raises(ValueError, match="already consumed"):
            builder.build()


class TestPolicyFactories:
    def test_external_only_factory(self) -> None:
        policy = Policy.external_only(cloud=["aws"])
        with pytest.raises(RessrfBlockedError):
            policy.is_network_allowed(["10.0.0.1"])

    def test_internal_only_factory(self) -> None:
        policy = Policy.internal_only(allowed=["8.8.8.0/24"])
        policy.is_network_allowed(["8.8.8.8"])

    def test_permissive_factory(self) -> None:
        policy = Policy.permissive()
        policy.is_network_allowed(["10.0.0.1"])

    def test_preset_property(self) -> None:
        assert Policy.external_only().preset == "external_only"
        assert Policy.internal_only().preset == "internal_only"
        assert Policy.permissive().preset == "none"


class TestUrlValidation:
    def test_allows_public_https(self) -> None:
        policy = Policy.external_only()
        policy.validate_url("https://example.com")

    def test_blocks_private_ip_url(self) -> None:
        policy = Policy.external_only()
        with pytest.raises(RessrfBlockedError):
            policy.validate_url("https://10.0.0.1/path")

    def test_blocks_loopback_url(self) -> None:
        policy = Policy.external_only()
        with pytest.raises(RessrfBlockedError):
            policy.validate_url("https://127.0.0.1")


class TestErrorStructure:
    def test_blocked_error_has_reason(self) -> None:
        policy = Policy.external_only()
        with pytest.raises(RessrfBlockedError) as exc_info:
            policy.is_network_allowed(["10.0.0.1"])
        assert exc_info.value.reason
        assert exc_info.value.is_blocked()

    def test_blocked_error_reason_is_dict(self) -> None:
        policy = Policy.external_only()
        with pytest.raises(RessrfBlockedError) as exc_info:
            policy.is_network_allowed(["10.0.0.1"])
        reason = exc_info.value.reason
        assert isinstance(reason, dict)
        assert "type" in reason
