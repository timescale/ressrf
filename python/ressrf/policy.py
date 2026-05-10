"""Pythonic SSRF policy builder and validator."""

from __future__ import annotations

from typing import Callable, Sequence

from ressrf._core import CorePolicy, CorePolicyBuilder
from ressrf._core import RessrfBlockedError as _CoreBlockedError
from ressrf.audit import AuditEvent, AuditSink
from ressrf.errors import RessrfBlockedError


class Policy:
    """Immutable SSRF policy that validates URLs and network addresses.

    Use PolicyBuilder or the factory class methods to create instances.

    Example:
        policy = Policy.external_only(cloud=["aws", "gcp"])
        policy.validate_url("https://example.com")  # OK
        policy.is_network_allowed(["10.0.0.1"])  # raises RessrfBlockedError
    """

    def __init__(self, core: CorePolicy) -> None:
        self._core = core

    @classmethod
    def external_only(
        cls,
        *,
        cloud: Sequence[str] | None = None,
        denied: Sequence[str] | None = None,
        allowed: Sequence[str] | None = None,
        audit_sink: AuditSink | Callable[[AuditEvent], None] | None = None,
    ) -> Policy:
        """Create a policy that denies known internal/metadata ranges."""
        builder = PolicyBuilder("external_only")
        for provider in cloud or []:
            builder.with_cloud(provider)
        if denied:
            builder.add_denied(list(denied))
        if allowed:
            builder.add_allowed(list(allowed))
        if audit_sink is not None:
            builder.audit_sink(audit_sink)
        return builder.build()

    @classmethod
    def internal_only(
        cls,
        *,
        allowed: Sequence[str] | None = None,
        audit_sink: AuditSink | Callable[[AuditEvent], None] | None = None,
    ) -> Policy:
        """Create a default-deny policy where only allow-listed IPs pass."""
        builder = PolicyBuilder("internal_only")
        if allowed:
            builder.add_allowed(list(allowed))
        if audit_sink is not None:
            builder.audit_sink(audit_sink)
        return builder.build()

    @classmethod
    def permissive(
        cls,
        *,
        audit_sink: AuditSink | Callable[[AuditEvent], None] | None = None,
    ) -> Policy:
        """Create a policy with no restrictions (audit-only mode)."""
        builder = PolicyBuilder("none")
        if audit_sink is not None:
            builder.audit_sink(audit_sink)
        return builder.build()

    def is_network_allowed(self, ips: list[str]) -> None:
        """Validate that all IPs are allowed by the policy.

        Raises RessrfBlockedError if any IP is denied.
        Returns None if all IPs are allowed.
        """
        try:
            self._core.is_network_allowed(ips)
        except _CoreBlockedError as e:
            raise RessrfBlockedError._from_core(e) from None

    def validate_url(self, url: str) -> None:
        """Validate a URL against the policy (scheme, host, IP checks).

        Raises RessrfBlockedError if the URL is denied.
        Returns None if the URL is allowed.
        """
        try:
            self._core.validate_url(url)
        except _CoreBlockedError as e:
            raise RessrfBlockedError._from_core(e) from None

    @property
    def preset(self) -> str:
        """The preset name used to create this policy."""
        return self._core.preset()


class PolicyBuilder:
    """Fluent builder for constructing an immutable Policy.

    Example:
        policy = (
            PolicyBuilder("external_only")
            .with_cloud("aws")
            .add_denied(["10.0.0.0/8"])
            .add_allowed(["10.0.0.5/32"])
            .build()
        )
    """

    def __init__(self, preset: str = "external_only") -> None:
        self._builder = CorePolicyBuilder(preset)
        self._audit_sink: AuditSink | Callable[[AuditEvent], None] | None = None

    def add_denied(self, cidrs: list[str]) -> PolicyBuilder:
        """Add CIDRs to the deny list."""
        self._builder.add_denied(cidrs)
        return self

    def add_allowed(self, cidrs: list[str]) -> PolicyBuilder:
        """Add CIDRs to the allow list (allow overrides deny)."""
        self._builder.add_allowed(cidrs)
        return self

    def header_rules(
        self,
        *,
        required: list[str] | None = None,
        denied: list[str] | None = None,
        auto_xff: bool = False,
    ) -> PolicyBuilder:
        """Configure header validation rules."""
        self._builder.header_rules(required=required, denied=denied, auto_xff=auto_xff)
        return self

    def protocol_rules(
        self,
        *,
        allow_plaintext_http: bool = False,
        require_https: bool = True,
    ) -> PolicyBuilder:
        """Configure protocol-level rules."""
        self._builder.protocol_rules(
            allow_plaintext_http=allow_plaintext_http,
            require_https=require_https,
        )
        return self

    def with_cloud(self, name: str) -> PolicyBuilder:
        """Add a cloud provider's deny ranges (aws, azure, gcp)."""
        self._builder.with_cloud(name)
        return self

    def url_allow(
        self,
        *,
        scheme: str | None = None,
        host: str | None = None,
        path: str | None = None,
        regex: str | None = None,
        bypass_ip_check: bool = False,
    ) -> PolicyBuilder:
        """Add a URL allow rule with glob patterns or regex."""
        self._builder.url_allow(
            scheme=scheme,
            host=host,
            path=path,
            regex=regex,
            bypass_ip_check=bypass_ip_check,
        )
        return self

    def url_deny(
        self,
        *,
        scheme: str | None = None,
        host: str | None = None,
        path: str | None = None,
        regex: str | None = None,
    ) -> PolicyBuilder:
        """Add a URL deny rule with glob patterns or regex."""
        self._builder.url_deny(scheme=scheme, host=host, path=path, regex=regex)
        return self

    def audit_sink(
        self, sink: AuditSink | Callable[[AuditEvent], None]
    ) -> PolicyBuilder:
        """Set the audit sink for policy events."""
        self._audit_sink = sink
        return self

    def build(self) -> Policy:
        """Build the immutable policy. The builder cannot be reused after this."""
        if self._audit_sink is not None:
            sink = self._audit_sink

            def _bridge(json_str: str) -> None:
                event = AuditEvent.from_json(json_str)
                if isinstance(sink, AuditSink):
                    sink.emit(event)
                else:
                    sink(event)

            self._builder.audit_sink(_bridge)
        core = self._builder.build()
        return Policy(core)


__all__ = ["Policy", "PolicyBuilder"]
