"""Tests for the HTTP protocol module."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from ressrf.errors import RessrfBlockedError
from ressrf.policy import Policy
from ressrf.protocols.http import _validate_redirect


class TestValidateRedirect:
    def test_blocks_http_downgrade(self) -> None:
        policy = Policy.external_only()
        with pytest.raises(RessrfBlockedError, match="downgrade"):
            _validate_redirect(policy, "http://example.com/path")

    def test_allows_https_redirect(self) -> None:
        fake_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))
        ]
        policy = Policy.external_only()
        with patch(
            "ressrf.protocols.http._ORIGINAL_GETADDRINFO", return_value=fake_result
        ):
            _validate_redirect(policy, "https://example.com/path")

    def test_blocks_redirect_to_private_ip(self) -> None:
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 443))]
        policy = Policy.external_only()
        with patch(
            "ressrf.protocols.http._ORIGINAL_GETADDRINFO", return_value=fake_result
        ):
            with pytest.raises(RessrfBlockedError):
                _validate_redirect(policy, "https://internal.corp/path")


class TestHttpxIntegration:
    """Tests requiring httpx (skipped if not installed)."""

    @pytest.fixture(autouse=True)
    def _require_httpx(self) -> None:
        pytest.importorskip("httpx")

    def test_safe_transport_blocks_private(self) -> None:
        from ressrf.protocols.http import SafeTransport

        policy = Policy.external_only()
        transport = SafeTransport(policy)
        assert transport is not None

    def test_httpx_client_creation(self) -> None:
        from ressrf.protocols.http import httpx_client

        policy = Policy.external_only()
        client = httpx_client(policy)
        assert client is not None
        client.close()


class TestRequestsIntegration:
    """Tests requiring requests (skipped if not installed)."""

    @pytest.fixture(autouse=True)
    def _require_requests(self) -> None:
        pytest.importorskip("requests")

    def test_safe_adapter_creation(self) -> None:
        from ressrf.protocols.http import SafeAdapter

        policy = Policy.external_only()
        adapter = SafeAdapter(policy)
        assert adapter is not None

    def test_requests_session_creation(self) -> None:
        from ressrf.protocols.http import requests_session

        policy = Policy.external_only()
        session = requests_session(policy)
        assert session is not None
        session.close()
