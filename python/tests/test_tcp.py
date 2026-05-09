"""Tests for the TCP protocol module."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from ressrf.errors import RessrfBlockedError
from ressrf.policy import Policy
from ressrf.protocols.tcp import create_connection, safe_getaddrinfo


class TestSafeGetaddrinfo:
    def test_blocks_private_ip(self) -> None:
        policy = Policy.external_only()
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 80))]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            with pytest.raises(RessrfBlockedError):
                safe_getaddrinfo(policy, "evil.com", 80)

    def test_allows_public_ip(self) -> None:
        policy = Policy.external_only()
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            result = safe_getaddrinfo(policy, "dns.google", 443)
            assert len(result) == 1
            assert result[0][4] == ("8.8.8.8", 443)

    def test_filters_mixed_results(self) -> None:
        policy = Policy.external_only()
        fake_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80)),
        ]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            result = safe_getaddrinfo(policy, "example.com", 80)
            assert len(result) == 1
            assert result[0][4] == ("93.184.216.34", 80)

    def test_blocks_loopback(self) -> None:
        policy = Policy.external_only()
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            with pytest.raises(RessrfBlockedError):
                safe_getaddrinfo(policy, "localhost", 80)

    def test_blocks_imds(self) -> None:
        policy = Policy.external_only()
        fake_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 80))
        ]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            with pytest.raises(RessrfBlockedError):
                safe_getaddrinfo(policy, "metadata.internal", 80)


class TestCreateConnection:
    def test_blocks_private_target(self) -> None:
        policy = Policy.external_only()
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 22))]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            with pytest.raises(RessrfBlockedError):
                create_connection(policy, ("internal.host", 22))

    def test_permissive_allows_private(self) -> None:
        policy = Policy.permissive()
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 22))]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            with patch("socket.socket") as mock_socket:
                instance = mock_socket.return_value
                instance.connect = lambda addr: None
                sock = create_connection(policy, ("internal.host", 22))
                assert sock is instance
