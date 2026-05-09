"""Tests for the SSH protocol module."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from ressrf.errors import RessrfBlockedError
from ressrf.policy import Policy


class TestSshConnect:
    @pytest.fixture(autouse=True)
    def _require_paramiko(self) -> None:
        pytest.importorskip("paramiko")

    def test_blocks_private_ssh_target(self) -> None:
        from ressrf.protocols.ssh import safe_ssh_connect

        policy = Policy.external_only()
        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 22))]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            with pytest.raises(RessrfBlockedError):
                safe_ssh_connect(policy, "internal.host", 22)

    def test_blocks_imds_ssh_target(self) -> None:
        from ressrf.protocols.ssh import safe_ssh_connect

        policy = Policy.external_only()
        fake_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 22))
        ]
        with patch("ressrf.protocols.tcp.socket.getaddrinfo", return_value=fake_result):
            with pytest.raises(RessrfBlockedError):
                safe_ssh_connect(policy, "metadata.internal", 22)
