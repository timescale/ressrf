"""SSRF-safe SSH connection utilities.

Validates the target host/IP through the SSRF policy before establishing
an SSH connection via paramiko.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ressrf.policy import Policy

from ressrf.protocols.tcp import create_connection

try:
    import paramiko

    def safe_ssh_connect(
        policy: Policy,
        host: str,
        port: int = 22,
        *,
        timeout: float | None = 30.0,
        **ssh_kwargs: Any,
    ) -> paramiko.SSHClient:
        """Establish an SSH connection after SSRF policy validation.

        Resolves and validates the target address through the policy, then
        creates a TCP socket and hands it to paramiko for the SSH handshake.

        Args:
            policy: The SSRF policy to validate against.
            host: SSH server hostname or IP.
            port: SSH server port (default 22).
            timeout: Connection timeout in seconds.
            **ssh_kwargs: Additional kwargs passed to paramiko.SSHClient.connect()
                (e.g. username, password, pkey, look_for_keys, allow_agent).

        Returns:
            A connected paramiko.SSHClient.

        Raises:
            RessrfBlockedError: If the target is denied by the policy.
            paramiko.SSHException: If the SSH handshake fails.
        """
        sock = create_connection(policy, (host, port), timeout=timeout)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            port=port,
            sock=sock,
            timeout=timeout,
            **ssh_kwargs,
        )
        return client

    __all__ = ["safe_ssh_connect"]

except ImportError:
    __all__ = []
