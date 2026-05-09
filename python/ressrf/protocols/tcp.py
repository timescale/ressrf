"""SSRF-safe TCP connection utilities.

Wraps socket.getaddrinfo and socket.create_connection with policy validation,
ensuring all resolved IP addresses pass the SSRF policy before connecting.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ressrf.policy import Policy

from ressrf.errors import RessrfBlockedError


def safe_getaddrinfo(
    policy: Policy,
    host: str,
    port: int | str | None,
    family: int = socket.AF_UNSPEC,
    type_: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple]]:  # type: ignore[type-arg]
    """Resolve a host and filter results through the SSRF policy.

    Returns only address info entries whose IPs are allowed by the policy.
    Raises RessrfBlockedError if all resolved IPs are denied.
    """
    results = socket.getaddrinfo(host, port, family, type_, proto, flags)
    if not results:
        return results

    allowed = []
    for info in results:
        addr = info[4]
        ip = str(addr[0])
        try:
            policy.is_network_allowed([ip])
            allowed.append(info)
        except RessrfBlockedError:
            continue

    if not allowed:
        all_ips = [info[4][0] for info in results]
        raise RessrfBlockedError(
            f"all resolved IPs denied for {host}: {all_ips}",
            reason={"type": "all_resolved_ips_denied", "host": host, "ips": all_ips},
        )

    return allowed


def create_connection(
    policy: Policy,
    address: tuple[str, int],
    timeout: float | None = 30.0,
    source_address: tuple[str, int] | None = None,
) -> socket.socket:
    """Create a TCP connection after validating the target through the SSRF policy.

    Resolves the hostname, validates all IPs against the policy, and connects
    only to allowed addresses.

    Args:
        policy: The SSRF policy to validate against.
        address: (host, port) tuple to connect to.
        timeout: Connection timeout in seconds (default 30s).
        source_address: Optional (host, port) to bind to before connecting.

    Returns:
        A connected socket.

    Raises:
        RessrfBlockedError: If all resolved IPs are denied by the policy.
        OSError: If the connection fails after policy validation passes.
    """
    host, port = address

    allowed_addrs = safe_getaddrinfo(policy, host, port, type_=socket.SOCK_STREAM)

    last_err: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in allowed_addrs:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            if timeout is not None:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            last_err = e
            if sock is not None:
                sock.close()

    if last_err is not None:
        raise last_err
    raise OSError(f"could not connect to {host}:{port}")


__all__ = ["create_connection", "safe_getaddrinfo"]
