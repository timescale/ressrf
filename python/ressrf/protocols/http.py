"""SSRF-safe HTTP transport adapters for httpx and requests.

All adapters intercept DNS resolution and validate resolved IPs against
the SSRF policy before allowing connections. Redirect targets are
re-validated per hop.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ressrf.policy import Policy

from ressrf.errors import RessrfBlockedError
from ressrf.protocols.tcp import safe_getaddrinfo

_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def _validate_redirect(policy: Policy, url: str) -> None:
    """Re-validate a redirect target URL through the policy."""
    parsed = urlparse(url)
    if parsed.scheme == "http":
        raise RessrfBlockedError(
            f"HTTPS downgrade detected in redirect to {url}",
            reason={"type": "redirect_scheme_downgrade", "to": url},
        )
    if parsed.hostname:
        addrs = _ORIGINAL_GETADDRINFO(
            parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
        )
        ips = [str(info[4][0]) for info in addrs]
        policy.is_network_allowed(list(set(ips)))


# ---------------------------------------------------------------------------
# httpx adapters
# ---------------------------------------------------------------------------

try:
    import httpx

    class SafeTransport(httpx.HTTPTransport):
        """httpx sync transport that validates connections through SSRF policy.

        Example:
            policy = Policy.external_only(cloud=["aws"])
            transport = SafeTransport(policy)
            client = httpx.Client(transport=transport)
            response = client.get("https://example.com")
        """

        def __init__(self, policy: Policy, **kwargs: Any) -> None:
            self._policy = policy
            super().__init__(**kwargs)

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            host = request.url.host
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            if host:
                safe_getaddrinfo(self._policy, host, port, type_=socket.SOCK_STREAM)
            return super().handle_request(request)

    class AsyncSafeTransport(httpx.AsyncHTTPTransport):
        """httpx async transport that validates connections through SSRF policy.

        Example:
            policy = Policy.external_only(cloud=["aws"])
            transport = AsyncSafeTransport(policy)
            async with httpx.AsyncClient(transport=transport) as client:
                response = await client.get("https://example.com")
        """

        def __init__(self, policy: Policy, **kwargs: Any) -> None:
            self._policy = policy
            super().__init__(**kwargs)

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            host = request.url.host
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            if host:
                safe_getaddrinfo(self._policy, host, port, type_=socket.SOCK_STREAM)
            return await super().handle_async_request(request)

    def httpx_client(
        policy: Policy, *, max_redirects: int = 10, **kwargs: Any
    ) -> httpx.Client:
        """Create an httpx.Client with SSRF protection.

        Validates DNS resolution and re-validates redirect targets per hop.
        """
        transport = SafeTransport(policy)

        def _event_hook_response(response: httpx.Response) -> None:
            if response.is_redirect and response.has_redirect_location:
                location = str(response.headers.get("location", ""))
                if location:
                    _validate_redirect(
                        policy,
                        str(response.next_request.url)
                        if response.next_request
                        else location,
                    )

        event_hooks: dict[str, list] = {"response": [_event_hook_response]}
        return httpx.Client(
            transport=transport,
            max_redirects=max_redirects,
            event_hooks=event_hooks,
            **kwargs,
        )

    __all_httpx__ = ["AsyncSafeTransport", "SafeTransport", "httpx_client"]

except ImportError:
    __all_httpx__ = []

# ---------------------------------------------------------------------------
# requests adapter
# ---------------------------------------------------------------------------

try:
    import requests
    from requests.adapters import HTTPAdapter

    class SafeAdapter(HTTPAdapter):
        """requests HTTPAdapter with SSRF policy validation.

        Example:
            policy = Policy.external_only()
            session = requests.Session()
            session.mount("https://", SafeAdapter(policy))
            session.mount("http://", SafeAdapter(policy))
            response = session.get("https://example.com")
        """

        def __init__(self, policy: Policy, **kwargs: Any) -> None:
            self._policy = policy
            super().__init__(**kwargs)

        def send(
            self, request: requests.PreparedRequest, **kwargs: Any
        ) -> requests.Response:
            parsed = urlparse(request.url or "")
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if host:
                safe_getaddrinfo(self._policy, host, port, type_=socket.SOCK_STREAM)
            return super().send(request, **kwargs)

    def requests_session(
        policy: Policy, *, max_redirects: int = 10
    ) -> requests.Session:
        """Create a requests.Session with SSRF protection.

        Validates DNS resolution before connecting. Redirect targets are
        re-validated per hop via the session's hook mechanism.
        """
        session = requests.Session()
        adapter = SafeAdapter(policy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.max_redirects = max_redirects

        def _check_redirect(response: requests.Response, *args: Any, **kw: Any) -> None:
            if response.is_redirect:
                location = response.headers.get("location", "")
                if location:
                    _validate_redirect(policy, location)

        session.hooks["response"].append(_check_redirect)
        return session

    __all_requests__ = ["SafeAdapter", "requests_session"]

except ImportError:
    __all_requests__ = []


__all__ = [*__all_httpx__, *__all_requests__, "_validate_redirect"]
