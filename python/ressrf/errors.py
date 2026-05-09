"""SSRF policy error types."""

from __future__ import annotations

import json
from typing import Any

from ressrf._core import RessrfBlockedError as _CoreBlockedError


class RessrfBlockedError(Exception):
    """Raised when a request is blocked by the SSRF policy.

    Attributes:
        reason: A dict describing why the request was blocked (structured DenyReason).
        message: Human-readable description of the denial.
    """

    def __init__(self, message: str, reason: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason or {}

    def is_blocked(self) -> bool:
        """Always returns True for this exception type."""
        return True

    @classmethod
    def _from_core(cls, err: _CoreBlockedError) -> RessrfBlockedError:
        """Convert a native _core.RessrfBlockedError into the Python-level error."""
        raw = str(err)
        try:
            reason = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            reason = {"type": "unknown", "detail": raw}
        return cls(raw, reason=reason)


__all__ = ["RessrfBlockedError"]
