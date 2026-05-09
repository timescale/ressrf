"""Audit event types and sink protocol."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable


@dataclass(frozen=True)
class AuditEvent:
    """Structured audit event emitted by the policy engine.

    Attributes:
        event_type: The kind of event (e.g. 'host_validated', 'url_validated').
        fields: All event fields as a dict.
    """

    event_type: str
    fields: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, raw: str) -> AuditEvent:
        """Parse a JSON string into an AuditEvent."""
        data = json.loads(raw)
        event_type = data.pop("event_type", "unknown")
        return cls(event_type=event_type, fields=data)


@runtime_checkable
class AuditSink(Protocol):
    """Protocol for receiving audit events from the policy engine.

    Implement this to route audit events to your logging system.

    Example with logging:

        class LoggingSink:
            def emit(self, event: AuditEvent) -> None:
                logging.info("ressrf.audit", extra={"event": event.fields})

    Example with structlog:

        class StructlogSink:
            def emit(self, event: AuditEvent) -> None:
                structlog.get_logger().info("ressrf.audit", **event.fields)
    """

    def emit(self, event: AuditEvent) -> None: ...


class AuditFunc:
    """Adapts a plain callable to the AuditSink protocol.

    Example:
        sink = AuditFunc(lambda e: print(f"blocked: {e.event_type}"))
    """

    def __init__(self, func: Callable[[AuditEvent], None]) -> None:
        self._func = func

    def emit(self, event: AuditEvent) -> None:
        self._func(event)


class MultiSink:
    """Fans out audit events to multiple sinks."""

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = list(sinks)

    def emit(self, event: AuditEvent) -> None:
        for sink in self._sinks:
            sink.emit(event)


class DiscardSink:
    """Silently drops all events."""

    def emit(self, event: AuditEvent) -> None:
        pass


__all__ = ["AuditEvent", "AuditFunc", "AuditSink", "DiscardSink", "MultiSink"]
