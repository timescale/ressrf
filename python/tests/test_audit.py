"""Tests for the audit module."""

from __future__ import annotations

from ressrf.audit import AuditEvent, AuditFunc, AuditSink, DiscardSink, MultiSink
from ressrf.policy import Policy


class TestAuditEvent:
    def test_from_json(self) -> None:
        raw = '{"event_type": "host_validated", "host": "example.com", "allowed": true}'
        event = AuditEvent.from_json(raw)
        assert event.event_type == "host_validated"
        assert event.fields["host"] == "example.com"
        assert event.fields["allowed"] is True

    def test_frozen(self) -> None:
        event = AuditEvent(event_type="test", fields={"key": "value"})
        import dataclasses

        assert dataclasses.is_dataclass(event)


class TestAuditFunc:
    def test_receives_events(self) -> None:
        events: list[AuditEvent] = []
        sink = AuditFunc(lambda e: events.append(e))

        event = AuditEvent(event_type="test", fields={})
        sink.emit(event)

        assert len(events) == 1
        assert events[0].event_type == "test"

    def test_satisfies_protocol(self) -> None:
        sink = AuditFunc(lambda e: None)
        assert isinstance(sink, AuditSink)


class TestMultiSink:
    def test_fans_out(self) -> None:
        events1: list[AuditEvent] = []
        events2: list[AuditEvent] = []
        multi = MultiSink(
            AuditFunc(lambda e: events1.append(e)),
            AuditFunc(lambda e: events2.append(e)),
        )

        event = AuditEvent(event_type="test", fields={})
        multi.emit(event)

        assert len(events1) == 1
        assert len(events2) == 1


class TestDiscardSink:
    def test_does_not_raise(self) -> None:
        sink = DiscardSink()
        event = AuditEvent(event_type="test", fields={})
        sink.emit(event)


class TestAuditIntegration:
    def test_policy_emits_audit_events(self) -> None:
        events: list[AuditEvent] = []
        sink = AuditFunc(lambda e: events.append(e))
        Policy.external_only(audit_sink=sink)

        assert len(events) >= 1
        assert any(e.event_type == "policy_created" for e in events)

    def test_policy_created_event_has_fields(self) -> None:
        events: list[AuditEvent] = []
        sink = AuditFunc(lambda e: events.append(e))
        Policy.external_only(audit_sink=sink)

        created = [e for e in events if e.event_type == "policy_created"]
        assert len(created) == 1
        assert "deny_count" in created[0].fields
        assert "allow_count" in created[0].fields
