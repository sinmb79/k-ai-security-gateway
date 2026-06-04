"""Tamper-evident audit evidence store.

Worker-owned implementation target.
"""

from __future__ import annotations

from kai_security.models import AuditEvent


class InMemoryEvidenceStore:
    """Append-only in-memory event store used for local MVP tests."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    def list_events(self, request_id: str | None = None) -> list[AuditEvent]:
        if request_id is None:
            return list(self._events)
        return [event for event in self._events if event.request_id == request_id]

    def verify_chain(self) -> bool:
        return True

