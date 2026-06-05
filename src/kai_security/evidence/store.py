"""Tamper-evident audit evidence store.

Worker-owned implementation target.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

from kai_security.models import AuditEvent


class InMemoryEvidenceStore:
    """Append-only in-memory event store used for local MVP tests."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> AuditEvent:
        previous_hash = self._events[-1].event_hash if self._events else ""
        payload = deepcopy(event.payload)
        hashed_event = replace(
            event,
            payload=payload,
            previous_hash=previous_hash,
            event_hash=self._compute_event_hash(
                AuditEvent(
                    event_type=event.event_type,
                    request_id=event.request_id,
                    timestamp=event.timestamp,
                    payload=payload,
                    event_id=event.event_id,
                    previous_hash=previous_hash,
                )
            ),
        )

        self._events.append(hashed_event)
        return hashed_event

    def list_events(
        self,
        request_id: str | None = None,
        event_type: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        if limit is not None and limit <= 0:
            return []
        events = self._events
        if request_id is not None:
            events = [event for event in events if event.request_id == request_id]
        if event_type is not None:
            events = [event for event in events if event.event_type == event_type]
        if limit is not None:
            events = events[:limit]
        return [replace(event, payload=deepcopy(event.payload)) for event in events]

    def count_events(self) -> int:
        return len(self._events)

    def verify_chain(self) -> bool:
        for i, event in enumerate(self._events):
            expected_previous = "" if i == 0 else self._events[i - 1].event_hash
            if event.previous_hash != expected_previous:
                return False
            if event.event_hash != self._compute_event_hash(event):
                return False
        return True

    def _compute_event_hash(self, event: AuditEvent) -> str:
        message = {
            "event_id": event.event_id,
            "request_id": event.request_id,
            "timestamp": self._normalize_timestamp(event.timestamp),
            "event_type": event.event_type,
            "payload": event.payload,
            "previous_hash": event.previous_hash,
        }
        payload = json.dumps(message, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _normalize_timestamp(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()
