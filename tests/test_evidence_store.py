import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
import unittest

from kai_security.evidence.store import InMemoryEvidenceStore
from kai_security.models import AuditEvent


class EvidenceStoreTests(unittest.TestCase):
    def _make_event(self, timestamp: datetime | None = None) -> AuditEvent:
        return AuditEvent(
            event_type="request_received",
            request_id="request-1",
            timestamp=timestamp or datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
            payload={"user_id": "alice", "action": "read"},
        )

    def _expected_event_hash(self, event: AuditEvent) -> str:
        canonical = {
            "event_id": event.event_id,
            "request_id": event.request_id,
            "timestamp": self._normalize_timestamp(event.timestamp),
            "event_type": event.event_type,
            "payload": event.payload,
            "previous_hash": event.previous_hash,
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _normalize_timestamp(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()

    def test_append_fills_previous_hash_and_event_hash(self) -> None:
        store = InMemoryEvidenceStore()
        first = store.append(self._make_event(datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC)))
        second = store.append(
            AuditEvent(
                event_type="request_analyzed",
                request_id="request-1",
                timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                payload={"risk": 0.2},
            )
        )

        self.assertEqual(first.previous_hash, "")
        self.assertNotEqual(first.event_hash, "")
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertNotEqual(second.event_hash, "")
        self.assertNotEqual(first.event_hash, second.event_hash)
        self.assertEqual(second.event_hash, self._expected_event_hash(second))

        all_events = store.list_events()
        self.assertEqual(len(all_events), 2)
        self.assertEqual(store.count_events(), 2)

    def test_list_events_returns_copy(self) -> None:
        store = InMemoryEvidenceStore()
        store.append(self._make_event())

        events = store.list_events()
        events.clear()

        self.assertEqual(len(store.list_events()), 1)

    def test_list_events_filters_and_limits(self) -> None:
        store = InMemoryEvidenceStore()
        store.append(
            AuditEvent(
                event_type="request_received",
                request_id="r1",
                timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                payload={"user_id": "alice", "action": "read"},
            )
        )
        store.append(
            AuditEvent(
                event_type="request_analyzed",
                request_id="r1",
                timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                payload={"risk": 0.2},
            )
        )
        store.append(
            AuditEvent(
                event_type="request_received",
                request_id="r2",
                timestamp=datetime(2026, 6, 5, 1, 2, 5, tzinfo=UTC),
                payload={"user_id": "alice", "action": "read"},
            )
        )

        self.assertEqual(len(store.list_events(event_type="request_analyzed")), 1)
        self.assertEqual(len(store.list_events(request_id="r1", event_type="request_analyzed")), 1)
        self.assertEqual(len(store.list_events(limit=1)), 1)
        self.assertEqual(len(store.list_events(request_id="r1", limit=1)), 1)

    def test_list_events_does_not_expose_payload_mutation(self) -> None:
        store = InMemoryEvidenceStore()
        store.append(
            AuditEvent(
                event_type="request_received",
                request_id="request-1",
                timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                payload={"nested": {"value": "safe"}},
            )
        )
        returned = store.list_events()

        returned[0].payload["nested"]["value"] = "tampered"

        self.assertEqual(store.list_events()[0].payload["nested"]["value"], "safe")
        self.assertTrue(store.verify_chain())

    def test_append_does_not_retain_caller_payload_reference(self) -> None:
        store = InMemoryEvidenceStore()
        payload = {"nested": {"value": "safe"}}
        store.append(
            AuditEvent(
                event_type="request_received",
                request_id="request-1",
                timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                payload=payload,
            )
        )

        payload["nested"]["value"] = "tampered"

        self.assertEqual(store.list_events()[0].payload["nested"]["value"], "safe")
        self.assertTrue(store.verify_chain())

    def test_verify_chain_detects_payload_tamper(self) -> None:
        store = InMemoryEvidenceStore()
        store.append(self._make_event())
        store.append(
            AuditEvent(
                event_type="request_analyzed",
                request_id="request-1",
                timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                payload={"risk": 0.2},
            )
        )

        tampered = replace(store.list_events()[1], payload={"risk": 0.9})
        store._events[1] = tampered

        self.assertFalse(store.verify_chain())

    def test_verify_chain_detects_reordered_events(self) -> None:
        store = InMemoryEvidenceStore()
        store.append(self._make_event(datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC)))
        store.append(
            AuditEvent(
                event_type="request_analyzed",
                request_id="request-1",
                timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                payload={"risk": 0.2},
            )
        )
        store.append(
            AuditEvent(
                event_type="policy_decided",
                request_id="request-1",
                timestamp=datetime(2026, 6, 5, 1, 2, 5, tzinfo=UTC),
                payload={"action": "allow"},
            )
        )

        store._events[0], store._events[1] = store._events[1], store._events[0]

        self.assertFalse(store.verify_chain())


if __name__ == "__main__":
    unittest.main()
