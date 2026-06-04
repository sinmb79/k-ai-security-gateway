import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from kai_security.evidence.sqlite_store import SQLiteEvidenceStore
from kai_security.evidence.store import InMemoryEvidenceStore
from kai_security.models import AuditEvent


class SQLiteEvidenceStoreTests(unittest.TestCase):
    def _make_event(
        self,
        *,
        event_type: str,
        request_id: str,
        timestamp: datetime,
        event_id: str | None = None,
    ) -> AuditEvent:
        data: dict[str, object] = {
            "event_type": event_type,
            "request_id": request_id,
            "timestamp": timestamp,
            "payload": {"nested": {"value": "safe"}},
        }
        if event_id is not None:
            data["event_id"] = event_id
        return AuditEvent(**data)

    def test_append_fills_previous_hash_and_event_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "evidence.sqlite3"
            with SQLiteEvidenceStore(str(db_path)) as store:
                first = store.append(
                    AuditEvent(
                        event_type="request_received",
                        request_id="request-1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                        payload={"user_id": "alice", "action": "read"},
                        event_id="evt-1",
                    )
                )
                second = store.append(
                    AuditEvent(
                        event_type="request_analyzed",
                        request_id="request-1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                        payload={"risk": 0.2},
                        event_id="evt-2",
                    )
                )

            with SQLiteEvidenceStore(str(db_path)) as reopened:
                reopened_events = reopened.list_events()
                self.assertEqual(reopened_events[0].previous_hash, "")
                self.assertEqual(reopened_events[1].previous_hash, reopened_events[0].event_hash)
                self.assertEqual(reopened_events[1].event_hash, second.event_hash)

            memory = InMemoryEvidenceStore()
            memory_first = memory.append(
                replace(
                    AuditEvent(
                        event_type="request_received",
                        request_id="request-1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                        payload={"user_id": "alice", "action": "read"},
                    ),
                    event_id="evt-1",
                )
            )
            memory_second = memory.append(
                replace(
                    AuditEvent(
                        event_type="request_analyzed",
                        request_id="request-1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                        payload={"risk": 0.2},
                    ),
                    event_id="evt-2",
                )
            )

            self.assertEqual(first.event_hash, memory_first.event_hash)
            self.assertEqual(second.event_hash, memory_second.event_hash)
            self.assertNotEqual(first.event_hash, second.event_hash)

    def test_list_events_filters_and_payload_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            with SQLiteEvidenceStore(str(Path(tempdir) / "evidence.sqlite3")) as store:
                store.append(self._make_event(event_type="request_received", request_id="r1", timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC)))
                store.append(
                    self._make_event(
                        event_type="request_analyzed",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                    )
                )
                store.append(
                    self._make_event(
                        event_type="policy_decided",
                        request_id="r2",
                        timestamp=datetime(2026, 6, 5, 1, 2, 5, tzinfo=UTC),
                    )
                )
                request_events = store.list_events(request_id="r1")
                all_events = store.list_events()

            self.assertEqual(len(request_events), 2)
            self.assertEqual(len(all_events), 3)

            copy_events = all_events
            copy_events[0].payload["nested"]["value"] = "tampered"
            copy_events[1].payload["nested"]["value"] = "tampered"

            with SQLiteEvidenceStore(str(Path(tempdir) / "evidence.sqlite3")) as reopened:
                self.assertEqual(reopened.list_events()[0].payload["nested"]["value"], "safe")
                self.assertEqual(reopened.list_events()[1].payload["nested"]["value"], "safe")
                self.assertEqual(len(reopened.list_events()), 3)

    def test_append_does_not_retain_caller_payload_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            payload = {"nested": {"value": "safe"}}
            db_file = Path(tempdir) / "evidence.sqlite3"
            with SQLiteEvidenceStore(str(db_file)) as store:
                store.append(
                    AuditEvent(
                        event_type="request_received",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                        payload=payload,
                        event_id="evt-1",
                    )
                )
            payload["nested"]["value"] = "tampered"

            with SQLiteEvidenceStore(str(db_file)) as reopened:
                self.assertEqual(reopened.list_events()[0].payload["nested"]["value"], "safe")
                self.assertTrue(reopened.verify_chain())

    def test_verify_chain_detects_payload_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "evidence.sqlite3"
            with SQLiteEvidenceStore(str(db_path)) as store:
                store.append(
                    self._make_event(
                        event_type="request_received",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                        event_id="evt-1",
                    )
                )
                store.append(
                    self._make_event(
                        event_type="request_analyzed",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                        event_id="evt-2",
                    )
                )
                store._conn.execute(
                    "UPDATE evidence_events SET payload_json = ? WHERE event_id = ?",
                    (
                        json.dumps(
                            {"risk": 0.99},
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        "evt-2",
                    ),
                )
                store._conn.commit()

            with SQLiteEvidenceStore(str(db_path)) as reopened:
                self.assertFalse(reopened.verify_chain())

    def test_verify_chain_detects_event_hash_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            with SQLiteEvidenceStore(str(Path(tempdir) / "evidence.sqlite3")) as store:
                store.append(
                    self._make_event(
                        event_type="request_received",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                        event_id="evt-1",
                    )
                )
                store.append(
                    self._make_event(
                        event_type="request_analyzed",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                        event_id="evt-2",
                    )
                )
                store._conn.execute(
                    "UPDATE evidence_events SET event_hash = 'tampered' WHERE event_id = ?",
                    ("evt-2",),
                )
                store._conn.commit()

            with SQLiteEvidenceStore(str(Path(tempdir) / "evidence.sqlite3")) as reopened:
                self.assertFalse(reopened.verify_chain())

    def test_reopen_store_retains_events(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "evidence.sqlite3"

            with SQLiteEvidenceStore(str(db_path)) as store:
                store.append(
                    self._make_event(
                        event_type="request_received",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
                        event_id="evt-1",
                    )
                )
                store.append(
                    self._make_event(
                        event_type="request_analyzed",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 4, tzinfo=UTC),
                        event_id="evt-2",
                    )
                )

            with SQLiteEvidenceStore(str(db_path)) as reopened:
                self.assertTrue(reopened.verify_chain())
                self.assertEqual(len(reopened.list_events()), 2)
                reopened.append(
                    self._make_event(
                        event_type="request_finalized",
                        request_id="r1",
                        timestamp=datetime(2026, 6, 5, 1, 2, 5, tzinfo=UTC),
                        event_id="evt-3",
                    )
                )
                self.assertEqual(len(reopened.list_events()), 3)
                self.assertTrue(reopened.verify_chain())

    def test_concurrent_append_preserves_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "evidence.sqlite3"
            with SQLiteEvidenceStore(str(db_path)) as store:
                def append_event(index: int) -> None:
                    store.append(
                        self._make_event(
                            event_type="request_received",
                            request_id=f"request-{index}",
                            timestamp=datetime(2026, 6, 5, 1, 2, index % 60, tzinfo=UTC),
                            event_id=f"evt-{index}",
                        )
                    )

                with ThreadPoolExecutor(max_workers=8) as executor:
                    list(executor.map(append_event, range(40)))

                self.assertEqual(len(store.list_events()), 40)
                self.assertTrue(store.verify_chain())


if __name__ == "__main__":
    unittest.main()
