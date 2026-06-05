"""SQLite-backed tamper-evident audit evidence store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from threading import RLock
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

from kai_security.models import AuditEvent


class SQLiteEvidenceStore:
    """Persist audit evidence in SQLite using append-only chained hash design."""

    def __init__(self, database_path: str = ":memory:") -> None:
        self._lock = RLock()
        self._conn = sqlite3.connect(database_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def append(self, event: AuditEvent) -> AuditEvent:
        payload = deepcopy(event.payload)

        with self._lock:
            with self._conn:
                row = self._conn.execute(
                    """
                    SELECT event_hash
                    FROM evidence_events
                    ORDER BY sequence DESC
                    LIMIT 1
                    """
                ).fetchone()
                previous_hash = row["event_hash"] if row else ""

                hashed_event = replace(
                    event,
                    payload=payload,
                    previous_hash=previous_hash,
                )
                hashed_event = replace(
                    hashed_event,
                    event_hash=self._compute_event_hash(hashed_event),
                )

                self._conn.execute(
                    """
                    INSERT INTO evidence_events (
                        event_id,
                        request_id,
                        timestamp,
                        event_type,
                        payload_json,
                        previous_hash,
                        event_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        hashed_event.event_id,
                        hashed_event.request_id,
                        self._normalize_timestamp(hashed_event.timestamp),
                        hashed_event.event_type,
                        json.dumps(hashed_event.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                        hashed_event.previous_hash,
                        hashed_event.event_hash,
                    ),
                )

        return hashed_event

    def __enter__(self) -> "SQLiteEvidenceStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def list_events(
        self,
        request_id: str | None = None,
        event_type: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        if limit is not None and limit <= 0:
            return []
        query = """
        SELECT
            event_id,
            request_id,
            timestamp,
            event_type,
            payload_json,
            previous_hash,
            event_hash,
            sequence
        FROM evidence_events
        """
        where_clauses: list[str] = []
        params: list[str | int] = []
        if request_id is not None:
            where_clauses.append("request_id = ?")
            params.append(request_id)
        if event_type is not None:
            where_clauses.append("event_type = ?")
            params.append(event_type)
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        query += " ORDER BY sequence ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [self._row_to_event(row) for row in rows]

    def verify_chain(self) -> bool:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    event_id,
                    request_id,
                    timestamp,
                    event_type,
                    payload_json,
                    previous_hash,
                    event_hash,
                    sequence
                FROM evidence_events
                ORDER BY sequence ASC
                """
            ).fetchall()

        expected_previous = ""
        for row in rows:
            payload = json.loads(row["payload_json"])
            event = AuditEvent(
                event_type=row["event_type"],
                request_id=row["request_id"],
                timestamp=self._normalize_timestamp_str(row["timestamp"]),
                payload=payload,
                event_id=row["event_id"],
                previous_hash=row["previous_hash"],
                event_hash=row["event_hash"],
            )

            if event.previous_hash != expected_previous:
                return False
            if event.event_hash != self._compute_event_hash(event):
                return False
            expected_previous = event.event_hash

        return True

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS evidence_events_event_id_idx ON evidence_events(event_id)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS evidence_events_request_id_idx ON evidence_events(request_id)"
        )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS evidence_events_sequence_idx ON evidence_events(sequence)"
        )
        self._conn.commit()

    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        payload = json.loads(row["payload_json"])
        return AuditEvent(
            event_type=row["event_type"],
            request_id=row["request_id"],
            timestamp=self._normalize_timestamp_str(row["timestamp"]),
            payload=deepcopy(payload),
            event_id=row["event_id"],
            previous_hash=row["previous_hash"],
            event_hash=row["event_hash"],
        )

    def _compute_event_hash(self, event: AuditEvent) -> str:
        message = {
            "event_id": event.event_id,
            "request_id": event.request_id,
            "timestamp": self._normalize_timestamp(event.timestamp),
            "event_type": event.event_type,
            "payload": event.payload,
            "previous_hash": event.previous_hash,
        }
        encoded = json.dumps(message, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _normalize_timestamp(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()

    @staticmethod
    def _normalize_timestamp_str(value: str) -> datetime:
        timestamp = value
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        parsed = datetime.fromisoformat(timestamp)
        return parsed.astimezone(UTC)
