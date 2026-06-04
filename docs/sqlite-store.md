# SQLite Evidence Store

`SQLiteEvidenceStore`는 `InMemoryEvidenceStore`와 동일한 인터페이스를 제공하면서
이벤트를 영속적으로 저장하기 위한 경량 구현입니다.

## 제공 인터페이스

- `append(event: AuditEvent) -> AuditEvent`
- `list_events(request_id: str | None = None) -> list[AuditEvent]`
- `verify_chain() -> bool`

모든 이벤트는 해시 체인(`previous_hash`, `event_hash`)으로 위변조를 탐지합니다.

## 저장 스키마

```sql
CREATE TABLE IF NOT EXISTS evidence_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL
);
```

`event_id`는 유니크 인덱스로 관리합니다.

## 해시 계산

`InMemoryEvidenceStore`와 동일한 규칙을 사용합니다.

- 정규화된 문자열(`UTC` 기준) timestamp
- event payload dict의 JSON canonicalization:
  - `sort_keys=True`
  - `separators=(",", ":")`
  - `ensure_ascii=False`
- `sha256(json_bytes)` 계산 결과를 `event_hash`에 저장

`previous_hash`는 append 시점 기준 DB에서 `sequence`가 가장 큰(마지막) 이벤트의 `event_hash`를 사용합니다.

## 동작 특성

- `append`는 단일 SQLite 트랜잭션으로 처리됩니다.
- `list_events`는 DB 문자열을 `datetime`과 `dict`로 복원합니다.
- 반환 객체의 `payload`는 `deepcopy`되어 호출측이 DB에 영향주지 않습니다.
- `verify_chain`은 `sequence` 오름차순으로 `previous_hash`와 `event_hash`를 재계산해 체인을 검증합니다.

## 테스트

`tests/test_sqlite_evidence_store.py`에서 다음을 검증합니다.

- append/hash 연쇄 연결
- request_id 필터링
- payload 복제 안전성
- 호출 측 payload 참조 영향 없음
- tamper detection (payload/event_hash 조작)
- DB 파일 재오픈 후 데이터 유지 및 연쇄 검증
