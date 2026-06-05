## 로컬 실행

로컬에서 API를 바로 실행하려면 `scripts/run-dev.ps1`를 사용하세요.

```powershell
$env:KAI_SECURITY_APPROVER_TOKENS = "approver-token=manager-1:security_manager"
$env:KAI_SECURITY_ADMIN_TOKENS = "admin-token=manager-1:security_manager"
$env:KAI_SECURITY_DB_PATH = ".\data\evidence.sqlite3"
./scripts/run-dev.ps1
```

포트는 기본 8765이며, 필요하면 `-Port` 옵션으로 변경할 수 있습니다.

```powershell
./scripts/run-dev.ps1 -Port 8765
./scripts/run-dev.ps1 -Port 9000
```

## Docker Compose 실행

Docker 환경에서는 8765 포트로 공개됩니다.

먼저 `.env.example`을 참고해 `.env`를 만들거나, 현재 PowerShell 세션에 필수 토큰을 주입하세요.

```powershell
$env:KAI_SECURITY_APPROVER_TOKENS = "approver-token-1=manager-1:security_manager"
$env:KAI_SECURITY_ADMIN_TOKENS = "admin-token-1=manager-1:security_manager"
docker compose config
```

```powershell
docker compose up --build
```

`docker-compose.yml`의 예시 환경변수:

```dotenv
KAI_SECURITY_APPROVER_TOKENS=approver-token-1=manager-1:security_manager;approver-token-2=admin-1:admin
KAI_SECURITY_ADMIN_TOKENS=admin-token-1=manager-1:security_manager;admin-token-2=admin-1:admin
PYTHONPATH=/app/src
KAI_SECURITY_DB_PATH=/app/data/evidence.sqlite3
```

접속 URL:
- `http://localhost:8765/admin`
- `http://localhost:8765/v1/chat/completions`
- `http://localhost:8765/v1/reports/policy`

Docker Compose는 `kai-security-data` 볼륨에 `evidence.sqlite3`를 저장합니다.

## 승인 토큰 설정

승인 처리 API는 `KAI_SECURITY_APPROVER_TOKENS`, 관리자 조회 API와 대시보드는 `KAI_SECURITY_ADMIN_TOKENS`를 사용합니다.
두 값은 다음 형식으로 지정합니다.

```
token=approver-id:role;token2=approver-id2:role2
```

예시:

```powershell
$env:KAI_SECURITY_APPROVER_TOKENS = "token-1=manager-1:security_manager;token-2=admin-1:admin"
$env:KAI_SECURITY_ADMIN_TOKENS = "admin-token-1=manager-1:security_manager"
```

허용된 역할: `admin`, `security_manager`, `approver`

관리자 API는 URL 쿼리에 토큰을 넣지 않고 HTTP 헤더로 호출합니다.

```powershell
Invoke-RestMethod -Method Get `
  -Uri "http://127.0.0.1:8765/v1/reports/policy" `
  -Headers @{ Authorization = "Bearer admin-token-1" }
```

관리자 대시보드(`/admin`)는 화면에서 입력한 관리자 토큰을 `Authorization: Bearer ...` 헤더로만 사용합니다.

## 감사 로그 저장소

기본 로컬 개발 스크립트는 `.\data\evidence.sqlite3`에 감사 이벤트를 저장합니다. 운영 환경에서는
`KAI_SECURITY_DB_PATH`를 별도로 지정해 영속 볼륨에 연결하세요.

## Smoke Test 실행

서버가 실행된 상태에서 다음을 실행해 핵심 엔드포인트를 검증합니다.

```powershell
./scripts/smoke-test.ps1
./scripts/smoke-test.ps1 -BaseUrl "http://127.0.0.1:8765" -AdminToken "admin-token-1"
```

체크 항목:
- `/v1/chat/completions`에서 계좌번호, 법인등록번호, 주소 마스킹 반영 여부
- `/v1/policies/simulate`에서 PII finding value가 raw 값이 아닌 토큰으로 반환되는지 확인
- `/v1/reports/evidence-package/{request_id}` 타임라인과 hash-chain 상태 확인
- `/v1/audit/events` 필터 검색 확인
- `/v1/audit/events/export` CSV/JSONL 다운로드와 raw PII 미포함 확인
- `/v1/reports/policy` 응답 존재 여부 및 통계 값 확인
