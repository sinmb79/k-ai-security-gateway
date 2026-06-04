# K-AI Security Gateway 실행 요약

## 결론

보안 에이전트는 "AI 백신"이 아니라 **AI 사용 통제, 감시, 승인, 감사 증적 플랫폼**으로 개발한다.

1차 MVP는 **K-AI Security Gateway + Audit Evidence Store**다.

## 왜 이 순서인가

- AI 사용을 막는 시장보다, 안전하게 쓰게 만드는 시장이 크다.
- 공공/금융/대기업은 외부 LLM 반출, 개인정보, 프롬프트 인젝션, 감사 증적을 가장 먼저 걱정한다.
- Agent Firewall, SOC Agent, Compliance Agent는 Gateway가 있어야 통제 지점을 가진다.
- 초기부터 자동 대응을 넣으면 오탐, 책임소재, 고객 거부감이 커진다.

## 1차 MVP 기능

- OpenAI 호환 AI Gateway
- 외부/내부 LLM 모델 라우팅
- 한국 개인정보 탐지와 마스킹
- 프롬프트 인젝션 및 데이터 반출 위험 탐지
- 정책 엔진: 허용, 마스킹, 내부 모델 라우팅, 승인요청, 차단
- 감사로그 및 변조 탐지 가능한 증적 저장소
- 관리자 대시보드
- AI 사용 현황, 개인정보 반출, N2SF/AI 기본법/ISMS-P 스타일 리포트 초안

## 후속 확장

Phase 2: Agent Firewall / Tool Broker

- 에이전트별 ID
- 최소권한
- 도구 허용목록
- 세션별 임시 권한
- 고위험 작업 인간 승인
- 모든 도구 호출 감사로그

Phase 3: AI SOC Agent

- 경보 요약
- 사건 타임라인
- MITRE ATT&CK/ATLAS/OWASP 매핑
- 대응 플레이북 추천
- 승인 기반 SOAR

Phase 4: AI Compliance Agent

- AI 기본법, 개인정보보호, KISA AI 보안 안내서, N2SF, ISMS-P, CSAP, 금융권 AI 기준 매핑
- 감사 증적 수집
- 리포트 초안 생성
- 미흡 통제 항목 식별

## 12주 착수안

1-2주차: 위협 모델, 정책 DSL, 이벤트 스키마, Gateway skeleton

3-4주차: OpenAI-compatible Gateway, provider adapter, 감사로그, hash-chain ledger

5-6주차: 한국 개인정보 탐지, 프롬프트 인젝션 탐지, 마스킹 엔진

7-8주차: 정책 엔진, 승인 큐, 정책 시뮬레이션

9-10주차: 관리자 대시보드, 로그 탐색, 리포트 생성

11-12주차: Docker Compose 온프레미스 POC, red-team 테스트, 데모 시나리오

## 첫 데모 시나리오

사용자가 고객 상담 내용을 외부 LLM에 요약 요청한다.

Gateway가 주민번호, 전화번호, 계좌번호, 주소를 탐지한다.

정책이 외부 LLM 직접 전송을 막고, 마스킹 또는 내부 모델 라우팅 또는 승인 요청으로 처리한다.

관리자는 대시보드에서 요청, 탐지 결과, 정책 결정, 승인자, 리포트를 확인한다.

## 바로 다음 작업

1. `docs/threat-model.md`
2. `docs/policy-spec.md`
3. `docs/event-schema.md`
4. Gateway API skeleton
5. Korean PII detector test suite

상세 계획서는 `K-AI-Security-Gateway-Development-Plan.md`를 기준 문서로 사용한다.
