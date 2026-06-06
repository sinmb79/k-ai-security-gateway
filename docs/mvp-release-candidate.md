# MVP Release Candidate Status

Updated: 2026-06-06

## Current Scope

K-AI Security Gateway is now a local MVP release candidate for controlled
OpenAI-compatible subset AI usage.

Implemented:

- OpenAI-compatible subset `/v1/chat/completions` gateway
- Client Bearer-token protection for `/v1/chat/completions` and `/v1/security/evaluate`
- Provider routing for external, private, domestic SaaS, and on-prem model zones
- Korean PII detection and masking for RRN-like IDs, foreigner registration IDs,
  phone numbers, email, cards, business numbers, account numbers, corporate
  registration numbers, and Korean address patterns
- Prompt-injection, data-exfiltration, and document/RAG risk detection
- Policy DSL loading from JSON-compatible YAML/JSON
- Policy decisions: `allow`, `mask`, `route_private`, `require_approval`, `block`
- Approval queue and admin/approver Bearer-token resolution flow with explicit
  attempt-aware `pending -> executing -> approved` execution state transitions
- Approval execution failure rollback, stale `executing` recovery, sanitized
  provider error evidence with capped body hashes, and status-aware retryability metadata
- Admin-only non-retryable provider failure reset via
  `POST /v1/approvals/{approval_id}/reset-execution-error`, with required
  `reason_code`, hash-only optional comments, provider-error allowlist, and
  `approval_execution_error_reset` audit evidence
- Post-provider attempt conflict audit evidence with structured `409` responses
  that do not mutate newer approval state
- Non-retryable `stored_approval_context_error` handling for invalid stored approval
  context before any provider call
- Structured `409` stored context error responses with `invalid_context` approval
  state, `retryable=false`, and operator-review guidance in admin payloads
- Approval capability hints split into `can_resolve`, `can_execute_provider`,
  `can_reject`, and `resolution_mode`, with `can_execute` retained for compatibility
- Failure-domain tagging for approval failure evidence: `gateway_state`,
  `gateway_runtime`, `approval_backend`, `provider_transport`, `provider_response`,
  `approval_state_conflict`, and `unknown`
- Explicit `policy_evaluation` context for non-provider approval resolutions so
  missing or unsupported approval context cannot silently succeed
- Tamper-evident audit evidence store with in-memory and SQLite backends
- Request-level evidence package reports with hash-chain verification metadata
- Response guard for model outputs, including PII masking and secret blocking
- Admin dashboard for overview, recent events, evidence package lookup, policy
  simulation, approval queue, routing, privacy metrics, event filtering, and
  CSV/JSONL audit export
- Docker Compose and local PowerShell run/smoke scripts

## Verification

Run from the repository root:

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests
python -m compileall src apps
node --check apps\gateway_api\static\admin.js
docker compose --env-file .env.example config --quiet
```

With a server running:

```powershell
./scripts/smoke-test.ps1 `
  -BaseUrl "http://127.0.0.1:8765" `
  -AdminToken "admin-token-1" `
  -ClientToken "client-token-1"
```

The smoke script verifies masking, policy simulation, evidence package generation,
audit event search, and CSV/JSONL export without raw PII leakage.

## Current Local Server

During development, the verified local server was restarted on:

- `http://127.0.0.1:8766/admin`

It uses:

- `KAI_SECURITY_POLICY_PATH=policies/default.yaml`
- `KAI_SECURITY_DB_PATH=data/master-policy-dsl-runtime.sqlite3`

## Known Follow-Up Items

These are intentionally outside this MVP release candidate or deferred hardening:

- Streaming chat completion and tool-calling pass-through
- Cursor-based audit export for very large evidence stores
- Label-specific policy DSL conditions such as account-only approval rules
- Full policy editing/version publishing in the dashboard
- OIDC/SAML SSO and production RBAC integration
- Persistent transactional approval backend for multi-worker or multi-replica
  deployments
- Transactional approval-state plus audit/outbox commit for reset and execution
  state transitions
- Logical approval-level idempotency ledger and unknown-outcome handling separate
  from per-attempt audit IDs
- Retention policy enforcement and encrypted raw-prompt vault separation
- Broader Korean PII categories such as passport, driver license, vehicle number,
  and customer-specific allowlists
- Browser E2E automation package integration for dashboard DOM/download tests
