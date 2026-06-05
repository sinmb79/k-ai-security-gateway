# MVP Release Candidate Status

Updated: 2026-06-05

## Current Scope

K-AI Security Gateway is now a local MVP release candidate for controlled
OpenAI-compatible AI usage.

Implemented:

- OpenAI-compatible `/v1/chat/completions` gateway
- Provider routing for external, private, domestic SaaS, and on-prem model zones
- Korean PII detection and masking for RRN-like IDs, foreigner registration IDs,
  phone numbers, email, cards, business numbers, account numbers, corporate
  registration numbers, and Korean address patterns
- Prompt-injection, data-exfiltration, and document/RAG risk detection
- Policy DSL loading from JSON-compatible YAML/JSON
- Policy decisions: `allow`, `mask`, `route_private`, `require_approval`, `block`
- Approval queue and admin/approver Bearer-token resolution flow
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
./scripts/smoke-test.ps1 -BaseUrl "http://127.0.0.1:8765" -AdminToken "admin-token-1"
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

- Streaming chat completion pass-through
- Cursor-based audit export for very large evidence stores
- Label-specific policy DSL conditions such as account-only approval rules
- Full policy editing/version publishing in the dashboard
- OIDC/SAML SSO and production RBAC integration
- Retention policy enforcement and encrypted raw-prompt vault separation
- Broader Korean PII categories such as passport, driver license, vehicle number,
  and customer-specific allowlists
- Browser E2E automation package integration for dashboard DOM/download tests
