# K-AI Security Gateway MVP

K-AI Security Gateway is a Korean-first AI usage control and audit platform.

The first MVP focuses on:

- OpenAI-compatible request evaluation flow
- Korean PII detection and masking
- Prompt-injection and data-exfiltration risk scoring
- Policy decisions: allow, mask, route_private, require_approval, block
- Tamper-evident audit events
- Evidence-backed compliance report drafts

See the root development plan for the product rationale:

- `K-AI-Security-Gateway-Development-Plan.md`
- `EXECUTIVE-SUMMARY.md`

## Local Verification

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests
python -m compileall src apps
```

## Provider Adapter Configuration

The gateway route resolves by policy `ModelRoute.provider` and uses a local echo provider
unless an endpoint is configured.

Set these environment variables to enable OpenAI-compatible upstream calls:

```powershell
$env:KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_ENDPOINT = "https://api.openai.com"
$env:KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_API_KEY = "..."

$env:KAI_SECURITY_PRIVATE_LLM_ENDPOINT = "http://10.0.0.10:8080"
$env:KAI_SECURITY_DOMESTIC_SAAS_ENDPOINT = "https://domestic-saas.internal"
$env:KAI_SECURITY_ON_PREM_LLM_ENDPOINT = "http://onprem.internal:8080"
```

If endpoint variables are absent, all four provider names (`external-openai-compatible`,
`private-llm`, `domestic-saas`, `on-prem-llm`) continue to use the mock/echo behavior.

You can also control upstream timeout with:

```powershell
$env:KAI_SECURITY_PROVIDER_REQUEST_TIMEOUT_SECONDS = "5.0"
```

Only finite positive values are accepted; invalid, zero/negative, `nan`, and `inf`
values fall back to `5.0` seconds.

## Policy Set Loader

Set `KAI_SECURITY_POLICY_PATH` to a JSON-compatible YAML/JSON file to load policy rules
for the gateway process. If the value is unset or the file is missing, the default
policy set is used. If the configured file exists but cannot be parsed or validated,
startup fails so policy mistakes are not hidden.

The repository default policy file is available at `policies/default.yaml`.

Current admin endpoints:

- `GET /v1/policies` returns active policy set version, source, and summaries.
- `POST /v1/policies/simulate` runs detection + policy decision + route computation
  without calling any model provider or approval queue.
- `GET /v1/audit/events` searches audit events by `request_id`, `event_type`,
  `action`, `policy_id`, timestamp range, order, and limit.
- `GET /v1/audit/events/export?format=csv|jsonl` exports the same safe event
  search result set. CSV cells are escaped for spreadsheet formula safety and
  JSONL uses report-safe payload summaries instead of raw free-form payloads.
- `GET /v1/reports/evidence-package/{request_id}` returns request-level evidence package
  for admin users using Bearer token authentication.
  `KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS` controls when full hash-chain
  verification is skipped for large stores (default: `50000`).

The `/admin` dashboard can query evidence packages by `request_id` and open a
request package directly from recent audit events.

## Approval Tokens

Approval resolution through the API requires server-side approver tokens. Configure
`KAI_SECURITY_APPROVER_TOKENS` with this format:

```powershell
$env:KAI_SECURITY_APPROVER_TOKENS='token-1=manager-1:security_manager;token-2=admin-1:admin'
```

Allowed roles are `admin`, `security_manager`, and `approver`. The API does not
trust `approver_id` or `approver_role` from the request body.
