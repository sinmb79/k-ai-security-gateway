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

## Approval Tokens

Approval resolution through the API requires server-side approver tokens. Configure
`KAI_SECURITY_APPROVER_TOKENS` with this format:

```powershell
$env:KAI_SECURITY_APPROVER_TOKENS='token-1=manager-1:security_manager;token-2=admin-1:admin'
```

Allowed roles are `admin`, `security_manager`, and `approver`. The API does not
trust `approver_id` or `approver_role` from the request body.
