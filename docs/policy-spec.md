# Policy Spec v0.2

## Policy Engine Inputs

- `data_grade`: public, internal, confidential, restricted
- `model_zone`: external, domestic_saas, private, on_prem
- detection findings and risk score
- user, department, role

## Policy DSL

Policy engine decisions can be loaded from JSON-compatible YAML/JSON policy files.
When `KAI_SECURITY_POLICY_PATH` is set, the gateway loads the file at process start.

Minimal example:

```yaml
{
  "version": "0.2.0",
  "policies": [
    {"id":"policy-001-block-prompt-injection","priority":10,"when":{"finding_kinds_any":["prompt_injection"]},"action":"block","reason":"prompt injection detected"},
    {"id":"policy-001-block-risk-threshold","priority":11,"when":{"min_risk_score":0.85},"action":"block","reason":"risk threshold exceeded"}
  ]
}
```

Supported `when` keys:

- `data_grade`: `public|internal|confidential|restricted`
- `model_zone`: `external|domestic_saas|private|on_prem`
- `finding_kinds_any`: list of finding kinds
- `finding_kinds_none`: list of finding kinds that must be absent
- `min_risk_score`: minimum score threshold (number)
- `no_findings`: boolean

`action` must match existing `PolicyAction` values.
`route_model_zone` (for `route_private`) must match `ModelZone`.

Rules are evaluated by increasing `priority`; equal priority keeps file order.

When no external policy file is configured, or the configured path is missing, default
policy rules are used to preserve current behavior. If a configured policy file exists
but is unreadable, unparsable, or invalid, startup must fail instead of silently falling
back to defaults.

## Default MVP Rules

1. Restricted data to external model: require approval.
2. Korean PII to external model: mask.
3. Prompt injection with high risk: block.
4. Confidential data to external model: route private.
5. Data exfiltration indicators to external model: require approval.
6. High-risk document/RAG hidden instructions to external model: require approval.
6. No findings and low risk: allow.

## API

- `GET /v1/policies` (admin only): returns active policy version/source and policy
  summaries.
- `POST /v1/policies/simulate` (admin only): evaluates policy on a request-like
  payload and returns `request_id`, `action`, `reason`, `policy_id`,
  `policy_version`, `risk_score`, `route`, `finding_count`, and `findings`.
