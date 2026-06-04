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
python -m unittest discover -s tests
python -m compileall src apps
```

