# MVP Demo Script

## Scenario: Korean PII External LLM Control

1. User submits a prompt containing Korean customer information.
2. Gateway detects Korean PII.
3. Policy engine decides `mask` or `require_approval`.
4. Audit evidence store records request, analysis, policy, and finalization.
5. Report generator creates a usage summary from evidence events.

