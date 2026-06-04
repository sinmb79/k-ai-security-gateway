# Threat Model v0

## Assets

- AI prompt and response data
- Korean PII and sensitive business data
- Model credentials and provider API keys
- Policy definitions and versions
- Audit evidence logs
- Approval records

## Primary Threats

- External LLM data exfiltration
- Direct and indirect prompt injection
- Hidden instructions inside documents/RAG content
- Excessive agent/tool permissions
- Audit log tampering
- Privileged administrator misuse
- Gateway bypass through unmanaged clients

## MVP Security Invariants

- Every evaluated request creates audit events.
- Policy decisions must be reproducible by request, detection result, and policy version.
- Restricted data must not be sent to external model zones without approval.
- Raw prompt retention must be configurable and minimized.
- Audit events must be tamper-evident.

