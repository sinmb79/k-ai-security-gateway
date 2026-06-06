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
- RAG/document tool-exfiltration instructions that ask an agent to call export,
  dump, upload, or send tools outside the user-visible task
- Excessive agent/tool permissions
- Audit log tampering
- Privileged administrator misuse
- Gateway bypass through unmanaged clients

## MVP Security Invariants

- Every evaluated request creates audit events.
- Policy decisions must be reproducible by request, detection result, and policy version.
- Restricted data must not be sent to external model zones without approval.
- Approved restricted requests must only be marked `approved` after the stored
  safe request context has executed successfully.
- Approval success/failure transitions must match the current
  `execution_attempt_id`; stale callbacks must not mutate newer attempts.
- Post-provider execution attempt mismatches must emit audit evidence and return
  a structured conflict response instead of silently consuming or changing approval state.
- Stored approval context validation errors must be non-retryable gateway state
  errors and must not call an upstream provider.
- Provider raw error bodies must not be copied into API responses, exception
  messages, or evidence package timelines.
- Provider error body hashing must use a bounded read cap and record truncation
  status instead of loading unbounded upstream error bodies.
- High-risk document/RAG hidden instructions must require approval before
  external model routing.
- Raw prompt retention must be configurable and minimized.
- Audit events must be tamper-evident.

## MVP Boundaries

- Approval execution locking is in-memory and process-local. Multi-worker or
  multi-replica deployments require a persistent transactional approval backend.
- Provider idempotency keys remain attempt-scoped in the MVP. Production hardening
  should add a logical approval-level execution ledger and unknown-outcome
  handling.

