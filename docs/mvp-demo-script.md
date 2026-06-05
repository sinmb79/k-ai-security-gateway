# MVP Demo Script

## Scenario: Korean PII External LLM Control

1. User submits a prompt containing Korean customer information.
2. Gateway detects Korean PII such as phone numbers, account numbers, corporate
   registration numbers, addresses, email, cards, business numbers, and RRN-like
   identifiers.
3. Policy engine decides `mask` or `require_approval`.
4. The provider receives the masked prompt, and the response guard checks the
   model response before it is returned.
5. Audit evidence store records request, analysis, policy, route, response, and
   finalization events.
6. Admin dashboard opens the request-level evidence package and filters the audit
   event explorer by request id, action, policy id, or event type.
7. Report/export endpoints generate policy summaries, privacy/export checks,
   CSV extracts, and JSONL extracts from safe metadata.

