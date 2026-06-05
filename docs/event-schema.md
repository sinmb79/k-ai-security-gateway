# Event Schema v0

## Event Types

- `request_received`
- `request_analyzed`
- `policy_decided`
- `model_routed`
- `approval_requested` (optional when decision is `require_approval`)
- `approval_resolved`
- `response_analyzed` (optional when a provider response is returned)
- `request_finalized`

## Common Fields

- `event_id`
- `request_id`
- `timestamp`
- `event_type`
- `payload`
- `previous_hash`
- `event_hash`

## Event Payload Contracts

### `request_received`

- `user_id` (string)

### `request_analyzed`

- `risk_score` (number)
- `finding_count` (number)
- `findings` (string array)

### `policy_decided`

- `action` (string)
- `reason` (string)
- `policy_id` (string)
- `policy_version` (string)
- `policy_source` (string, optional)
- `policy_set_version` (string, optional)
- `effective_prompt_changed` (boolean)

### `model_routed`

- `action` (string)
- `policy_id` (string)
- `policy_version` (string)
- `requested_model` (string)
- `effective_prompt_changed` (boolean)
- `reason` (string)
- `route` (object or null)

When a route is available, `route` must include:

- `provider` (string)
- `model` (string)
- `zone` (string)
- `reason` (string)

When no route is available (e.g. `block` / `require_approval`), `route` must be `null` and `reason`
must describe the decision reason in human-readable text.

### `approval_requested`

- `approval_id` (string)
- `requested_by` (string)
- `reason` (string)
- `action` (string)
- `status` (string)

### `approval_resolved`

- `approval_id`, `request_id`, `requested_by`, `reason`, `action`, `status`,
  `created_at`, `resolved_by`, `resolved_at`, `resolution_comment`

### `response_analyzed`

- `action` (`allow`, `mask`, or `block`)
- `risk_score` (number)
- `finding_count` (number)
- `findings` (array of metadata objects: `kind`, `label`, `severity`, `confidence`)
- `choices` (array of per-choice metadata: `index`, `action`, `risk_score`,
  `finding_count`, `response_changed`)
- `response_changed` (boolean)

### `request_finalized`

- `action` (string)
- `effective_prompt_changed` (boolean)

## Integrity

Events are appended in order. Each event hash is computed from the previous hash and
canonical JSON of the current event payload.

## Request Evidence Package Report

`GET /v1/reports/evidence-package/{request_id}` builds a request-level evidence
package for admin users. The report includes:

- request id, event count, event types, and hash-chain verification status
- `chain_verification.status`: `verified`, `failed`, or `skipped`
- timeline entries with `event_id`, `timestamp`, `event_type`, `event_hash`,
  `previous_hash`, and a safe payload summary
- latest policy decision and route decision
- approval request/resolution summary when applicable
- evidence status: `missing_evidence`, `incomplete`, or `complete`
- missing required event types

Required request events are `request_received`, `request_analyzed`,
`policy_decided`, `model_routed`, and `request_finalized`.

The report intentionally exposes only metadata needed for audit reconstruction.
Raw prompts, raw model responses, and free-form approval comments are not included
in the package.

Full hash-chain verification is capped by
`KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS` (default: `50000`). When the store
exceeds this threshold, `chain_verified` is `null` and `chain_verification.status`
is `skipped` so the admin API cannot become an unbounded verification endpoint.

## Audit Event Search And Export

`GET /v1/audit/events` supports admin-only event search by `request_id`,
`event_type`, payload `action`, payload `policy_id`, timestamp range, sort order,
and limit. `GET /v1/audit/events/export?format=csv|jsonl` applies the same search
filters for downloadable evidence extracts.

CSV exports contain fixed metadata columns and escape spreadsheet formula prefixes.
JSONL exports use the same safe payload whitelist as request evidence packages, so
raw prompts, raw model responses, and free-form approval comments are not included.
