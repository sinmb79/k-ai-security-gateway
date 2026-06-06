# Event Schema v0

## Event Types

- `request_received`
- `request_analyzed`
- `policy_decided`
- `model_routed`
- `approval_requested` (optional when decision is `require_approval`)
- `approval_resolved`
- `approval_executed` (optional when an approved chat completion is forwarded)
- `approval_execution_failed` (optional when approved forwarding fails)
- `approval_execution_stale_recovered` (optional when an old `executing` item is returned to `pending`)
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
- `department` (string)
- `metadata.authenticated_client_id` (string, optional)
- `metadata.authenticated_client_department` (string, optional)
- `metadata.client_supplied_user_id` (string, optional)
- `metadata.client_supplied_department` (string, optional)

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

Approval status values are `pending`, `executing`, `approved`, or `rejected`.
The transient `executing` status is used to prevent duplicate provider calls while
an approved request is being forwarded.

### `approval_executed`

- `approval_id` (string)
- `route` (object)
- `status` (`executed`)
- `attempt_count` (number)
- `execution_attempt_id` (string)
- `response_guard` (object, optional)
- `delivery.mode` (`approval_resolve_response`)
- `delivery.original_client_callback` (boolean, currently `false`)

### `approval_execution_failed`

- `approval_id` (string)
- `route` (object)
- `status` (`failed`)
- `provider_name` (string, optional)
- `error_type` (`provider_timeout`, `provider_invalid_response`, `provider_http_error`,
  or `provider_runtime_error`)
- `provider_status_code` (number or null)
- `provider_error_body_sha256` (string or null)
- `provider_error_body_truncated` (boolean)
- `attempt_count` (number)
- `execution_attempt_id` (string)
- `first_failed_at` (string)
- `last_failed_at` (string)
- `retryable` (boolean)

Provider execution failures do not resolve or consume the approval request. The
approval remains `pending` so an authorized approver can retry after the provider
or network issue is fixed.

Provider raw error bodies are not copied into exception messages, API responses, or
evidence package timelines. When a provider returns an HTTP error body, the event may
include a capped `provider_error_body_sha256` and `provider_error_body_truncated` only
for correlation. Retryability is status-aware: network timeouts, `408`, `409`, `425`,
`429`, and `5xx` are retryable; ordinary `4xx` provider errors such as `400`, `401`,
`403`, `404`, and `422` are not. Invalid provider response shape is non-retryable.

### `approval_execution_stale_recovered`

- `approval_id` (string)
- `route` (object or null)
- `status` (`pending`)
- `provider_name` (string, optional)
- `attempt_count` (number)
- `stale_execution_attempt_id` (string)
- `execution_started_at` (string or null)
- `recovered_at` (string or null)
- `first_failed_at` (string or null)
- `last_failed_at` (string or null)
- `reason` (string)
- `retryable` (boolean)
- `recovered_by` (string)
- `recovered_by_role` (string)
- `auth_method` (`admin_bearer_token`)

This event is emitted when an admin calls `POST /v1/approvals/recover-stale` and an
`executing` approval has exceeded the timeout. The in-memory MVP returns the item to
`pending` for manual retry; production deployments should replace this with a
transactional persistent approval backend.

`POST /v1/approvals/recover-stale` supports `dry_run=true` for preview. Timeout values
below the default require `force=true`, and recovery reasons are restricted to
`execution_timeout`, `process_restart`, or `operator_recovery`.

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
