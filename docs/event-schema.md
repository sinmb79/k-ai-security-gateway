# Event Schema v0

## Event Types

- `request_received`
- `request_analyzed`
- `policy_decided`
- `model_routed`
- `approval_requested` (optional when decision is `require_approval`)
- `approval_resolved`
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

### `request_finalized`

- `action` (string)
- `effective_prompt_changed` (boolean)

## Integrity

Events are appended in order. Each event hash is computed from the previous hash and
canonical JSON of the current event payload.
