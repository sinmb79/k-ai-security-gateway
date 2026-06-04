# Event Schema v0

## Event Types

- `request_received`
- `request_analyzed`
- `policy_decided`
- `approval_requested`
- `approval_resolved`
- `model_routed`
- `request_finalized`

## Common Fields

- `event_id`
- `request_id`
- `timestamp`
- `event_type`
- `payload`
- `previous_hash`
- `event_hash`

## Integrity

Events are appended in order. Each event hash is computed from the previous hash
and canonical JSON of the current event payload.

