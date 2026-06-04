# Policy Spec v0

## Decision Inputs

- `data_grade`: public, internal, confidential, restricted
- `model_zone`: external, domestic_saas, private, on_prem
- detection findings and risk score
- user, department, role

## Actions

- `allow`: request may proceed
- `mask`: sensitive spans must be masked before model routing
- `route_private`: route to private or on-prem model zone
- `require_approval`: queue for human approval
- `block`: reject the request
- `log_only`: record the risk without blocking

## Default MVP Rules

1. Restricted data to external model: require approval.
2. Korean PII to external model: mask.
3. Prompt injection with high risk: block.
4. Confidential data to external model: route private.
5. No findings and low risk: allow.

