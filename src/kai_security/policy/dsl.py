"""Policy DSL loader for file-based policies.

This module intentionally keeps dependencies minimal and uses only stdlib parsing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterable

from kai_security.models import DataGrade, ModelZone, PolicyAction, RiskKind

_DEFAULT_VERSION: Final = "0.1.0"


@dataclass(frozen=True)
class PolicyRule:
    """Single rule in an ordered policy set."""

    id: str
    priority: int
    when: dict[str, object]
    action: PolicyAction
    reason: str
    route_model_zone: ModelZone | None = None


@dataclass(frozen=True)
class PolicySet:
    """Policy set loaded from disk or built as defaults."""

    version: str
    source: str
    policies: tuple[PolicyRule, ...]


def default_policy_set() -> PolicySet:
    """Return the built-in policy set used when no external file is configured."""
    policies = (
        PolicyRule(
            id="policy-001-block-high-risk",
            priority=10,
            when={"finding_kinds_any": [RiskKind.PROMPT_INJECTION]},
            action=PolicyAction.BLOCK,
            reason="high-risk prompt-injection or risk threshold exceeded",
        ),
        PolicyRule(
            id="policy-001b-block-risk-threshold",
            priority=11,
            when={
                "min_risk_score": 0.85,
                "finding_kinds_none": [RiskKind.KOREAN_PII],
            },
            action=PolicyAction.BLOCK,
            reason="high-risk prompt-injection or risk threshold exceeded",
        ),
        PolicyRule(
            id="policy-002-restricted-external-require-approval",
            priority=20,
            when={
                "data_grade": DataGrade.RESTRICTED,
                "model_zone": ModelZone.EXTERNAL,
            },
            action=PolicyAction.REQUIRE_APPROVAL,
            reason="restricted data must be approved before routing to external models",
        ),
        PolicyRule(
            id="policy-003-data-exfiltration-external-require-approval",
            priority=30,
            when={
                "finding_kinds_any": [RiskKind.DATA_EXFILTRATION],
                "model_zone": ModelZone.EXTERNAL,
            },
            action=PolicyAction.REQUIRE_APPROVAL,
            reason="data exfiltration indicators require approval before external model routing",
        ),
        PolicyRule(
            id="policy-003b-document-risk-external-require-approval",
            priority=35,
            when={
                "finding_kinds_any": [RiskKind.DOCUMENT_RISK],
                "model_zone": ModelZone.EXTERNAL,
                "min_risk_score": 0.7,
            },
            action=PolicyAction.REQUIRE_APPROVAL,
            reason="document or RAG content contains high-risk hidden instructions",
        ),
        PolicyRule(
            id="policy-004-external-korean-pii-mask",
            priority=40,
            when={
                "finding_kinds_any": [RiskKind.KOREAN_PII],
                "model_zone": ModelZone.EXTERNAL,
            },
            action=PolicyAction.MASK,
            reason="korean pii found for external model traffic",
        ),
        PolicyRule(
            id="policy-005-confidential-external-route-private",
            priority=38,
            when={
                "data_grade": DataGrade.CONFIDENTIAL,
                "model_zone": ModelZone.EXTERNAL,
            },
            action=PolicyAction.ROUTE_PRIVATE,
            reason="confidential data must be routed to private model zone",
            route_model_zone=ModelZone.PRIVATE,
        ),
        PolicyRule(
            id="policy-006-allow-low-risk",
            priority=60,
            when={"no_findings": True},
            action=PolicyAction.ALLOW,
            reason="no high-risk findings; low-risk request allowed",
        ),
        PolicyRule(
            id="policy-007-default-allow",
            priority=1000,
            when={},
            action=PolicyAction.ALLOW,
            reason="default allow",
        ),
    )
    return PolicySet(
        version=_DEFAULT_VERSION,
        source="default",
        policies=_order_policies(policies),
    )


def load_policy_set(policy_path: str | None = None) -> PolicySet:
    """Load policy set from a JSON-compatible YAML/JSON file path."""
    if not policy_path:
        return default_policy_set()
    path = Path(policy_path)
    if not path.is_file():
        return default_policy_set()
    return load_policy_set_from_path(path)


def load_policy_set_from_path(path: str | Path) -> PolicySet:
    """Load and validate a policy set from a JSON-compatible document."""
    raw_payload = Path(path).read_text(encoding="utf-8")
    parsed = _parse_json_compat(raw_payload, path=path)
    if not isinstance(parsed, dict):
        raise ValueError("policy file must contain a JSON object")
    version = parsed.get("version", _DEFAULT_VERSION)
    if not isinstance(version, str) or not version.strip():
        raise ValueError("policy version must be a non-empty string")

    raw_policies = parsed.get("policies")
    if raw_policies is None:
        raw_policies = []
    if not isinstance(raw_policies, list):
        raise ValueError("policy.policies must be a list")

    parsed_policies = []
    for index, raw_policy in enumerate(raw_policies):
        parsed_policies.append((index, _parse_policy(raw_policy)))
    ordered_policies = _order_policies(policy for _, policy in parsed_policies)
    if not ordered_policies:
        raise ValueError("policy set must contain at least one policy")

    return PolicySet(
        version=version,
        source=str(path),
        policies=ordered_policies,
    )


def _order_policies(policies: Iterable[PolicyRule]) -> tuple[PolicyRule, ...]:
    return tuple(
        policy
        for _, policy in sorted(
            enumerate(policies),
            key=lambda item: (item[1].priority, item[0]),
        )
    )


def _parse_json_compat(raw_text: str, path: str | Path) -> dict[str, object]:
    """Parse a JSON-compatible YAML object body.

    The loader intentionally prefers plain JSON parsing and treats common .yaml/.yml policy
    files as plain JSON objects for compatibility.
    """
    stripped = "\n".join(line for line in raw_text.splitlines() if not line.strip().startswith("#"))
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"policy file {path!s} is not valid JSON-compatible YAML/JSON"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError("policy file root must be an object")
    return data


def _parse_policy(raw_policy: object) -> PolicyRule:
    if not isinstance(raw_policy, dict):
        raise ValueError("each policy must be an object")

    policy_id = str(raw_policy.get("id", "")).strip()
    if not policy_id:
        raise ValueError("policy id is required")

    priority_raw = raw_policy.get("priority")
    if isinstance(priority_raw, bool) or not isinstance(priority_raw, int):
        raise ValueError(f"policy {policy_id}: priority must be an integer")
    if priority_raw < 0:
        raise ValueError(f"policy {policy_id}: priority must be non-negative")
    reason = str(raw_policy.get("reason", "")).strip()
    if not reason:
        reason = "policy matched"

    if "action" not in raw_policy:
        raise ValueError(f"policy {policy_id}: action is required")
    try:
        action = PolicyAction(str(raw_policy["action"]))
    except ValueError as exc:
        raise ValueError(f"policy {policy_id}: unsupported action {raw_policy['action']!r}") from exc

    raw_when = raw_policy.get("when", {})
    if not isinstance(raw_when, dict):
        raise ValueError(f"policy {policy_id}: when must be an object")
    when: dict[str, object] = {}
    for key, value in raw_when.items():
        when.update(_parse_condition(policy_id, key, value))

    route_model_zone = raw_policy.get("route_model_zone")
    if route_model_zone is not None:
        try:
            route_model_zone = ModelZone(str(route_model_zone))
        except ValueError as exc:
            raise ValueError(
                f"policy {policy_id}: unsupported route_model_zone {route_model_zone!r}"
            ) from exc

    if action == PolicyAction.ROUTE_PRIVATE and route_model_zone is None:
        raise ValueError(f"policy {policy_id}: route_private requires route_model_zone")

    return PolicyRule(
        id=policy_id,
        priority=priority_raw,
        when=when,
        action=action,
        reason=reason,
        route_model_zone=route_model_zone,
    )


def _parse_condition(policy_id: str, key: str, value: object) -> dict[str, object]:
    if key == "data_grade":
        try:
            return {"data_grade": DataGrade(str(value))}
        except ValueError as exc:
            raise ValueError(f"policy {policy_id}: unsupported data_grade {value!r}") from exc

    if key == "model_zone":
        try:
            return {"model_zone": ModelZone(str(value))}
        except ValueError as exc:
            raise ValueError(f"policy {policy_id}: unsupported model_zone {value!r}") from exc

    if key == "min_risk_score":
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"policy {policy_id}: min_risk_score must be a number")
        return {"min_risk_score": float(value)}

    if key == "no_findings":
        if not isinstance(value, bool):
            raise ValueError(f"policy {policy_id}: no_findings must be boolean")
        return {"no_findings": value}

    if key in {"finding_kinds_any", "finding_kinds_none"}:
        if not isinstance(value, list):
            raise ValueError(f"policy {policy_id}: {key} must be a list")
        kinds = []
        for finding_kind in value:
            if not isinstance(finding_kind, str):
                raise ValueError(
                    f"policy {policy_id}: {key} values must be strings"
                )
            try:
                kinds.append(RiskKind(finding_kind))
            except ValueError as exc:
                raise ValueError(f"policy {policy_id}: unsupported finding kind {finding_kind!r}") from exc
        return {key: tuple(kinds)}

    raise ValueError(f"policy {policy_id}: unsupported condition {key!r}")
