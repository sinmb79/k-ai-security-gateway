"""Policy engine.

Worker-owned implementation target.
"""

from __future__ import annotations

from collections.abc import Iterable
from kai_security.models import (
    DataGrade,
    DetectionFinding,
    DetectionResult,
    GatewayRequest,
    ModelZone,
    PolicyAction,
    PolicyDecision,
    RiskKind,
)
from kai_security.policy.dsl import PolicyRule, PolicySet, default_policy_set


def _has_finding_of_kind(findings: tuple[DetectionFinding, ...], kind: RiskKind) -> bool:
    return any(finding.kind == kind for finding in findings)


def _build_decision(
    action: PolicyAction,
    reason: str,
    request: GatewayRequest,
    detection: DetectionResult,
    policy_set: PolicySet,
    policy_id: str,
    route_model_zone: ModelZone | None = None,
    metadata: dict[str, object] | None = None,
) -> PolicyDecision:
    base_metadata: dict[str, object] = {
        "request_id": request.request_id,
        "data_grade": request.data_grade.value,
        "model_zone": request.model_zone.value,
        "finding_count": len(detection.findings),
    }
    if metadata:
        base_metadata.update(metadata)
    return PolicyDecision(
        action=action,
        reason=reason,
        policy_id=policy_id,
        policy_version=policy_set.version,
        risk_score=detection.risk_score,
        route_model_zone=route_model_zone,
        metadata=base_metadata,
    )


def decide_policy(
    request: GatewayRequest,
    detection: DetectionResult,
    policy_set: PolicySet | None = None,
) -> PolicyDecision:
    """Return the policy decision for a request and its detection result."""
    active_set = policy_set or default_policy_set()
    for rule in active_set.policies:
        if _matches(rule, request, detection):
            return _build_decision(
                action=rule.action,
                reason=rule.reason,
                request=request,
                detection=detection,
                policy_set=active_set,
                policy_id=rule.id,
                route_model_zone=rule.route_model_zone,
                metadata={
                    "policy_source": active_set.source,
                    "policy_set_version": active_set.version,
                    "rule_priority": rule.priority,
                },
            )
    return _build_decision(
        action=PolicyAction.ALLOW,
        reason="default allow",
        request=request,
        detection=detection,
        policy_set=active_set,
        policy_id="policy-default-allow",
        metadata={"policy_source": active_set.source, "policy_set_version": active_set.version},
    )


def _matches(rule: PolicyRule, request: GatewayRequest, detection: DetectionResult) -> bool:
    if not isinstance(rule.when, dict):
        return False
    for condition_key, expected in rule.when.items():
        if not _matches_condition(condition_key, expected, request, detection):
            return False
    return True


def _matches_condition(
    condition_key: str,
    expected: object,
    request: GatewayRequest,
    detection: DetectionResult,
) -> bool:
    if condition_key == "data_grade":
        if isinstance(expected, DataGrade):
            return request.data_grade == expected
        return False
    if condition_key == "model_zone":
        if isinstance(expected, ModelZone):
            return request.model_zone == expected
        return False
    if condition_key == "finding_kinds_any":
        kinds: Iterable[RiskKind]
        if isinstance(expected, (list, tuple)):
            kinds = tuple(k for k in expected if isinstance(k, RiskKind))
        else:
            return False
        return any(_has_finding_of_kind(detection.findings, kind) for kind in kinds)
    if condition_key == "finding_kinds_none":
        none_kinds: Iterable[RiskKind]
        if isinstance(expected, (list, tuple)):
            none_kinds = tuple(k for k in expected if isinstance(k, RiskKind))
        else:
            return False
        return not any(_has_finding_of_kind(detection.findings, kind) for kind in none_kinds)
    if condition_key == "min_risk_score":
        if isinstance(expected, int | float):
            return detection.risk_score >= float(expected)
        return False
    if condition_key == "no_findings":
        if isinstance(expected, bool):
            return detection.has_findings is (not expected)
        return False
    return False
