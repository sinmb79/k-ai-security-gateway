"""Policy engine.

Worker-owned implementation target.
"""

from __future__ import annotations

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


_POLICY_VERSION = "0.1.0"


def _has_finding_of_kind(findings: tuple[DetectionFinding, ...], kind: RiskKind) -> bool:
    return any(finding.kind == kind for finding in findings)


def _build_decision(
    action: PolicyAction,
    reason: str,
    request: GatewayRequest,
    detection: DetectionResult,
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
        policy_version=_POLICY_VERSION,
        risk_score=detection.risk_score,
        route_model_zone=route_model_zone,
        metadata=base_metadata,
    )


def decide_policy(request: GatewayRequest, detection: DetectionResult) -> PolicyDecision:
    """Return the policy decision for a request and its detection result."""
    is_prompt_injection = _has_finding_of_kind(detection.findings, RiskKind.PROMPT_INJECTION)
    is_data_exfiltration = _has_finding_of_kind(detection.findings, RiskKind.DATA_EXFILTRATION)
    has_korean_pii = _has_finding_of_kind(detection.findings, RiskKind.KOREAN_PII)

    if is_prompt_injection or detection.risk_score >= 0.85:
        return _build_decision(
            action=PolicyAction.BLOCK,
            reason="high-risk prompt-injection or risk threshold exceeded",
            request=request,
            detection=detection,
            policy_id="policy-001-block-high-risk",
            metadata={"block_reason": "prompt_injection_or_risk_threshold"},
        )

    if request.data_grade == DataGrade.RESTRICTED and request.model_zone == ModelZone.EXTERNAL:
        return _build_decision(
            action=PolicyAction.REQUIRE_APPROVAL,
            reason="restricted data must be approved before routing to external models",
            request=request,
            detection=detection,
            policy_id="policy-002-restricted-external-require-approval",
        )

    if is_data_exfiltration and request.model_zone == ModelZone.EXTERNAL:
        return _build_decision(
            action=PolicyAction.REQUIRE_APPROVAL,
            reason="data exfiltration indicators require approval before external model routing",
            request=request,
            detection=detection,
            policy_id="policy-003-data-exfiltration-external-require-approval",
            metadata={"finding_kinds": [finding.kind.value for finding in detection.findings]},
        )

    if has_korean_pii and request.model_zone == ModelZone.EXTERNAL:
        return _build_decision(
            action=PolicyAction.MASK,
            reason="korean pii found for external model traffic",
            request=request,
            detection=detection,
            policy_id="policy-004-external-korean-pii-mask",
            metadata={"finding_kinds": [finding.kind.value for finding in detection.findings]},
        )

    if request.data_grade == DataGrade.CONFIDENTIAL and request.model_zone == ModelZone.EXTERNAL:
        return _build_decision(
            action=PolicyAction.ROUTE_PRIVATE,
            reason="confidential data must be routed to private model zone",
            request=request,
            detection=detection,
            policy_id="policy-005-confidential-external-route-private",
            route_model_zone=ModelZone.PRIVATE,
        )

    if not detection.has_findings and detection.risk_score < 0.85:
        return _build_decision(
            action=PolicyAction.ALLOW,
            reason="no high-risk findings; low-risk request allowed",
            request=request,
            detection=detection,
            policy_id="policy-006-allow-low-risk",
        )

    return _build_decision(
        action=PolicyAction.ALLOW,
        reason="default allow",
        request=request,
        detection=detection,
        policy_id="policy-007-default-allow",
    )
