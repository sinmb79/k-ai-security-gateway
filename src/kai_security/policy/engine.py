"""Policy engine.

Worker-owned implementation target.
"""

from __future__ import annotations

from kai_security.models import DetectionResult, GatewayRequest, PolicyAction, PolicyDecision


def decide_policy(request: GatewayRequest, detection: DetectionResult) -> PolicyDecision:
    """Return the policy decision for a request and its detection result."""
    return PolicyDecision(
        action=PolicyAction.ALLOW,
        reason="default allow",
        policy_id="default-allow",
        policy_version="0.1.0",
        risk_score=detection.risk_score,
    )

