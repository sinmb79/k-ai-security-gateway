"""Gateway orchestration service."""

from __future__ import annotations

from datetime import UTC, datetime

from kai_security.detectors.pii import detect_korean_pii
from kai_security.detectors.prompt_risk import detect_prompt_risk
from kai_security.evidence.store import InMemoryEvidenceStore
from kai_security.models import AuditEvent, DetectionResult, GatewayEvaluation, GatewayRequest
from kai_security.policy.engine import decide_policy


class GatewayService:
    def __init__(self, evidence_store: InMemoryEvidenceStore | None = None) -> None:
        self.evidence_store = evidence_store or InMemoryEvidenceStore()

    def evaluate(self, request: GatewayRequest) -> GatewayEvaluation:
        self._record("request_received", request.request_id, {"user_id": request.user_id})
        pii = detect_korean_pii(request.prompt)
        prompt_risk = detect_prompt_risk(request.prompt)
        combined = _combine_detection_results(pii, prompt_risk)
        self._record(
            "request_analyzed",
            request.request_id,
            {
                "risk_score": combined.risk_score,
                "finding_count": len(combined.findings),
                "findings": [finding.label for finding in combined.findings],
            },
        )
        decision = decide_policy(request, combined)
        effective_prompt = _effective_prompt(request.prompt, combined, decision.action)
        self._record(
            "policy_decided",
            request.request_id,
            {
                "action": decision.action.value,
                "reason": decision.reason,
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "effective_prompt_changed": effective_prompt != request.prompt,
            },
        )
        self._record(
            "request_finalized",
            request.request_id,
            {
                "action": decision.action.value,
                "effective_prompt_changed": effective_prompt != request.prompt,
            },
        )
        return GatewayEvaluation(
            request=request,
            detection=combined,
            decision=decision,
            effective_prompt=effective_prompt,
        )

    def _record(self, event_type: str, request_id: str, payload: dict[str, object]) -> None:
        self.evidence_store.append(
            AuditEvent(
                event_type=event_type,
                request_id=request_id,
                timestamp=datetime.now(UTC),
                payload=payload,
            )
        )


def _combine_detection_results(*results: DetectionResult) -> DetectionResult:
    findings = tuple(finding for result in results for finding in result.findings)
    risk_score = min(1.0, sum(result.risk_score for result in results))
    masked_text = next((result.masked_text for result in results if result.masked_text), None)
    return DetectionResult(findings=findings, risk_score=risk_score, masked_text=masked_text)


def _effective_prompt(prompt: str, detection: DetectionResult, action: object) -> str:
    action_value = getattr(action, "value", str(action))
    if action_value == "mask" and detection.masked_text:
        return detection.masked_text
    return prompt
