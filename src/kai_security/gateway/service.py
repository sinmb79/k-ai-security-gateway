"""Gateway orchestration service."""

from __future__ import annotations

from datetime import UTC, datetime

from kai_security.approval.queue import InMemoryApprovalQueue
from kai_security.detectors.pii import detect_korean_pii
from kai_security.detectors.prompt_risk import detect_prompt_risk
from kai_security.evidence.store import InMemoryEvidenceStore
from kai_security.models import AuditEvent, DetectionResult, GatewayEvaluation, GatewayRequest, PolicyDecision
from kai_security.model_router import ModelRoute, choose_route
from kai_security.policy.engine import decide_policy
from kai_security.policy.dsl import PolicySet, load_policy_set


class GatewayService:
    def __init__(
        self,
        evidence_store: InMemoryEvidenceStore | None = None,
        approval_queue: InMemoryApprovalQueue | None = None,
        policy_set: PolicySet | None = None,
        policy_path: str | None = None,
    ) -> None:
        self.evidence_store = evidence_store or InMemoryEvidenceStore()
        self.approval_queue = approval_queue or InMemoryApprovalQueue()
        self.policy_set = policy_set or load_policy_set(policy_path)

    def evaluate(self, request: GatewayRequest) -> GatewayEvaluation:
        combined_detection = _analyze_request(request)
        decision = decide_policy(request, combined_detection, policy_set=self.policy_set)
        effective_prompt = _effective_prompt(request.prompt, combined_detection, decision.action)
        approval_id = None

        self._record("request_received", request.request_id, {"user_id": request.user_id})
        self._record(
            "request_analyzed",
            request.request_id,
            {
                "risk_score": combined_detection.risk_score,
                "finding_count": len(combined_detection.findings),
                "findings": [finding.label for finding in combined_detection.findings],
            },
        )
        self._record(
            "policy_decided",
            request.request_id,
            {
                "action": decision.action.value,
                "reason": decision.reason,
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "policy_source": decision.metadata.get("policy_source"),
                "policy_set_version": decision.metadata.get("policy_set_version"),
                "effective_prompt_changed": effective_prompt != request.prompt,
            },
        )
        if decision.action.value == "require_approval":
            approval = self.approval_queue.create(
                request_id=request.request_id,
                requested_by=request.user_id,
                reason=decision.reason,
                action=decision.action.value,
            )
            approval_id = approval.approval_id
            self._record(
                "approval_requested",
                request.request_id,
                {
                    "approval_id": approval.approval_id,
                    "requested_by": approval.requested_by,
                    "reason": approval.reason,
                    "action": approval.action,
                    "status": approval.status,
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
            detection=combined_detection,
            decision=decision,
            effective_prompt=effective_prompt,
            approval_id=approval_id,
        )

    def simulate(
        self, request: GatewayRequest
    ) -> tuple[DetectionResult, PolicyDecision, str, ModelRoute | None]:
        combined_detection = _analyze_request(request)
        decision = decide_policy(request, combined_detection, policy_set=self.policy_set)
        effective_prompt = _effective_prompt(request.prompt, combined_detection, decision.action)
        route = choose_route(decision, request.requested_model)
        return combined_detection, decision, effective_prompt, route

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


def _analyze_request(request: GatewayRequest) -> DetectionResult:
    pii = detect_korean_pii(request.prompt)
    prompt_risk = detect_prompt_risk(request.prompt)
    return _combine_detection_results(pii, prompt_risk)


def _effective_prompt(prompt: str, detection: DetectionResult, action: object) -> str:
    action_value = getattr(action, "value", str(action))
    if action_value == "mask" and detection.masked_text:
        return detection.masked_text
    return prompt
