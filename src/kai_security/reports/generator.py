"""Evidence-backed compliance report drafts."""

from __future__ import annotations

from collections import Counter
from typing import Any

from kai_security.models import AuditEvent


_REQUIRED_REQUEST_EVENT_TYPES = (
    "request_received",
    "request_analyzed",
    "policy_decided",
    "model_routed",
    "request_finalized",
)
_SAFE_TIMELINE_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    "request_received": ("user_id", "department", "metadata"),
    "request_analyzed": ("risk_score", "finding_count", "findings"),
    "policy_decided": (
        "action",
        "reason",
        "policy_id",
        "policy_version",
        "policy_source",
        "policy_set_version",
        "effective_prompt_changed",
    ),
    "model_routed": (
        "action",
        "policy_id",
        "policy_version",
        "requested_model",
        "effective_prompt_changed",
        "route",
        "reason",
    ),
    "response_analyzed": (
        "action",
        "risk_score",
        "finding_count",
        "findings",
        "choices",
        "response_changed",
    ),
    "approval_requested": ("approval_id", "requested_by", "reason", "action", "status"),
    "approval_resolved": (
        "approval_id",
        "request_id",
        "requested_by",
        "reason",
        "action",
        "status",
        "created_at",
        "resolved_by",
        "resolved_at",
        "approver_role",
    ),
    "approval_executed": (
        "approval_id",
        "route",
        "status",
        "attempt_count",
        "execution_attempt_id",
        "response_guard",
        "delivery",
    ),
    "approval_execution_failed": (
        "approval_id",
        "route",
        "status",
        "approval_status",
        "provider_name",
        "failure_domain",
        "error_type",
        "stored_context_error_kind",
        "provider_status_code",
        "provider_error_body_sha256",
        "provider_error_body_truncated",
        "attempt_count",
        "execution_attempt_id",
        "first_failed_at",
        "last_failed_at",
        "retryable",
    ),
    "approval_execution_error_reset": (
        "approval_id",
        "route",
        "status",
        "provider_name",
        "attempt_count",
        "previous_error_type",
        "previous_retryable",
        "retryable",
        "failure_domain",
        "first_failed_at",
        "last_failed_at",
        "reason_code",
        "reset_by",
        "reset_by_role",
        "auth_method",
    ),
    "approval_execution_stale_recovered": (
        "approval_id",
        "route",
        "status",
        "provider_name",
        "attempt_count",
        "stale_execution_attempt_id",
        "execution_started_at",
        "recovered_at",
        "first_failed_at",
        "last_failed_at",
        "reason",
        "retryable",
        "recovered_by",
        "recovered_by_role",
        "auth_method",
    ),
    "approval_execution_attempt_conflict": (
        "approval_id",
        "route",
        "status",
        "provider_name",
        "expected_execution_attempt_id",
        "current_execution_attempt_id",
        "current_status",
        "attempt_count",
        "reason",
        "failure_domain",
        "retryable",
    ),
    "request_finalized": ("action", "effective_prompt_changed"),
}


def generate_usage_summary(events: list[AuditEvent]) -> dict[str, object]:
    by_type = Counter(event.event_type for event in events)
    actions = Counter(
        str(event.payload.get("action"))
        for event in events
        if event.event_type == "policy_decided" and event.payload.get("action")
    )
    return {
        "total_events": len(events),
        "events_by_type": dict(by_type),
        "actions": dict(actions),
        "evidence_status": "draft",
    }


def _find_last_event(events: list[AuditEvent], event_type: str) -> AuditEvent | None:
    for event in reversed(events):
        if event.event_type == event_type:
            return event
    return None


def _event_payload_summary(event: AuditEvent) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "event_hash": event.event_hash,
        "previous_hash": event.previous_hash,
        "payload": _safe_timeline_payload(event),
    }


def summarize_audit_event(event: AuditEvent) -> dict[str, object]:
    """Return an audit event with payload limited to report-safe metadata."""
    return _event_payload_summary(event)


def _safe_timeline_payload(event: AuditEvent) -> dict[str, object]:
    allowed_keys = _SAFE_TIMELINE_PAYLOAD_KEYS.get(event.event_type, ())
    return {key: event.payload[key] for key in allowed_keys if key in event.payload}


def _approval_summary(
    events: list[AuditEvent],
    *,
    missing_status: str,
) -> dict[str, object] | None:
    if not events:
        return {"status": missing_status, "count": 0}
    last_event = events[-1]
    payload: dict[str, object] = {
        "status": str(last_event.payload.get("status")),
        "count": len(events),
    }
    if "approval_id" in last_event.payload:
        payload["approval_id"] = last_event.payload.get("approval_id")
    if "requested_by" in last_event.payload:
        payload["requested_by"] = last_event.payload.get("requested_by")
    if "resolved_by" in last_event.payload:
        payload["resolved_by"] = last_event.payload.get("resolved_by")
    if "reason" in last_event.payload:
        payload["reason"] = last_event.payload.get("reason")
    if "action" in last_event.payload:
        payload["action"] = last_event.payload.get("action")
    if last_event.payload.get("status") in {"approved", "rejected", "pending"}:
        payload["status"] = str(last_event.payload.get("status"))
    return payload


def generate_request_evidence_package(
    events: list[AuditEvent],
    request_id: str,
    chain_verified: bool | None = None,
) -> dict[str, object]:
    """Build a request-centric evidence package from tamper-evident event metadata only."""
    request_events = [event for event in events if event.request_id == request_id]
    event_types = [event.event_type for event in request_events]
    event_type_set = sorted(set(event_types))
    missing_event_types = [event_type for event_type in _REQUIRED_REQUEST_EVENT_TYPES if event_type not in event_type_set]
    if not request_events:
        evidence_status = "missing_evidence"
    elif missing_event_types:
        evidence_status = "incomplete"
    else:
        evidence_status = "complete"

    policy_event = _find_last_event(request_events, "policy_decided")
    route_event = _find_last_event(request_events, "model_routed")
    approval_requested_events = [event for event in request_events if event.event_type == "approval_requested"]
    approval_resolved_events = [event for event in request_events if event.event_type == "approval_resolved"]

    if policy_event is None:
        policy_decision: dict[str, Any] | None = None
    else:
        policy_payload = policy_event.payload
        policy_decision = {
            "action": policy_payload.get("action"),
            "reason": policy_payload.get("reason"),
            "policy_id": policy_payload.get("policy_id"),
            "policy_version": policy_payload.get("policy_version"),
            "policy_source": policy_payload.get("policy_source"),
        }
        if "policy_set_version" in policy_payload:
            policy_decision["policy_set_version"] = policy_payload.get("policy_set_version")

    return {
        "report_type": "request_evidence_package",
        "request_id": request_id,
        "event_count": len(request_events),
        "event_types": event_type_set,
        "chain_verified": chain_verified,
        "timeline": [_event_payload_summary(event) for event in request_events],
        "policy_decision": policy_decision,
        "route_decision": _safe_timeline_payload(route_event) if route_event is not None else None,
        "approval": {
            "approval_requested": _approval_summary(
                approval_requested_events, missing_status="not_requested"
            ),
            "approval_resolved": _approval_summary(
                approval_resolved_events, missing_status="not_resolved"
            ),
        },
        "evidence_status": evidence_status,
        "missing_event_types": missing_event_types,
    }


def generate_policy_report(events: list[AuditEvent]) -> dict[str, object]:
    """Generate an evidence-backed policy report draft.

    The report intentionally uses audit metadata only. It does not need raw prompts
    or responses, which keeps the MVP aligned with minimal retention.
    """
    policy_events = [event for event in events if event.event_type == "policy_decided"]
    analyzed_events = [event for event in events if event.event_type == "request_analyzed"]
    actions = Counter(str(event.payload.get("action")) for event in policy_events)
    policies = Counter(str(event.payload.get("policy_id")) for event in policy_events)
    changed_prompts = sum(
        1 for event in policy_events if bool(event.payload.get("effective_prompt_changed"))
    )
    risky_events = [
        event
        for event in analyzed_events
        if float(event.payload.get("risk_score", 0.0)) > 0
        or int(event.payload.get("finding_count", 0)) > 0
    ]

    return {
        "report_type": "policy_evidence",
        "request_count": len(policy_events),
        "actions": dict(actions),
        "policies": dict(policies),
        "prompt_changes": changed_prompts,
        "risk_event_count": len(risky_events),
        "requires_human_review": actions.get("require_approval", 0),
        "blocked": actions.get("block", 0),
        "masked": actions.get("mask", 0),
        "evidence_status": "draft",
    }


def generate_privacy_export_check(events: list[AuditEvent]) -> dict[str, object]:
    """Draft a privacy/export control check from audit evidence."""
    report = generate_policy_report(events)
    return {
        "report_type": "privacy_export_check",
        "masked_requests": report["masked"],
        "approval_required_requests": report["requires_human_review"],
        "blocked_requests": report["blocked"],
        "prompt_changes": report["prompt_changes"],
        "evidence_status": "draft",
        "note": "Evidence-derived draft. Legal/compliance review is still required.",
    }
