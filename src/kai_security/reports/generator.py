"""Evidence-backed compliance report drafts."""

from __future__ import annotations

from collections import Counter

from kai_security.models import AuditEvent


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
