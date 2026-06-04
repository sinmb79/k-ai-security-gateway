"""Evidence-backed compliance report drafts."""

from __future__ import annotations

from collections import Counter

from kai_security.models import AuditEvent


def generate_usage_summary(events: list[AuditEvent]) -> dict[str, object]:
    by_type = Counter(event.event_type for event in events)
    actions = Counter(
        str(event.payload.get("action"))
        for event in events
        if event.event_type in {"policy_decided", "request_finalized"}
    )
    return {
        "total_events": len(events),
        "events_by_type": dict(by_type),
        "actions": dict(actions),
        "evidence_status": "draft",
    }

