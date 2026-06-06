import unittest

from datetime import UTC, datetime

from kai_security.gateway.service import GatewayService
from kai_security.models import AuditEvent, GatewayRequest
from kai_security.reports.generator import (
    generate_policy_report,
    generate_privacy_export_check,
    generate_request_evidence_package,
    generate_usage_summary,
)


class ReportGeneratorTests(unittest.TestCase):
    def test_policy_report_summarizes_actions_from_evidence(self) -> None:
        service = GatewayService()
        service.evaluate(GatewayRequest(prompt="contains 010-1234-5678", user_id="alice"))
        service.evaluate(GatewayRequest(prompt="API key and secret exposed", user_id="bob"))

        events = service.evidence_store.list_events()
        usage = generate_usage_summary(events)
        policy = generate_policy_report(events)

        self.assertEqual(usage["actions"], {"mask": 1, "require_approval": 1})
        self.assertEqual(policy["request_count"], 2)
        self.assertEqual(policy["masked"], 1)
        self.assertEqual(policy["requires_human_review"], 1)
        self.assertEqual(policy["risk_event_count"], 2)

    def test_privacy_export_check_uses_evidence_not_raw_prompt(self) -> None:
        service = GatewayService()
        service.evaluate(GatewayRequest(prompt="contains 010-1234-5678", user_id="alice"))

        report = generate_privacy_export_check(service.evidence_store.list_events())

        self.assertEqual(report["report_type"], "privacy_export_check")
        self.assertEqual(report["masked_requests"], 1)
        self.assertIn("Legal/compliance review", report["note"])

    def test_request_evidence_package_reports_route_policy_and_approval(self) -> None:
        service = GatewayService()
        request = GatewayRequest(prompt="API key and secret exposed", user_id="alice")
        service.evaluate(request)

        report = generate_request_evidence_package(
            service.evidence_store.list_events(),
            request_id=request.request_id,
            chain_verified=True,
        )

        self.assertEqual(report["report_type"], "request_evidence_package")
        self.assertEqual(report["request_id"], request.request_id)
        self.assertEqual(report["event_count"], 6)
        self.assertEqual(report["event_types"], [
            "approval_requested",
            "model_routed",
            "policy_decided",
            "request_analyzed",
            "request_finalized",
            "request_received",
        ])
        self.assertEqual(report["evidence_status"], "complete")
        self.assertEqual(report["missing_event_types"], [])
        self.assertEqual(report["policy_decision"]["action"], "require_approval")
        self.assertEqual(report["policy_decision"]["policy_version"], "0.1.0")
        self.assertEqual(report["chain_verified"], True)
        self.assertTrue(all(isinstance(item.get("event_hash"), str) for item in report["timeline"]))
        self.assertEqual(report["approval"]["approval_requested"]["count"], 1)

    def test_request_evidence_package_omits_raw_prompt_response_and_comments(self) -> None:
        service = GatewayService()
        request = GatewayRequest(prompt="API key and secret exposed", user_id="alice")
        service.evaluate(request)
        approval = service.approval_queue.list_pending()[0]
        executing = service.approval_queue.begin_execution(
            approval.approval_id,
            resolved_by="manager-1",
            comment="contains raw customer prompt",
        )
        resolved = service.approval_queue.finish_execution_success(
            executing.approval_id,
            expected_execution_attempt_id=executing.execution_attempt_id,
            resolved_by="manager-1",
            comment="contains raw customer prompt",
        )
        service.evidence_store.append(
            AuditEvent(
                event_type="approval_resolved",
                request_id=request.request_id,
                timestamp=resolved.resolved_at,
                payload={
                    "approval_id": resolved.approval_id,
                    "request_id": resolved.request_id,
                    "requested_by": resolved.requested_by,
                    "reason": resolved.reason,
                    "action": resolved.action,
                    "status": resolved.status,
                    "created_at": resolved.created_at.isoformat(),
                    "resolved_by": resolved.resolved_by,
                    "resolved_at": resolved.resolved_at.isoformat(),
                    "resolution_comment": resolved.resolution_comment,
                    "prompt": "raw secret prompt",
                    "response": "raw provider response",
                },
            )
        )
        service.evidence_store.append(
            AuditEvent(
                event_type="model_routed",
                request_id=request.request_id,
                timestamp=resolved.resolved_at,
                payload={
                    "action": "require_approval",
                    "policy_id": "policy-004-secret-approval",
                    "policy_version": "0.1.0",
                    "requested_model": "default",
                    "effective_prompt_changed": False,
                    "route": None,
                    "reason": "routing skipped",
                    "prompt": "raw route prompt",
                    "response": "raw route response",
                },
            )
        )

        report = generate_request_evidence_package(
            service.evidence_store.list_events(),
            request_id=request.request_id,
        )
        rendered = str(report)

        self.assertNotIn("raw secret prompt", rendered)
        self.assertNotIn("raw provider response", rendered)
        self.assertNotIn("contains raw customer prompt", rendered)
        self.assertNotIn("raw route prompt", rendered)
        self.assertNotIn("raw route response", rendered)
        self.assertEqual(report["approval"]["approval_resolved"]["status"], "approved")

    def test_request_evidence_package_keeps_sanitized_failure_and_recovery_metadata(self) -> None:
        now = datetime.now(UTC)
        events = [
            AuditEvent(
                event_type="approval_execution_failed",
                request_id="req-provider-failure",
                timestamp=now,
                payload={
                    "approval_id": "approval-1",
                    "status": "failed",
                    "provider_name": "external-openai-compatible",
                    "error_type": "provider_http_error",
                    "provider_status_code": 401,
                    "provider_error_body_sha256": "abc123",
                    "provider_error_body_truncated": True,
                    "attempt_count": 1,
                    "execution_attempt_id": "attempt-1",
                    "first_failed_at": now.isoformat(),
                    "last_failed_at": now.isoformat(),
                    "retryable": False,
                    "raw_error_body": "raw secret body",
                },
            ),
            AuditEvent(
                event_type="approval_execution_stale_recovered",
                request_id="req-provider-failure",
                timestamp=now,
                payload={
                    "approval_id": "approval-1",
                    "status": "pending",
                    "attempt_count": 1,
                    "stale_execution_attempt_id": "attempt-1",
                    "execution_started_at": now.isoformat(),
                    "recovered_at": now.isoformat(),
                    "reason": "execution_timeout",
                    "retryable": True,
                    "recovered_by": "manager-1",
                    "recovered_by_role": "admin",
                    "auth_method": "admin_bearer_token",
                    "raw_error_body": "raw stale secret",
                },
            ),
        ]

        report = generate_request_evidence_package(
            events,
            request_id="req-provider-failure",
        )
        rendered = str(report)

        self.assertIn("abc123", rendered)
        self.assertIn("provider_error_body_truncated", rendered)
        self.assertIn("approval_execution_stale_recovered", rendered)
        self.assertIn("execution_timeout", rendered)
        self.assertIn("manager-1", rendered)
        self.assertNotIn("raw secret body", rendered)
        self.assertNotIn("raw stale secret", rendered)

    def test_request_evidence_package_without_events_reports_missing(self) -> None:
        report = generate_request_evidence_package([], request_id="missing-request")

        self.assertEqual(report["report_type"], "request_evidence_package")
        self.assertEqual(report["request_id"], "missing-request")
        self.assertEqual(report["evidence_status"], "missing_evidence")
        self.assertEqual(
            report["missing_event_types"],
            [
                "request_received",
                "request_analyzed",
                "policy_decided",
                "model_routed",
                "request_finalized",
            ],
        )


if __name__ == "__main__":
    unittest.main()
