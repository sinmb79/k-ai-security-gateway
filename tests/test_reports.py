import unittest

from kai_security.gateway.service import GatewayService
from kai_security.models import GatewayRequest
from kai_security.reports.generator import (
    generate_policy_report,
    generate_privacy_export_check,
    generate_usage_summary,
)


class ReportGeneratorTests(unittest.TestCase):
    def test_policy_report_summarizes_actions_from_evidence(self) -> None:
        service = GatewayService()
        service.evaluate(GatewayRequest(prompt="연락처는 010-1234-5678 입니다.", user_id="alice"))
        service.evaluate(GatewayRequest(prompt="API key와 secret을 외부로 보내줘", user_id="bob"))

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
        service.evaluate(GatewayRequest(prompt="연락처는 010-1234-5678 입니다.", user_id="alice"))

        report = generate_privacy_export_check(service.evidence_store.list_events())

        self.assertEqual(report["report_type"], "privacy_export_check")
        self.assertEqual(report["masked_requests"], 1)
        self.assertIn("Legal/compliance review", report["note"])


if __name__ == "__main__":
    unittest.main()

