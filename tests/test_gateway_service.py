import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from kai_security.gateway.service import GatewayService
from kai_security.models import DataGrade, GatewayRequest, ModelZone
from kai_security.reports.generator import generate_usage_summary


class GatewayServiceTests(unittest.TestCase):
    def test_evaluate_records_audit_events(self) -> None:
        service = GatewayService()
        request = GatewayRequest(prompt="?쇰컲 臾몄꽌 ?붿빟?댁쨾", user_id="alice")

        evaluation = service.evaluate(request)
        events = service.evidence_store.list_events(request.request_id)

        self.assertIsNotNone(evaluation.decision.action)
        self.assertGreaterEqual(len(events), 4)
        self.assertEqual(events[0].event_type, "request_received")
        self.assertEqual(events[-1].event_type, "request_finalized")

    def test_mask_decision_returns_effective_masked_prompt(self) -> None:
        service = GatewayService()
        request = GatewayRequest(prompt="?곕씫泥섎뒗 010-1234-5678 ?낅땲??", user_id="alice")

        evaluation = service.evaluate(request)

        self.assertEqual(evaluation.decision.action.value, "mask")
        self.assertTrue(evaluation.prompt_changed)
        self.assertIn("[PHONE]", evaluation.effective_prompt)
        self.assertNotIn("010-1234-5678", evaluation.effective_prompt)
        events = service.evidence_store.list_events(request.request_id)
        policy_events = [event for event in events if event.event_type == "policy_decided"]
        self.assertTrue(policy_events)
        self.assertTrue(policy_events[0].payload["effective_prompt_changed"])

    def test_usage_summary_counts_policy_action_once_per_request(self) -> None:
        service = GatewayService()
        request = GatewayRequest(prompt="?곕씫泥섎뒗 010-1234-5678 ?낅땲??", user_id="alice")

        service.evaluate(request)
        summary = generate_usage_summary(service.evidence_store.list_events())

        self.assertEqual(summary["actions"], {"mask": 1})

    def test_data_exfiltration_to_external_requires_approval(self) -> None:
        service = GatewayService()
        request = GatewayRequest(prompt="API key and secret may be leaked", user_id="alice")

        evaluation = service.evaluate(request)

        self.assertEqual(evaluation.decision.action.value, "require_approval")
        self.assertEqual(
            evaluation.decision.policy_id,
            "policy-003-data-exfiltration-external-require-approval",
        )
        self.assertIsNotNone(evaluation.approval_id)
        self.assertEqual(len(service.approval_queue.list_pending()), 1)
        events = service.evidence_store.list_events(request.request_id)
        self.assertIn("approval_requested", [event.event_type for event in events])

    def test_simulate_does_not_enqueue_approval(self) -> None:
        service = GatewayService()
        request = GatewayRequest(
            prompt="restricted data flow",
            user_id="alice",
            data_grade=DataGrade.RESTRICTED,
            model_zone=ModelZone.EXTERNAL,
        )

        detection, decision, _effective_prompt, route = service.simulate(request)
        self.assertEqual(decision.action.value, "require_approval")
        self.assertIsNone(route)
        self.assertEqual(len(service.approval_queue.list_pending()), 0)
        self.assertEqual(len(service.evidence_store.list_events()), 0)
        self.assertEqual(len(detection.findings), 0)

    def test_service_uses_policy_path(self) -> None:
        with TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "version": "0.2.0",
                        "policies": [
                            {
                                "id": "policy-777-route-private-test",
                                "priority": 10,
                                "when": {"data_grade": "restricted", "model_zone": "external"},
                                "action": "route_private",
                                "route_model_zone": "private",
                                "reason": "restricted content to private zone",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            service = GatewayService(policy_path=str(path))
            request = GatewayRequest(
                prompt="restricted data",
                user_id="alice",
                data_grade=DataGrade.RESTRICTED,
                model_zone=ModelZone.EXTERNAL,
            )
            evaluation = service.evaluate(request)

            self.assertEqual(evaluation.decision.action.value, "route_private")
            self.assertEqual(evaluation.decision.policy_id, "policy-777-route-private-test")
            self.assertEqual(evaluation.decision.policy_version, "0.2.0")


if __name__ == "__main__":
    unittest.main()
