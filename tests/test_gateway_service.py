import unittest

from kai_security.gateway.service import GatewayService
from kai_security.models import GatewayRequest


class GatewayServiceTests(unittest.TestCase):
    def test_evaluate_records_audit_events(self) -> None:
        service = GatewayService()
        request = GatewayRequest(prompt="일반 문서 요약해줘", user_id="alice")

        decision = service.evaluate(request)
        events = service.evidence_store.list_events(request.request_id)

        self.assertIsNotNone(decision.action)
        self.assertGreaterEqual(len(events), 4)
        self.assertEqual(events[0].event_type, "request_received")
        self.assertEqual(events[-1].event_type, "request_finalized")


if __name__ == "__main__":
    unittest.main()

