import unittest

from apps.gateway_api.main import build_gateway_request
from kai_security.gateway.service import GatewayService
from kai_security.model_router import choose_route
from kai_security.models import DataGrade, ModelZone


class GatewayApiContractTests(unittest.TestCase):
    def test_build_gateway_request_maps_policy_context(self) -> None:
        request = build_gateway_request(
            {
                "prompt": "내부 문서 요약",
                "user_id": "alice",
                "department": "audit",
                "role": "auditor",
                "requested_model": "gpt-compatible",
                "data_grade": "restricted",
                "model_zone": "external",
            }
        )

        self.assertEqual(request.data_grade, DataGrade.RESTRICTED)
        self.assertEqual(request.model_zone, ModelZone.EXTERNAL)
        self.assertEqual(request.role, "auditor")

    def test_route_private_decision_has_route_payload_source(self) -> None:
        request = build_gateway_request(
            {
                "prompt": "기밀 보고서 요약",
                "user_id": "alice",
                "data_grade": "confidential",
                "model_zone": "external",
            }
        )
        evaluation = GatewayService().evaluate(request)
        route = choose_route(evaluation.decision, request.requested_model)

        self.assertEqual(evaluation.decision.action.value, "route_private")
        self.assertIsNotNone(route)
        self.assertEqual(route.zone, ModelZone.PRIVATE)

    def test_invalid_enum_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_gateway_request({"prompt": "x", "data_grade": "top-secret"})


if __name__ == "__main__":
    unittest.main()

