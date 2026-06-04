import unittest

from apps.gateway_api.main import (
    _approval_payload,
    _coerce_bool,
    _parse_approver_tokens,
    _require_approver,
    build_gateway_request,
)
from kai_security.approval.queue import InMemoryApprovalQueue
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

    def test_approval_payload_is_json_ready(self) -> None:
        approval = InMemoryApprovalQueue().create(
            request_id="request-1",
            requested_by="alice",
            reason="review",
            action="require_approval",
        )

        payload = _approval_payload(approval)

        self.assertEqual(payload["request_id"], "request-1")
        self.assertEqual(payload["status"], "pending")
        self.assertIsInstance(payload["created_at"], str)

    def test_coerce_bool_rejects_ambiguous_values(self) -> None:
        self.assertTrue(_coerce_bool("true"))
        self.assertFalse(_coerce_bool("false"))
        with self.assertRaises(ValueError):
            _coerce_bool("definitely")

    def test_require_approver_allows_only_approval_roles(self) -> None:
        self.assertEqual(
            _require_approver(
                {"approval_token": "token-1"},
                {"token-1": ("manager-1", "security_manager")},
            ),
            ("manager-1", "security_manager"),
        )
        with self.assertRaises(PermissionError):
            _require_approver({"approval_token": "bad"}, {"token-1": ("manager-1", "admin")})
        with self.assertRaises(PermissionError):
            _require_approver({}, {"token-1": ("manager-1", "admin")})

    def test_parse_approver_tokens_ignores_invalid_roles(self) -> None:
        registry = _parse_approver_tokens(
            "a=manager-1:security_manager;b=user-1:viewer;c=admin-1:admin"
        )

        self.assertEqual(registry, {"a": ("manager-1", "security_manager"), "c": ("admin-1", "admin")})


if __name__ == "__main__":
    unittest.main()
