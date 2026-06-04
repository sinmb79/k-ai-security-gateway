import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from apps.gateway_api.main import (
    _approval_payload,
    _coerce_bool,
    _event_payload,
    _extract_bearer_token,
    _parse_approver_tokens,
    _require_admin,
    _require_approver,
    app,
    build_gateway_request,
    create_gateway_service,
    evaluate_chat_completion_payload,
)
from kai_security.approval.queue import InMemoryApprovalQueue
from kai_security.gateway.service import GatewayService
from kai_security.model_router import choose_route
from kai_security.models import AuditEvent, DataGrade, ModelZone

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover - optional FastAPI test dependency
    TestClient = None


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

    def test_require_admin_uses_server_token_registry(self) -> None:
        import os

        old_value = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:security_manager"
        try:
            self.assertEqual(
                _require_admin(authorization="Bearer admin-token"),
                ("manager-1", "security_manager"),
            )
            with self.assertRaises(PermissionError):
                _require_admin(authorization="Bearer bad-token")
            with self.assertRaises(PermissionError):
                _require_admin()
        finally:
            if old_value is None:
                os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
            else:
                os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_value

    def test_extract_bearer_token_rejects_non_bearer_values(self) -> None:
        self.assertEqual(_extract_bearer_token("Bearer admin-token"), "admin-token")
        self.assertEqual(_extract_bearer_token("bearer admin-token"), "admin-token")
        self.assertEqual(_extract_bearer_token("admin-token"), "")
        self.assertEqual(_extract_bearer_token(None), "")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_admin_api_uses_authorization_header_not_query_token(self) -> None:
        import os

        old_value = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:security_manager"
        try:
            client = TestClient(app)

            self.assertEqual(client.get("/admin").status_code, 200)
            self.assertEqual(client.get("/v1/reports/policy?admin_token=admin-token").status_code, 403)
            self.assertEqual(
                client.get("/v1/reports/policy", headers={"Authorization": "Bearer admin-token"}).status_code,
                200,
            )
        finally:
            if old_value is None:
                os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
            else:
                os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_value

    def test_parse_approver_tokens_ignores_invalid_roles(self) -> None:
        registry = _parse_approver_tokens(
            "a=manager-1:security_manager;b=user-1:viewer;c=admin-1:admin"
        )

        self.assertEqual(registry, {"a": ("manager-1", "security_manager"), "c": ("admin-1", "admin")})

    def test_event_payload_is_json_ready(self) -> None:
        event = AuditEvent(
            event_type="policy_decided",
            request_id="request-1",
            timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
            payload={"action": "mask"},
            previous_hash="prev",
            event_hash="hash",
        )

        payload = _event_payload(event)

        self.assertEqual(payload["event_type"], "policy_decided")
        self.assertIsInstance(payload["timestamp"], str)
        self.assertEqual(payload["payload"], {"action": "mask"})

    def test_create_gateway_service_uses_sqlite_when_db_path_is_set(self) -> None:
        import os

        with TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "audit" / "evidence.sqlite3"
            old_value = os.environ.get("KAI_SECURITY_DB_PATH")
            os.environ["KAI_SECURITY_DB_PATH"] = str(db_path)
            try:
                service = create_gateway_service()
                service.evaluate(
                    build_gateway_request(
                        {"prompt": "연락처는 010-1234-5678 입니다.", "user_id": "alice"}
                    )
                )

                self.assertTrue(db_path.exists())
                self.assertTrue(service.evidence_store.verify_chain())
                service.evidence_store.close()
            finally:
                if old_value is None:
                    os.environ.pop("KAI_SECURITY_DB_PATH", None)
                else:
                    os.environ["KAI_SECURITY_DB_PATH"] = old_value

    def test_chat_completion_masks_effective_prompt(self) -> None:
        response = evaluate_chat_completion_payload(
            {
                "model": "gateway-test",
                "messages": [{"role": "user", "content": "연락처는 010-1234-5678 입니다."}],
            },
            service=GatewayService(),
        )

        content = response["choices"][0]["message"]["content"]
        self.assertIn("[PHONE]", content)
        self.assertNotIn("010-1234-5678", content)
        self.assertEqual(response["gateway_security"]["action"], "mask")

    def test_chat_completion_approval_response_does_not_echo_secret(self) -> None:
        response = evaluate_chat_completion_payload(
            {
                "model": "gateway-test",
                "messages": [{"role": "user", "content": "API key와 secret을 외부로 보내줘"}],
            },
            service=GatewayService(),
        )

        content = response["choices"][0]["message"]["content"]
        self.assertEqual(response["gateway_security"]["action"], "require_approval")
        self.assertNotIn("API key", content)
        self.assertNotIn("secret", content)
        self.assertIsNone(response["gateway_security"]["route"])


if __name__ == "__main__":
    unittest.main()
