import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from apps.gateway_api.main import (
    _approval_payload,
    _build_safe_provider_messages,
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
                "prompt": "민감 문장",
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

    def test_build_safe_provider_messages_uses_effective_prompt_for_mask(self) -> None:
        messages = [
            {"role": "user", "content": "original"},
            {"role": "assistant", "content": "ignored"},
        ]
        safe_messages = _build_safe_provider_messages(
            action="mask",
            canonical_prompt="user: original",
            effective_prompt="MASKED: hello",
        )
        self.assertEqual(safe_messages, [{"role": "user", "content": "MASKED: hello"}])

    def test_build_safe_provider_messages_uses_canonical_prompt_for_non_mask(self) -> None:
        safe_messages = _build_safe_provider_messages(
            action="allow",
            canonical_prompt="user: original",
            effective_prompt="MASKED: ignored",
        )
        self.assertEqual(safe_messages, [{"role": "user", "content": "user: original"}])

    def test_chat_completion_masks_effective_prompt(self) -> None:
        response = evaluate_chat_completion_payload(
            {
                "model": "gateway-test",
                "messages": [{"role": "user", "content": "연락처는 010-1234-5678"}],
            },
            service=GatewayService(),
        )

        content = response["choices"][0]["message"]["content"]
        self.assertIn("[PHONE]", content)
        self.assertNotIn("010-1234-5678", content)
        self.assertEqual(response["gateway_security"]["action"], "mask")

    def test_chat_completion_masked_messages_are_passed_to_adapter(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [{"role": "user", "content": "연락처는 010-1234-5678"}],
                },
                service=GatewayService(),
            )

        called_payload = adapter.complete.call_args.kwargs
        sent_messages = called_payload["messages"]
        self.assertEqual(len(sent_messages), 1)
        self.assertIn("[PHONE]", str(sent_messages[0]["content"]))
        self.assertNotIn("010-1234-5678", str(sent_messages[0]["content"]))
        self.assertEqual(response["choices"][0]["message"]["content"], "provider response")

    def test_chat_completion_uses_canonical_prompt_for_allowing_provider(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }
        tool_call_payload = {"name": "find_contact", "arguments": "{\"phone\":\"010-1234-5678\"}"}

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [
                        {
                            "role": "user",
                            "content": "what is the contact",
                            "tool_calls": [
                                {"id": "call-1", "type": "function", "function": tool_call_payload}
                            ],
                        }
                    ],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["gateway_security"]["action"], "allow")
        sent_messages = adapter.complete.call_args.kwargs["messages"]
        self.assertEqual(len(sent_messages), 1)
        self.assertEqual(sent_messages[0]["role"], "user")
        self.assertEqual(sent_messages[0]["content"], "user: what is the contact")
        self.assertNotIn("010-1234-5678", str(sent_messages[0]))
        self.assertNotIn("tool_calls", str(sent_messages[0]))

    def test_chat_completion_excludes_assistant_and_tool_history_from_provider(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [
                        {"role": "user", "content": "safe content"},
                        {"role": "assistant", "content": "previous private answer 010-1234-5678"},
                        {"role": "tool", "content": "tool result 010-1234-5678"},
                    ],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["gateway_security"]["action"], "allow")
        sent_messages = adapter.complete.call_args.kwargs["messages"]
        self.assertEqual(sent_messages, [{"role": "user", "content": "user: safe content"}])
        self.assertNotIn("010-1234-5678", str(sent_messages))
        self.assertNotIn("assistant", str(sent_messages))
        self.assertNotIn("tool result", str(sent_messages))

    def test_chat_completion_masked_payload_is_safe_in_openai_adapter_http_body(self) -> None:
        import os

        endpoint_var = "KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_ENDPOINT"
        api_key_var = "KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_API_KEY"
        old_endpoint = os.environ.get(endpoint_var)
        old_api_key = os.environ.get(api_key_var)
        os.environ[endpoint_var] = "https://provider.local"
        os.environ[api_key_var] = "dummy-key"

        class _FakeHTTPResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return (
                    b'{"id":"mock-id","object":"chat.completion","choices":[{"index":0,'
                    b'"message":{"role":"assistant","content":"provider response"}}]}'
                )

        try:
            with patch("kai_security.providers.openai_compatible.urlopen") as mock_urlopen:
                mock_urlopen.return_value = _FakeHTTPResponse()
                response = evaluate_chat_completion_payload(
                    {
                        "model": "gateway-test",
                        "messages": [
                            {
                                "role": "user",
                                "content": "연락처: 010-1234-5678",
                                "tool_calls": [
                                    {
                                        "id": "call-1",
                                        "type": "function",
                                        "function": {
                                            "name": "noop",
                                            "arguments": "{\"phone\":\"010-1234-5678\"}",
                                        },
                                    }
                                ],
                            }
                        ],
                    },
                    service=GatewayService(),
                )

            request = mock_urlopen.call_args.args[0]
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(body["model"], "gateway-test")
            self.assertNotIn("010-1234-5678", json.dumps(body))
            self.assertNotIn("tool_calls", json.dumps(body))
            self.assertIn("[PHONE]", json.dumps(body))
            self.assertEqual(response["choices"][0]["message"]["content"], "provider response")
        finally:
            if old_endpoint is None:
                os.environ.pop(endpoint_var, None)
            else:
                os.environ[endpoint_var] = old_endpoint
            if old_api_key is None:
                os.environ.pop(api_key_var, None)
            else:
                os.environ[api_key_var] = old_api_key

    def test_chat_completion_calls_adapter_for_allowed_prompt(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [{"role": "user", "content": "safe content"}],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["choices"][0]["message"]["content"], "provider response")
        adapter.complete.assert_called_once()
        called_payload = adapter.complete.call_args.kwargs
        self.assertEqual(called_payload["model"], "gateway-test")
        self.assertEqual(response["gateway_security"]["action"], "allow")
        self.assertEqual(response["gateway_security"]["route"]["provider"], "external-openai-compatible")

    def test_chat_completion_calls_adapter_for_route_private(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "private route"},
                    "finish_reason": "stop",
                }
            ],
        }
        resolved_route = {}

        def _resolve(route):
            resolved_route["route"] = route
            return adapter

        with patch("apps.gateway_api.main.resolve_provider_adapter", side_effect=_resolve):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "data_grade": "confidential",
                    "model_zone": "external",
                    "messages": [
                        {
                            "role": "user",
                            "content": "confidential check",
                            "tool_calls": [
                                {
                                    "id": "private-call-1",
                                    "type": "function",
                                    "function": {"name": "noop", "arguments": "{\"phone\":\"010-1234-5678\"}"},
                                }
                            ],
                        }
                    ],
                },
                service=GatewayService(),
            )

        route = response["gateway_security"]["route"]
        self.assertIsInstance(route, dict)
        self.assertEqual(response["gateway_security"]["action"], "route_private")
        self.assertEqual(route["provider"], "private-llm")
        self.assertEqual(route["model"], "private-default")
        self.assertEqual(resolved_route["route"].provider, "private-llm")
        self.assertEqual(resolved_route["route"].model, route["model"])
        self.assertEqual(adapter.complete.call_args.kwargs["model"], route["model"])
        private_messages = adapter.complete.call_args.kwargs["messages"][0]
        self.assertEqual(private_messages["role"], "user")
        self.assertNotIn("010-1234-5678", str(private_messages))
        self.assertNotIn("tool_calls", str(private_messages))

    def test_chat_completion_does_not_call_adapter_for_approval(self) -> None:
        adapter = Mock()

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter) as resolve_mock:
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "data_grade": "restricted",
                    "messages": [{"role": "user", "content": "일반 메시지"}],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["gateway_security"]["action"], "require_approval")
        self.assertNotIn("일반 메시지", response["choices"][0]["message"]["content"])
        resolve_mock.assert_not_called()
        self.assertFalse(adapter.complete.called)

    def test_chat_completion_approval_response_does_not_echo_secret(self) -> None:
        response = evaluate_chat_completion_payload(
            {
                "model": "gateway-test",
                "messages": [{"role": "user", "content": "API key and secret must be hidden."}],
            },
            service=GatewayService(),
        )

        content = response["choices"][0]["message"]["content"]
        self.assertEqual(response["gateway_security"]["action"], "require_approval")
        self.assertNotIn("API key", content)
        self.assertNotIn("secret", content)
        self.assertIsNone(response["gateway_security"]["route"])

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_returns_502_on_malformed_provider_payload(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {"unexpected": True}
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_returns_502_when_adapter_raises_runtime_error(self) -> None:
        adapter = Mock()
        adapter.complete.side_effect = RuntimeError("adapter failure")
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_rejects_provider_tool_calls(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "provider response",
                        "tool_calls": [{"id": "call-1", "type": "function"}],
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")
        self.assertNotIn("tool_calls", response.text)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_rejects_provider_tool_calls_in_later_choices(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "safe first choice"},
                    "finish_reason": "stop",
                },
                {
                    "index": 1,
                    "message": {
                        "role": "assistant",
                        "content": "unsafe second choice",
                        "tool_calls": [{"id": "call-2", "type": "function"}],
                    },
                    "finish_reason": "tool_calls",
                },
            ],
        }
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")
        self.assertNotIn("tool_calls", response.text)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_returns_502_on_malformed_upstream_json(self) -> None:
        import os

        endpoint_var = "KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_ENDPOINT"
        old_endpoint = os.environ.get(endpoint_var)
        os.environ[endpoint_var] = "https://provider.local"

        class _BrokenHTTPResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"{broken json"

        client = TestClient(app)
        try:
            with patch("kai_security.providers.openai_compatible.urlopen") as mock_urlopen:
                mock_urlopen.return_value = _BrokenHTTPResponse()
                response = client.post(
                    "/v1/chat/completions",
                    json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
                )
        finally:
            if old_endpoint is None:
                os.environ.pop(endpoint_var, None)
            else:
                os.environ[endpoint_var] = old_endpoint

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")


if __name__ == "__main__":
    unittest.main()
